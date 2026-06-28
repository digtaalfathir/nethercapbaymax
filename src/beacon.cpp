#include "beacon.h"
#include "sniffer.h"
#include "cli.h"
#include "deauth.h"
#include "pdeauth.h"
#include "evil.h"
#include <ESP8266WiFi.h>
#include <string.h>

extern "C" {
  #include "user_interface.h"
  // tidak selalu ada di header publik -> deklarasikan manual
  int wifi_send_pkt_freedom(uint8_t* buf, int len, bool sys_seq);
}

#define BS_MAX_SSID 32
#define BS_SSID_LEN 32

struct bs_entry {
  char    ssid[BS_SSID_LEN + 1];
  uint8_t bssid[6];                 // MAC palsu, stabil per-SSID
};
static bs_entry s_list[BS_MAX_SSID];
static uint8_t  s_listN = 0;

static bool     s_spamming = false;
static uint8_t  s_ch       = 1;
static uint32_t s_lastTick = 0;
static uint32_t s_sent     = 0;     // freedom-send sukses (return 0)
static uint32_t s_fail     = 0;     // freedom-send gagal  (return != 0)
static uint8_t  s_pkt[128];

// callback promiscuous kosong — kita cuma butuh promiscuous ENABLE agar
// wifi_send_pkt_freedom() aktif, bukan untuk menerima frame.
static void nullcb(uint8_t*, uint16_t) {}

enum { BS_MENU, BS_ADD, BS_RANDOM };
static uint8_t s_state = BS_MENU;

// -------------------------------------------------------------- helpers ----
static void rand_mac(uint8_t* m) {
  for (int i = 0; i < 6; i++) m[i] = (uint8_t)random(256);
  m[0] = (m[0] & 0xFE) | 0x02;       // unicast + locally administered
}

static bool add_ssid(const char* s) {
  if (s_listN >= BS_MAX_SSID || s[0] == '\0') return false;
  strncpy(s_list[s_listN].ssid, s, BS_SSID_LEN);
  s_list[s_listN].ssid[BS_SSID_LEN] = 0;
  rand_mac(s_list[s_listN].bssid);
  s_listN++;
  return true;
}

static void gen_random(int n) {
  static const char* cs =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (int k = 0; k < n && s_listN < BS_MAX_SSID; k++) {
    char tmp[13];
    int len = 6 + (int)random(7);    // 6..12 karakter
    for (int j = 0; j < len; j++) tmp[j] = cs[random(62)];
    tmp[len] = 0;
    add_ssid(tmp);
  }
}

// Susun beacon frame; kembalikan panjangnya.
static int build_beacon(uint8_t* p, const char* ssid, const uint8_t* bssid, uint8_t ch) {
  int i = 0;
  p[i++] = 0x80; p[i++] = 0x00; p[i++] = 0x00; p[i++] = 0x00;     // FC(beacon) + duration
  for (int j = 0; j < 6; j++) p[i++] = 0xFF;                      // dst broadcast
  for (int j = 0; j < 6; j++) p[i++] = bssid[j];                  // src
  for (int j = 0; j < 6; j++) p[i++] = bssid[j];                  // BSSID
  p[i++] = 0x00; p[i++] = 0x00;                                   // seq
  for (int j = 0; j < 8; j++) p[i++] = 0x00;                      // timestamp
  p[i++] = 0x64; p[i++] = 0x00;                                   // beacon interval 100 TU
  p[i++] = 0x01; p[i++] = 0x04;                                   // capability: ESS (open)

  uint8_t slen = (uint8_t)strlen(ssid); if (slen > 32) slen = 32; // tag SSID
  p[i++] = 0x00; p[i++] = slen;
  memcpy(p + i, ssid, slen); i += slen;

  p[i++] = 0x01; p[i++] = 0x08;                                   // tag supported rates
  p[i++] = 0x82; p[i++] = 0x84; p[i++] = 0x8B; p[i++] = 0x96;
  p[i++] = 0x24; p[i++] = 0x30; p[i++] = 0x48; p[i++] = 0x6C;

  p[i++] = 0x03; p[i++] = 0x01; p[i++] = ch;                      // tag DS param (channel)
  return i;
}

// ------------------------------------------------------------- lifecycle ---
static void spam_start() {
  if (s_listN == 0) { Serial.println(F("[beacon] daftar kosong — tambah SSID dulu")); return; }
  if (sniffer_running()) sniffer_stop();
  deauth_stop(); pdeauth_stop(); evil_stop();   // jangan rebutan channel/mode

  // Kunci: ESP8266 hanya mengizinkan wifi_send_pkt_freedom() saat
  // promiscuous mode ENABLE. Callback di-set ke nullcb (tak dipakai).
  wifi_set_opmode_current(STATION_MODE);
  wifi_set_promiscuous_rx_cb(nullcb);
  wifi_promiscuous_enable(1);

  s_spamming = true;
  s_sent = s_fail = 0;
  s_lastTick = 0;
  s_ch       = 1;
  Serial.printf("[beacon] START — %u SSID di-broadcast (sweep ch1-13). Cari ini di scan:\n", s_listN);
  for (uint8_t i = 0; i < s_listN; i++)
    Serial.printf("   * %-20s  %s\n", s_list[i].ssid, nc_mac_str(s_list[i].bssid));
}

static void spam_stop() {
  if (!s_spamming) { Serial.println(F("[beacon] tidak jalan")); return; }
  s_spamming = false;
  wifi_promiscuous_enable(0);
  Serial.printf("[beacon] STOP — sukses %lu, gagal %lu\n",
                (unsigned long)s_sent, (unsigned long)s_fail);
}

void beacon_stop() { if (s_spamming) spam_stop(); }   // cross-module, senyap

void beacon_loop() {
  if (!s_spamming || s_listN == 0) return;

  wifi_set_channel(s_ch);
  for (uint8_t i = 0; i < s_listN; i++) {
    int len = build_beacon(s_pkt, s_list[i].ssid, s_list[i].bssid, s_ch);
    if (wifi_send_pkt_freedom(s_pkt, len, 0) == 0) s_sent++;
    else                                           s_fail++;
    delay(1);                              // beri WiFi stack waktu flush TX (cegah gagal beruntun)
  }
  s_ch = (uint8_t)(s_ch >= 13 ? 1 : s_ch + 1);
}

// ----------------------------------------------------------------- menu ----
static void print_menu() {
  Serial.printf("\n=== BEACON SPAM === (%u SSID, %s)\n",
                s_listN, s_spamming ? "RUNNING" : "stop");
  Serial.println(F("  1) tambah SSID manual"));
  Serial.println(F("  2) generate acak"));
  Serial.println(F("  3) lihat daftar"));
  Serial.println(F("  4) hapus semua"));
  Serial.println(F("  5) START spam"));
  Serial.println(F("  6) STOP spam"));
  Serial.println(F("pilih (1-6, 'q' keluar):"));
}

static void list_print() {
  Serial.printf("daftar SSID (%u):\n", s_listN);
  for (uint8_t i = 0; i < s_listN; i++)
    Serial.printf("  %2u) %-20s  %s\n", i, s_list[i].ssid, nc_mac_str(s_list[i].bssid));
}

static void on_input(const char* line) {
  if (s_state == BS_ADD) {
    if (line[0] == '\0') { s_state = BS_MENU; print_menu(); cli_capture(on_input, "beacon> "); return; }
    if (add_ssid(line)) Serial.printf("  + \"%s\" (total %u)\n", line, s_listN);
    else                Serial.println(F("  ! gagal (daftar penuh?)"));
    return;                                                  // tetap menambah
  }
  if (s_state == BS_RANDOM) {
    int n = atoi(line);
    if (n < 1 || n > BS_MAX_SSID) { Serial.printf("masukkan 1-%d\n", BS_MAX_SSID); return; }
    gen_random(n);
    Serial.printf("  + %d SSID acak (total %u)\n", n, s_listN);
    s_state = BS_MENU; print_menu(); cli_capture(on_input, "beacon> ");
    return;
  }

  // BS_MENU
  if (line[0] == 'q' || line[0] == 'Q') { Serial.println(F("[beacon] keluar menu")); cli_release(); return; }
  switch (line[0]) {
    case '1': s_state = BS_ADD;    Serial.println(F("ketik SSID, ENTER kosong = selesai:")); cli_capture(on_input, "ssid> ");  return;
    case '2': s_state = BS_RANDOM; Serial.printf("berapa SSID acak? (1-%d):\n", BS_MAX_SSID); cli_capture(on_input, "jumlah> "); return;
    case '3': list_print();                              break;
    case '4': s_listN = 0; Serial.println(F("daftar dikosongkan")); break;
    case '5': spam_start();                              break;
    case '6': spam_stop();                               break;
    default:  Serial.println(F("pilihan tidak dikenal")); break;
  }
  print_menu();
}

static void cmd_beacon(int argc, char** argv) {
  (void)argc; (void)argv;
  s_state = BS_MENU;
  print_menu();
  cli_capture(on_input, "beacon> ");
}

void beacon_init() {
  randomSeed(ESP.getCycleCount());
  cli_register("beacon", "beacon spam (menu terpandu)", cmd_beacon);
}
