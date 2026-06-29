#include "station.h"
#include "sniffer.h"
#include "cli.h"
#include <ESP8266WiFi.h>
#include <string.h>

// Kapasitas tabel (fixed — tanpa alokasi dinamis di dalam callback)
#define ST_MAX_AP  24
#define ST_MAX_CLI 64

struct st_ap {
  uint8_t  bssid[6];
  uint8_t  channel;
  int8_t   rssi;
  uint32_t last;       // millis terakhir terlihat
  uint16_t clients;    // jumlah client terasosiasi
};

struct st_client {
  uint8_t  mac[6];
  int16_t  ap;         // index ke s_ap[], -1 = belum diketahui (mis. probe-req)
  uint8_t  channel;
  int8_t   rssi;
  uint32_t last;
  uint32_t pkts;
};

static st_ap     s_ap[ST_MAX_AP];
static st_client s_cli[ST_MAX_CLI];
static uint8_t   s_apN  = 0;
static uint8_t   s_cliN = 0;
static volatile bool s_lock = false;   // jeda mutasi saat print

// --- mode fokus (Count Station terpandu pada 1 AP) ---
struct scan_entry { uint8_t bssid[6]; uint8_t channel; int8_t rssi; char ssid[33]; };
static scan_entry s_scan[ST_MAX_AP];
static uint8_t    s_scanN = 0;

static bool     s_focused = false;
static uint8_t  s_target[6];
static uint8_t  s_targetCh = 1;
static char     s_targetSsid[33] = {0};
static uint32_t s_lastShow = 0;

// -------------------------------------------------------------- helpers ----
static inline bool mac_eq(const uint8_t* a, const uint8_t* b) { return memcmp(a, b, 6) == 0; }
static inline bool mac_group(const uint8_t* m) { return (m[0] & 0x01) != 0; }  // broadcast/multicast
static inline bool mac_zero(const uint8_t* m) {
  for (int i = 0; i < 6; i++) if (m[i]) return false;
  return true;
}

static int ap_seen(const uint8_t* b, uint8_t ch, int8_t rssi, uint32_t now) {
  for (uint8_t i = 0; i < s_apN; i++) if (mac_eq(s_ap[i].bssid, b)) {
    s_ap[i].channel = ch; s_ap[i].rssi = rssi; s_ap[i].last = now;
    return i;
  }
  if (s_apN >= ST_MAX_AP) return -1;
  int i = s_apN++;
  memcpy(s_ap[i].bssid, b, 6);
  s_ap[i].channel = ch; s_ap[i].rssi = rssi; s_ap[i].last = now;
  s_ap[i].clients = 0;
  return i;
}

static void client_seen(const uint8_t* m, int ap, uint8_t ch, int8_t rssi, uint32_t now) {
  for (uint8_t i = 0; i < s_cliN; i++) if (mac_eq(s_cli[i].mac, m)) {
    if (ap >= 0 && s_cli[i].ap != ap) {           // pindah/baru ketemu AP-nya
      if (s_cli[i].ap >= 0 && s_cli[i].ap < (int)s_apN && s_ap[s_cli[i].ap].clients)
        s_ap[s_cli[i].ap].clients--;
      s_cli[i].ap = (int16_t)ap;
      s_ap[ap].clients++;
    }
    s_cli[i].channel = ch; s_cli[i].rssi = rssi; s_cli[i].last = now; s_cli[i].pkts++;
    return;
  }
  if (s_cliN >= ST_MAX_CLI) return;
  uint8_t i = s_cliN++;
  memcpy(s_cli[i].mac, m, 6);
  s_cli[i].ap = (int16_t)ap;
  s_cli[i].channel = ch; s_cli[i].rssi = rssi; s_cli[i].last = now; s_cli[i].pkts = 1;
  if (ap >= 0) s_ap[ap].clients++;
}

static void table_reset() { s_lock = true; s_apN = 0; s_cliN = 0; s_lock = false; }

// ------------------------------------------------------------- handler -----
// Dipanggil dari konteks callback sniffer -> harus ringan, tanpa Serial.
static void st_handler(const nc_frame* f) {
  if (s_lock) return;
  uint32_t now = millis();
  const uint8_t* ap  = nullptr;
  const uint8_t* cli = nullptr;

  if (f->type == 2) {                                   // DATA -> pasangan AP/client
    if (f->from_ds && !f->to_ds)      { ap = f->addr2; cli = f->addr1; }
    else if (f->to_ds && !f->from_ds) { ap = f->addr1; cli = f->addr2; }
    else return;                                        // ad-hoc / WDS -> abaikan
  } else if (!s_focused && f->type == 0 && f->subtype == 8) {   // BEACON -> discovery AP (mode bebas)
    if (f->has_addr3) ap_seen(f->addr3, f->channel, f->rssi, now);
    return;
  } else if (!s_focused && f->type == 0 && f->subtype == 4) {   // PROBE-REQ -> client tak terasosiasi
    if (f->has_addr2 && !mac_group(f->addr2) && !mac_zero(f->addr2))
      client_seen(f->addr2, -1, f->channel, f->rssi, now);
    return;
  } else {
    return;
  }

  if (mac_group(cli) || mac_zero(cli)) return;          // client wajib unicast
  if (mac_group(ap)  || mac_zero(ap))  return;
  if (s_focused && !mac_eq(ap, s_target)) return;       // mode fokus: hanya AP target
  int api = ap_seen(ap, f->channel, f->rssi, now);
  client_seen(cli, api, f->channel, f->rssi, now);
}

// ----------------------------------------------- mode bebas: dump penuh ----
static void cmd_stations(int argc, char** argv) {
  if (argc >= 2 && strcasecmp(argv[1], "clear") == 0) {
    table_reset();
    Serial.println(F("[stations] tabel direset"));
    return;
  }

  s_lock = true;
  uint32_t now = millis();
  Serial.printf("=== STATIONS === %u AP, %u client\n", s_apN, s_cliN);
  for (uint8_t a = 0; a < s_apN; a++) {
    Serial.printf("AP %s  ch%-2d %4ddBm  clients=%u  age=%lus\n",
      nc_mac_str(s_ap[a].bssid), s_ap[a].channel, s_ap[a].rssi,
      s_ap[a].clients, (unsigned long)((now - s_ap[a].last) / 1000));
    for (uint8_t c = 0; c < s_cliN; c++) if (s_cli[c].ap == a)
      Serial.printf("   - %s  %4ddBm  pkts=%lu  age=%lus\n",
        nc_mac_str(s_cli[c].mac), s_cli[c].rssi,
        (unsigned long)s_cli[c].pkts, (unsigned long)((now - s_cli[c].last) / 1000));
  }
  bool header = false;
  for (uint8_t c = 0; c < s_cliN; c++) if (s_cli[c].ap < 0) {
    if (!header) { Serial.println(F("client tak terasosiasi (probe-req):")); header = true; }
    Serial.printf("   ? %s  %4ddBm  pkts=%lu  age=%lus\n",
      nc_mac_str(s_cli[c].mac), s_cli[c].rssi,
      (unsigned long)s_cli[c].pkts, (unsigned long)((now - s_cli[c].last) / 1000));
  }
  s_lock = false;
}

// ------------------------------------------ mode terpandu: count <AP> ------
// Dipanggil saat user mengetik nomor AP (cli capture mode).
static void on_select(const char* line) {
  if (line[0] == 'q' || line[0] == 'Q' || line[0] == '\0') {
    Serial.println(F("[count] dibatalkan"));
    cli_release();
    return;
  }
  int idx = atoi(line);
  if (idx < 0 || idx >= (int)s_scanN) {
    Serial.printf("nomor tidak valid (0-%u). coba lagi atau 'q'\n",
                  s_scanN ? s_scanN - 1 : 0);
    return;                                   // tetap di mode pilih
  }

  station_count_on(s_scan[idx].bssid, s_scan[idx].channel, s_scan[idx].ssid);
  cli_release();
}

// programatik (UI) ----------------------------------------------------------
void station_count_on(const uint8_t* bssid, uint8_t ch, const char* ssid) {
  memcpy(s_target, bssid, 6);
  s_targetCh = ch;
  strncpy(s_targetSsid, ssid, sizeof(s_targetSsid));
  s_targetSsid[sizeof(s_targetSsid) - 1] = 0;

  table_reset();
  s_focused = true;
  sniffer_set_hop(false);
  sniffer_set_channel(s_targetCh);
  sniffer_set_verbose(false);
  if (!sniffer_running()) sniffer_start();
  s_lastShow = millis();
  Serial.printf("[count] target: %s (%s) ch%d\n",
    s_targetSsid[0] ? s_targetSsid : "<hidden>", nc_mac_str(s_target), s_targetCh);
}

void station_count_stop() {
  s_focused = false;
  sniffer_set_hop(true);
  sniffer_set_verbose(true);
  if (sniffer_running()) sniffer_stop();
}

int station_count_clients() {
  for (uint8_t i = 0; i < s_apN; i++) if (mac_eq(s_ap[i].bssid, s_target)) return s_ap[i].clients;
  return 0;
}

const char* station_count_ssid() { return s_targetSsid; }

static void cmd_count(int argc, char** argv) {
  if (argc >= 2 && strcasecmp(argv[1], "stop") == 0) {
    s_focused = false;
    sniffer_set_hop(true);
    sniffer_set_verbose(true);
    if (sniffer_running()) sniffer_stop();
    Serial.println(F("[count] berhenti"));
    return;
  }

  if (sniffer_running()) sniffer_stop();       // scan butuh STA normal
  Serial.println(F("[count] memindai AP..."));
  int n = WiFi.scanNetworks(false, true);

  s_scanN = 0;
  for (int i = 0; i < n && s_scanN < ST_MAX_AP; i++) {
    memcpy(s_scan[s_scanN].bssid, WiFi.BSSID(i), 6);
    s_scan[s_scanN].channel = (uint8_t)WiFi.channel(i);
    s_scan[s_scanN].rssi    = (int8_t)WiFi.RSSI(i);
    strncpy(s_scan[s_scanN].ssid, WiFi.SSID(i).c_str(), 32);
    s_scan[s_scanN].ssid[32] = 0;
    s_scanN++;
  }
  WiFi.scanDelete();

  if (s_scanN == 0) { Serial.println(F("[count] tidak ada AP ditemukan")); return; }

  Serial.println(F("=== pilih AP untuk Count Station ==="));
  for (uint8_t i = 0; i < s_scanN; i++)
    Serial.printf("  %u) ch%-2d %4ddBm  %s  %s\n",
      i, s_scan[i].channel, s_scan[i].rssi, nc_mac_str(s_scan[i].bssid),
      s_scan[i].ssid[0] ? s_scan[i].ssid : "<hidden>");
  Serial.println(F("ketik nomor AP (atau 'q' untuk batal):"));
  cli_capture(on_select, "pilih AP#> ");
}

// Tampilan live AP target, dipanggil dari loop()
void station_loop() {
  if (!s_focused) return;
  uint32_t now = millis();
  if ((now - s_lastShow) < 2500) return;
  s_lastShow = now;

  s_lock = true;
  int ai = -1;
  for (uint8_t i = 0; i < s_apN; i++) if (mac_eq(s_ap[i].bssid, s_target)) { ai = i; break; }

  Serial.printf("[count] %s (%s) ch%d : ",
    s_targetSsid[0] ? s_targetSsid : "<hidden>", nc_mac_str(s_target), s_targetCh);
  if (ai < 0) {
    Serial.println(F("0 station (belum ada trafik)"));
    s_lock = false;
    return;
  }
  Serial.printf("%u station\n", s_ap[ai].clients);
  uint8_t k = 0;
  for (uint8_t c = 0; c < s_cliN; c++) if (s_cli[c].ap == ai)
    Serial.printf("   %u) %s  %4ddBm  pkts=%lu  age=%lus\n",
      ++k, nc_mac_str(s_cli[c].mac), s_cli[c].rssi,
      (unsigned long)s_cli[c].pkts, (unsigned long)((now - s_cli[c].last) / 1000));
  s_lock = false;
}

void station_init() {
  sniffer_add_handler(st_handler);
  cli_register("count",    "count station terpandu (count | count stop)", cmd_count);
  cli_register("stations", "dump semua AP->client  (stations | stations clear)", cmd_stations);
}
