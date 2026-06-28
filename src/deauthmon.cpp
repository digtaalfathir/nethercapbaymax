#include "deauthmon.h"
#include "sniffer.h"
#include "cli.h"
#include <string.h>

#define DM_MAX_SRC    16
#define DM_THRESHOLD  8        // deauth+disassoc per detik -> alarm
#define DM_WINDOW_MS  1000     // panjang window evaluasi
#define DM_BEAT_MS    10000    // heartbeat saat sepi

struct dm_src {
  uint8_t  mac[6];             // transmitter (addr2) — pengirim deauth
  uint8_t  bssid[6];           // addr3
  uint32_t count;             // total deauth/disassoc dari sumber ini
  uint32_t last;
  int8_t   rssi;
  uint8_t  channel;
};

static dm_src   s_src[DM_MAX_SRC];
static uint8_t  s_srcN = 0;

static bool     s_on = false;
static volatile uint32_t s_window = 0;   // counter window berjalan (ditulis di callback)
static volatile uint32_t s_total  = 0;
static uint32_t s_lastEval = 0;
static uint32_t s_lastBeat = 0;

// -------------------------------------------------------------- helpers ----
static inline bool mac_eq(const uint8_t* a, const uint8_t* b) { return memcmp(a, b, 6) == 0; }

static void record(const uint8_t* src, const uint8_t* bssid,
                   uint8_t ch, int8_t rssi, uint32_t now) {
  for (uint8_t i = 0; i < s_srcN; i++) if (mac_eq(s_src[i].mac, src)) {
    s_src[i].count++; s_src[i].last = now; s_src[i].rssi = rssi; s_src[i].channel = ch;
    memcpy(s_src[i].bssid, bssid, 6);
    return;
  }
  if (s_srcN >= DM_MAX_SRC) return;
  uint8_t i = s_srcN++;
  memcpy(s_src[i].mac, src, 6);
  memcpy(s_src[i].bssid, bssid, 6);
  s_src[i].count = 1; s_src[i].last = now; s_src[i].rssi = rssi; s_src[i].channel = ch;
}

static void print_sources() {
  uint32_t now = millis();
  Serial.printf("  sumber terdeteksi (%u):\n", s_srcN);
  for (uint8_t i = 0; i < s_srcN; i++) {
    // nc_mac_str pakai buffer statis -> panggil terpisah per printf
    Serial.printf("   - src %s", nc_mac_str(s_src[i].mac));
    Serial.printf("  bssid %s  count=%lu  ch%d  %ddBm  age=%lus\n",
      nc_mac_str(s_src[i].bssid), (unsigned long)s_src[i].count,
      s_src[i].channel, s_src[i].rssi,
      (unsigned long)((now - s_src[i].last) / 1000));
  }
}

// ------------------------------------------------------------- handler -----
// Konteks callback sniffer -> ringan, tanpa Serial.
static void dm_handler(const nc_frame* f) {
  if (!s_on) return;
  if (f->type != 0) return;
  if (f->subtype != 12 && f->subtype != 10) return;     // deauth / disassoc saja
  if (!f->has_addr2) return;
  record(f->addr2, f->has_addr3 ? f->addr3 : f->addr2, f->channel, f->rssi, millis());
  s_window++;
  s_total++;
}

// ------------------------------------------------------------- lifecycle ---
static void start() {
  s_on = true;
  s_window = 0; s_total = 0; s_srcN = 0;
  s_lastEval = millis(); s_lastBeat = millis();
  sniffer_set_verbose(false);
  sniffer_set_hop(true);
  if (!sniffer_running()) sniffer_start();
  Serial.printf("[dmon] MONITOR aktif — ambang %u deauth/detik, hop on.\n", DM_THRESHOLD);
  Serial.println(F("       'dmon stop' berhenti | 'dmon test' uji alarm"));
}

static void stop() {
  if (!s_on) { Serial.println(F("[dmon] tidak jalan")); return; }
  s_on = false;
  if (sniffer_running()) sniffer_stop();
  sniffer_set_verbose(true);
  Serial.printf("[dmon] stop — total deauth/disassoc terdeteksi: %lu\n", (unsigned long)s_total);
  if (s_srcN) print_sources();
}

void deauthmon_loop() {
  if (!s_on) return;
  uint32_t now = millis();
  if (now - s_lastEval < DM_WINDOW_MS) return;
  s_lastEval = now;

  uint32_t c = s_window;
  s_window = 0;

  if (c == 0) {
    if (now - s_lastBeat >= DM_BEAT_MS) {
      s_lastBeat = now;
      Serial.println(F("[dmon] clear — tidak ada deauth/disassoc"));
    }
    return;
  }
  s_lastBeat = now;

  if (c >= DM_THRESHOLD) {
    Serial.printf("\n*** ALARM DEAUTH *** %lu frame/detik (ambang %u) — kemungkinan serangan!\n",
                  (unsigned long)c, DM_THRESHOLD);
    print_sources();
  } else {
    Serial.printf("[dmon] %lu deauth/disassoc per detik (di bawah ambang)\n", (unsigned long)c);
  }
}

// ----------------------------------------------------------- CLI command --
static void cmd_dmon(int argc, char** argv) {
  if (argc >= 2 && strcasecmp(argv[1], "stop") == 0) { stop(); return; }

  if (argc >= 2 && strcasecmp(argv[1], "test") == 0) {
    if (!s_on) { Serial.println(F("[dmon] start dulu: ketik 'dmon'")); return; }
    uint8_t atk[6] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37 };   // attacker palsu
    uint8_t bss[6] = { 0x6C, 0xA5, 0xD1, 0x32, 0x9E, 0xA0 };   // AP korban palsu
    for (int i = 0; i < 30; i++) record(atk, bss, 6, -42, millis());
    s_window += 30;
    Serial.println(F("[dmon] +30 deauth sintetis disuntik — alarm muncul ~1 detik lagi"));
    return;
  }

  start();
}

void deauthmon_init() {
  sniffer_add_handler(dm_handler);
  cli_register("dmon", "deauth monitor (dmon | dmon stop | dmon test)", cmd_dmon);
}
