#include "sniffer.h"
#include "cli.h"
#include <ESP8266WiFi.h>
#include <string.h>

extern "C" {
  #include "user_interface.h"
}

// ---------------------------------------------------------------- state ----
static volatile bool s_running = false;
static uint8_t  s_channel     = 1;
static bool     s_hop         = true;
static uint32_t s_hopInterval = 300;   // ms per channel
static uint32_t s_lastHop     = 0;
static uint32_t s_lastStats   = 0;
static bool     s_verbose     = true;

#define MAX_HANDLERS 4
static nc_frame_handler s_handlers[MAX_HANDLERS];
static uint8_t          s_handlerN = 0;

static struct {
  uint32_t total, mgmt, ctrl, data;
  uint32_t beacon, probe, deauth, disassoc;
  uint32_t dropped;
} s_stats;

// -------------------------------------- ring buffer (1 producer/1 consumer) -
// Producer = callback SDK, consumer = loop(). ESP8266 single-core, jadi
// volatile index sudah cukup aman untuk pola ini.
#define RING_SZ 24
static nc_frame        s_ring[RING_SZ];
static volatile uint8_t s_head = 0, s_tail = 0;

static inline bool ring_push(const nc_frame* f) {
  uint8_t next = (uint8_t)((s_head + 1) % RING_SZ);
  if (next == s_tail) return false;          // penuh -> drop
  s_ring[s_head] = *f;
  s_head = next;
  return true;
}
static inline bool ring_pop(nc_frame* out) {
  if (s_tail == s_head) return false;
  *out = s_ring[s_tail];
  s_tail = (uint8_t)((s_tail + 1) % RING_SZ);
  return true;
}

// ------------------------------------------------------------- callback ----
// Buffer ESP8266: [ RxControl (12B) ][ frame 802.11 ... ]
// rx_ctrl.rssi = byte ke-0. Frame mulai di offset 12 (berlaku untuk
// sniffer_buf & sniffer_buf2). len==12 artinya hanya rx_ctrl, tanpa frame.
static void sniffer_cb(uint8_t* buf, uint16_t len) {
  if (len < 12) return;
  int8_t rssi = (int8_t) buf[0];
  if (len == 12) return;

  const uint8_t* p = buf + 12;
  uint16_t flen = (uint16_t)(len - 12);
  if (flen < 4) return;

  uint8_t fc0     = p[0];                     // frame control byte 0
  uint8_t fc1     = p[1];                     // frame control byte 1 (flags)
  uint8_t type    = (uint8_t)((fc0 >> 2) & 0x03);
  uint8_t subtype = (uint8_t)((fc0 >> 4) & 0x0F);

  nc_frame f;
  f.rssi    = rssi;
  f.channel = s_channel;                      // kita yang set channel -> tahu pasti
  f.type    = type;
  f.subtype = subtype;
  f.len     = flen;
  f.to_ds   = (fc1 & 0x01) != 0;
  f.from_ds = (fc1 & 0x02) != 0;
  f.has_addr2 = false;
  f.has_addr3 = false;

  if (flen >= 10) memcpy(f.addr1, p + 4, 6);  else memset(f.addr1, 0, 6);
  if (flen >= 16) { memcpy(f.addr2, p + 10, 6); f.has_addr2 = true; } else memset(f.addr2, 0, 6);
  if (flen >= 22) { memcpy(f.addr3, p + 16, 6); f.has_addr3 = true; } else memset(f.addr3, 0, 6);

  s_stats.total++;
  if (type == 0) {
    s_stats.mgmt++;
    if      (subtype == 8)               s_stats.beacon++;
    else if (subtype == 4 || subtype == 5) s_stats.probe++;
    else if (subtype == 12)              s_stats.deauth++;
    else if (subtype == 10)              s_stats.disassoc++;
  } else if (type == 1) s_stats.ctrl++;
  else if (type == 2)   s_stats.data++;

  for (uint8_t i = 0; i < s_handlerN; i++) s_handlers[i](&f);
  if (s_verbose && !ring_push(&f)) s_stats.dropped++;
}

// -------------------------------------------------------------- helpers ----
const char* nc_mac_str(const uint8_t* mac) {
  static char b[18];
  snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return b;
}

const char* nc_subtype_name(uint8_t type, uint8_t subtype) {
  if (type == 0) switch (subtype) {           // management
    case 0:  return "assoc-req";
    case 1:  return "assoc-resp";
    case 2:  return "reassoc-req";
    case 3:  return "reassoc-resp";
    case 4:  return "probe-req";
    case 5:  return "probe-resp";
    case 8:  return "beacon";
    case 10: return "disassoc";
    case 11: return "auth";
    case 12: return "deauth";
    case 13: return "action";
    default: return "mgmt?";
  }
  if (type == 1) switch (subtype) {           // control
    case 11: return "rts";
    case 12: return "cts";
    case 13: return "ack";
    default: return "ctrl?";
  }
  if (type == 2) switch (subtype) {           // data
    case 0:  return "data";
    case 4:  return "null";
    case 8:  return "qos-data";
    case 12: return "qos-null";
    default: return "data?";
  }
  return "?";
}

static void print_stats() {
  Serial.printf("[stats] total=%lu mgmt=%lu (beacon=%lu probe=%lu deauth=%lu disassoc=%lu) ctrl=%lu data=%lu dropped=%lu\n",
    (unsigned long)s_stats.total, (unsigned long)s_stats.mgmt,
    (unsigned long)s_stats.beacon, (unsigned long)s_stats.probe,
    (unsigned long)s_stats.deauth, (unsigned long)s_stats.disassoc,
    (unsigned long)s_stats.ctrl, (unsigned long)s_stats.data,
    (unsigned long)s_stats.dropped);
}

static void print_frame(const nc_frame* f) {
  const char* tname = f->type == 0 ? "mgmt" : f->type == 1 ? "ctrl"
                    : f->type == 2 ? "data" : "ext";
  Serial.printf("[%s/%-10s] ch%-2d %4ddBm  src %s",
    tname, nc_subtype_name(f->type, f->subtype), f->channel, f->rssi,
    f->has_addr2 ? nc_mac_str(f->addr2) : "--:--:--:--:--:--");
  Serial.printf(" -> %s", nc_mac_str(f->addr1));
  if (f->has_addr3) Serial.printf("  bssid %s", nc_mac_str(f->addr3));
  Serial.println();
}

// ------------------------------------------------------------- lifecycle ---
void sniffer_set_channel(uint8_t ch) {
  s_channel = ch;
  if (s_running) wifi_set_channel(ch);
}
uint8_t sniffer_channel()                  { return s_channel; }
bool    sniffer_running()                  { return s_running; }
void    sniffer_set_hop(bool on)           { s_hop = on; }
void    sniffer_set_verbose(bool on)       { s_verbose = on; }
bool    sniffer_add_handler(nc_frame_handler h) {
  if (s_handlerN >= MAX_HANDLERS) return false;
  s_handlers[s_handlerN++] = h;
  return true;
}

void sniffer_start() {
  if (s_running) { Serial.println(F("[sniffer] sudah jalan")); return; }
  memset(&s_stats, 0, sizeof(s_stats));
  s_head = s_tail = 0;

  WiFi.disconnect();
  wifi_set_opmode_current(STATION_MODE);
  wifi_set_channel(s_channel);
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(sniffer_cb);
  wifi_promiscuous_enable(1);

  s_running   = true;
  s_lastHop   = millis();
  s_lastStats = millis();
  Serial.printf("[sniffer] START ch%d hop=%s — ketik 'sniff stop' untuk berhenti\n",
                s_channel, s_hop ? "on" : "off");
}

void sniffer_stop() {
  if (!s_running) { Serial.println(F("[sniffer] tidak jalan")); return; }
  wifi_promiscuous_enable(0);
  WiFi.mode(WIFI_STA);
  s_running = false;
  Serial.println(F("[sniffer] STOP"));
  print_stats();
}

void sniffer_loop() {
  // selalu kuras ring (max 12/loop biar tak memonopoli CPU)
  nc_frame f;
  uint8_t budget = 12;
  while (budget-- && ring_pop(&f)) print_frame(&f);

  if (!s_running) return;

  uint32_t now = millis();
  if (s_hop && (now - s_lastHop) >= s_hopInterval) {
    s_lastHop = now;
    s_channel = (uint8_t)(s_channel >= 13 ? 1 : s_channel + 1);
    wifi_set_channel(s_channel);
  }
  if (s_verbose && (now - s_lastStats) >= 3000) {
    s_lastStats = now;
    print_stats();
  }
}

// ----------------------------------------------------------- CLI commands --
static void cmd_sniff(int argc, char** argv) {
  if (argc >= 2 && strcasecmp(argv[1], "stop") == 0) sniffer_stop();
  else sniffer_start();
}
static void cmd_channel(int argc, char** argv) {
  if (argc < 2) {
    Serial.printf("channel=%d hop=%s\n", s_channel, s_hop ? "on" : "off");
    return;
  }
  int ch = atoi(argv[1]);
  if (ch < 1 || ch > 13) { Serial.println(F("channel harus 1-13")); return; }
  s_hop = false;
  sniffer_set_channel((uint8_t)ch);
  Serial.printf("channel=%d (hop OFF)\n", ch);
}
static void cmd_hop(int argc, char** argv) {
  if (argc >= 2) s_hop = (strcasecmp(argv[1], "off") != 0);
  else           s_hop = !s_hop;
  Serial.printf("hop=%s\n", s_hop ? "ON" : "OFF");
}
static void cmd_stats(int argc, char** argv) {
  (void)argc; (void)argv;
  print_stats();
}

void sniffer_init() {
  cli_register("sniff",   "mulai/stop sniffer  (sniff | sniff stop)", cmd_sniff);
  cli_register("channel", "channel tetap       (channel <1-13>)",     cmd_channel);
  cli_register("hop",     "channel hopping     (hop on|off)",         cmd_hop);
  cli_register("stats",   "statistik frame",                          cmd_stats);
}
