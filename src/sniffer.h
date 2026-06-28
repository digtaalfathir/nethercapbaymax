// nethercap :: Promiscuous sniffer engine
// Fondasi yang dipakai modul lain (count-station, deauth-monitor, dst).
//
// Cara kerja: callback promiscuous mem-parse header 802.11 ke nc_frame,
// lalu (1) update statistik, (2) panggil handler opsional, (3) push ke
// ring buffer untuk dicetak di loop (TIDAK mencetak di dalam callback).

#pragma once
#include <Arduino.h>

// Tipe frame 802.11
//   type:    0 = management, 1 = control, 2 = data
//   subtype: lihat nc_subtype_name()
struct nc_frame {
  int8_t   rssi;
  uint8_t  channel;
  uint8_t  type;
  uint8_t  subtype;
  uint16_t len;
  bool     has_addr2;
  bool     has_addr3;
  bool     to_ds;      // frame menuju distribution system (client -> AP)
  bool     from_ds;    // frame dari distribution system (AP -> client)
  uint8_t  addr1[6];   // receiver / destination
  uint8_t  addr2[6];   // transmitter / source
  uint8_t  addr3[6];   // BSSID (umumnya)
};

typedef void (*nc_frame_handler)(const nc_frame* f);

void    sniffer_init();        // daftarkan perintah CLI (sniff/channel/hop/stats)
void    sniffer_loop();        // channel hopping + flush cetak; panggil di loop()
void    sniffer_start();
void    sniffer_stop();
bool    sniffer_running();

void    sniffer_set_channel(uint8_t ch);
uint8_t sniffer_channel();
void    sniffer_set_hop(bool on);
void    sniffer_set_verbose(bool on);   // cetak frame mentah + stats periodik di loop
bool    sniffer_add_handler(nc_frame_handler h);   // modul lain meng-intercept frame (maks 4)

// Helper format
const char* nc_mac_str(const uint8_t* mac);            // "AA:BB:CC:DD:EE:FF" (buffer statis)
const char* nc_subtype_name(uint8_t type, uint8_t subtype);
