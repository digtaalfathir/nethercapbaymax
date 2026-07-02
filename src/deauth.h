// nethercap :: Deauth
// Pilih AP hasil scan -> broadcast deauth + disassoc ke channel AP itu
// (spoof BSSID sebagai source). Injection via wifi_send_pkt_freedom().

#pragma once
#include <Arduino.h>

void deauth_init();    // daftar perintah CLI 'deauth'
void deauth_loop();    // kirim deauth saat aktif — panggil di loop()
void deauth_stop();    // hentikan (no-op kalau tak jalan) — dipakai modul lain

// programatik (untuk UI)
void        deauth_attack(const uint8_t* bssid, uint8_t ch, const char* ssid);
void        deauth_all_start();       // gempur semua AP (sweep)
uint8_t     deauth_all_count();       // jumlah AP yang digempur
bool        deauth_active();
void        deauth_stats(uint32_t* sent, uint32_t* fail);
const char* deauth_ssid();
