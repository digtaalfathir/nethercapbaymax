// nethercap :: Deauth
// Pilih AP hasil scan -> broadcast deauth + disassoc ke channel AP itu
// (spoof BSSID sebagai source). Injection via wifi_send_pkt_freedom().

#pragma once
#include <Arduino.h>

void deauth_init();    // daftar perintah CLI 'deauth'
void deauth_loop();    // kirim deauth saat aktif — panggil di loop()
void deauth_stop();    // hentikan (no-op kalau tak jalan) — dipakai modul lain
