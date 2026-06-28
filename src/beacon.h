// nethercap :: Beacon Spam
// Broadcast banyak beacon frame dengan SSID palsu (manual / acak).
// Menu terpandu: tambah SSID -> start. Injection via wifi_send_pkt_freedom().

#pragma once
#include <Arduino.h>

void beacon_init();   // daftar perintah CLI 'beacon'
void beacon_loop();   // kirim beacon + sweep channel — panggil di loop()
void beacon_stop();   // hentikan spam (no-op kalau tak jalan) — dipakai modul lain
