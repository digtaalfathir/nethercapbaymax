// nethercap :: Count Station
// Bangun tabel asosiasi  AP (BSSID) -> { client MAC }  dari frame data,
// plus discovery AP (beacon) & client tak terasosiasi (probe-req).
// Tabel ini jadi sumber target untuk precise deauth nanti.

#pragma once
#include <Arduino.h>

void station_init();   // pasang handler sniffer + daftar perintah CLI
void station_loop();   // tampilan live AP target (mode count) — panggil di loop()

// programatik (untuk UI)
void        station_count_on(const uint8_t* bssid, uint8_t ch, const char* ssid);
void        station_count_stop();
int         station_count_clients();
const char* station_count_ssid();
