// nethercap :: Deauth Monitor (defensif)
// Deteksi frame deauth (subtype 12) & disassoc (subtype 10), hitung rate,
// dan alarm saat melewati ambang (ciri serangan deauth flood).
// Lacak juga siapa sumbernya (transmitter) & AP target-nya.

#pragma once
#include <Arduino.h>

void deauthmon_init();   // pasang handler sniffer + perintah CLI 'dmon'
void deauthmon_loop();   // evaluasi window + alarm/heartbeat — panggil di loop()
