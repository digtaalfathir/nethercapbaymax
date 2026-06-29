// nethercap :: Deauth Monitor (defensif)
// Deteksi frame deauth (subtype 12) & disassoc (subtype 10), hitung rate,
// dan alarm saat melewati ambang (ciri serangan deauth flood).
// Lacak juga siapa sumbernya (transmitter) & AP target-nya.

#pragma once
#include <Arduino.h>

void deauthmon_init();   // pasang handler sniffer + perintah CLI 'dmon'
void deauthmon_loop();   // evaluasi window + alarm/heartbeat — panggil di loop()

// Accessor untuk UI/display
void deauthmon_start();
void deauthmon_stop();
bool deauthmon_active();
void deauthmon_test();   // suntik 30 deauth sintetis (uji alarm)
void deauthmon_get(uint32_t* total, uint32_t* lastRate, bool* alarm);
