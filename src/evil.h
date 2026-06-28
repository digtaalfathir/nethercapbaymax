// nethercap :: Evil Twin
// AP kembar (clone SSID + BSSID, open) + captive portal + tangkap password
// + verifikasi password ke AP asli (STA). Kalau salah, portal minta ulang.

#pragma once
#include <Arduino.h>

void evil_init();    // perintah CLI 'evil'
void evil_loop();    // layani DNS + web + verifikasi — panggil di loop()
void evil_stop();    // teardown (no-op kalau off) — dipakai modul lain
