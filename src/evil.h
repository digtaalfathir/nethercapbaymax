// nethercap :: Evil Twin
// AP kembar (clone SSID + BSSID, open) + captive portal + tangkap password
// + verifikasi password ke AP asli (STA). Kalau salah, portal minta ulang.

#pragma once
#include <Arduino.h>

void evil_init();    // perintah CLI 'evil'
void evil_loop();    // layani DNS + web + verifikasi — panggil di loop()
void evil_stop();    // teardown (no-op kalau off) — dipakai modul lain

// programatik (untuk UI)
void        evil_attack(const uint8_t* bssid, uint8_t ch, const char* ssid);
bool        evil_active();
int         evil_clients();
bool        evil_got_password();
const char* evil_password();
const char* evil_ssid();
uint32_t    evil_deauth_count();
bool        evil_deauth_on();
void        evil_toggle_deauth();
