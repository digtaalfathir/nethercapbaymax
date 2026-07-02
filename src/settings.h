// nethercap :: Persistent Settings (EEPROM)
// Simpan konfigurasi user antar-reboot: ambang deauth monitor, jumlah SSID
// acak beacon, default auto-deauth evil twin.

#pragma once
#include <Arduino.h>

struct nc_settings {
  uint16_t magic;
  uint8_t  dmon_threshold;   // 1..50  — ambang alarm deauth/detik
  uint8_t  beacon_random;    // 1..32  — jumlah SSID acak per "tambah"
  uint8_t  evil_autodeauth;  // 0/1    — default auto-deauth saat evil twin
};

void         settings_init();   // load dari EEPROM (atau default)
nc_settings* settings_get();
void         settings_save();
