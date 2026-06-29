// nethercap :: UI (TFT 240x280 ST7789 + 3 tombol)
// Menu navigable: UP/DOWN pilih, OK masuk/aksi, OK-tahan = kembali.
// CLI serial tetap jalan paralel.

#pragma once
#include <Arduino.h>

void ui_init();
void ui_loop();
