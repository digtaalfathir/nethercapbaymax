// nethercap :: 3 push button (UP / DOWN / OK)
// UP=D1(GPIO5), DOWN=D4(GPIO2), OK=D3(GPIO0). Semua INPUT_PULLUP, tekan=LOW.
// OK ditahan >0.6s = BACK (karena cuma 3 tombol).
// CATATAN: jangan tahan OK saat power-on/reset (GPIO0 -> mode flash).

#pragma once
#include <Arduino.h>

enum nc_btn { BTN_NONE = 0, BTN_UP, BTN_DOWN, BTN_OK, BTN_BACK };

void   buttons_init();
nc_btn buttons_poll();   // satu event per panggilan; BTN_NONE jika tidak ada
