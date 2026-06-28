// nethercap :: Precise Deauth
// Pilih AP -> kumpulkan client-nya (live) -> pilih client tertentu ->
// deauth unicast 2-arah (ke client & ke AP). Lebih efektif & terarah.

#pragma once
#include <Arduino.h>

void pdeauth_init();   // pasang handler sniffer + perintah CLI 'pdeauth'
void pdeauth_loop();   // tampilan client (collect) / kirim deauth (attack)
void pdeauth_stop();   // hentikan (no-op kalau idle) — dipakai modul lain
