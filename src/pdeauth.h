// nethercap :: Precise Deauth
// Pilih AP -> kumpulkan client-nya (live) -> pilih client tertentu ->
// deauth unicast 2-arah (ke client & ke AP). Lebih efektif & terarah.

#pragma once
#include <Arduino.h>

void pdeauth_init();   // pasang handler sniffer + perintah CLI 'pdeauth'
void pdeauth_loop();   // tampilan client (collect) / kirim deauth (attack)
void pdeauth_stop();   // hentikan (no-op kalau idle) — dipakai modul lain

// programatik (untuk UI)
void        pdeauth_collect_on(const uint8_t* bssid, uint8_t ch, const char* ssid);
int         pdeauth_client_count();
const char* pdeauth_client_mac(int i);   // buffer statis
int8_t      pdeauth_client_rssi(int i);
void        pdeauth_attack_index(int idx);
void        pdeauth_attack_all();
bool        pdeauth_collecting();
bool        pdeauth_attacking();
void        pdeauth_stats(uint32_t* sent, uint32_t* fail);
