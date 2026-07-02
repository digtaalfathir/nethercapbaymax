// nethercap :: Fase 1 — sniffer engine + CLI control plane
//
// Arsitektur:
//   main      -> init + loop (cli_update + sniffer_loop)
//   cli       -> control plane (Serial command dispatcher)
//   sniffer   -> promiscuous engine (fondasi modul berikutnya)
//
// Modul berikutnya (count-station, deauth-monitor, dst) cukup
// sniffer_set_handler() untuk meng-intercept frame, lalu daftarkan
// perintah CLI-nya sendiri.

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include "cli.h"
#include "settings.h"
#include "sniffer.h"
#include "station.h"
#include "beacon.h"
#include "deauthmon.h"
#include "deauth.h"
#include "pdeauth.h"
#include "evil.h"
#include "ui.h"

#ifndef NETHERCAP_VERSION
#define NETHERCAP_VERSION "dev"
#endif

// Scan AP aktif (butuh STA normal -> hentikan sniffer dulu kalau jalan)
static void cmd_scan(int argc, char** argv) {
  (void)argc; (void)argv;
  if (sniffer_running()) { Serial.println(F("[scan] hentikan sniffer dulu...")); sniffer_stop(); }

  Serial.println(F("[scan] memindai..."));
  int n = WiFi.scanNetworks(false, true);
  if (n <= 0) { Serial.println(F("[scan] tidak ada AP")); return; }

  Serial.printf("[scan] %d AP:\n", n);
  for (int i = 0; i < n; i++)
    Serial.printf("  %2d | ch%2d | %4ddBm | %-17s | %s\n",
      i, WiFi.channel(i), WiFi.RSSI(i), WiFi.BSSIDstr(i).c_str(),
      WiFi.SSID(i).length() ? WiFi.SSID(i).c_str() : "<hidden>");
  WiFi.scanDelete();
}

static void cmd_info(int argc, char** argv) {
  (void)argc; (void)argv;
  Serial.printf("nethercap v%s | chip %08X | free %u B | ch %d | sniffer %s\n",
    NETHERCAP_VERSION, ESP.getChipId(), ESP.getFreeHeap(),
    sniffer_channel(), sniffer_running() ? "ON" : "OFF");
}

void setup() {
  Serial.begin(115200);
  delay(300);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  Serial.printf("\n=== nethercap v%s ===\n", NETHERCAP_VERSION);

  settings_init();                 // load config persistent (EEPROM) dulu
  cli_register("scan", "scan AP aktif",            cmd_scan);
  cli_register("info", "info & status perangkat",  cmd_info);
  sniffer_init();
  station_init();
  beacon_init();
  deauthmon_init();
  deauth_init();
  pdeauth_init();
  evil_init();
  cli_begin();                 // daftarkan 'help' + cetak prompt

  ui_init();                   // TFT + tombol (splash -> menu)
}

void loop() {
  cli_update();
  sniffer_loop();
  station_loop();
  beacon_loop();
  deauthmon_loop();
  deauth_loop();
  pdeauth_loop();
  evil_loop();
  ui_loop();
}
