#include "settings.h"
#include "cli.h"
#include <EEPROM.h>
#include <string.h>

#define CFG_MAGIC 0x4E43   // "NC"
#define CFG_SIZE  64

static nc_settings s_cfg;

static void apply_defaults() {
  s_cfg.magic          = CFG_MAGIC;
  s_cfg.dmon_threshold = 8;
  s_cfg.beacon_random  = 5;
  s_cfg.evil_autodeauth = 0;
}

nc_settings* settings_get() { return &s_cfg; }

void settings_save() {
  s_cfg.magic = CFG_MAGIC;
  EEPROM.put(0, s_cfg);
  EEPROM.commit();
}

// clamp nilai supaya selalu valid (jaga dari EEPROM korup)
static void sanitize() {
  if (s_cfg.dmon_threshold < 1 || s_cfg.dmon_threshold > 50) s_cfg.dmon_threshold = 8;
  if (s_cfg.beacon_random  < 1 || s_cfg.beacon_random  > 32) s_cfg.beacon_random  = 5;
  if (s_cfg.evil_autodeauth > 1) s_cfg.evil_autodeauth = 0;
}

static void cmd_settings(int argc, char** argv) {
  if (argc >= 3) {
    int v = atoi(argv[2]);
    if      (!strcasecmp(argv[1], "threshold")) s_cfg.dmon_threshold  = (uint8_t)v;
    else if (!strcasecmp(argv[1], "beacon"))    s_cfg.beacon_random   = (uint8_t)v;
    else if (!strcasecmp(argv[1], "autodeauth"))s_cfg.evil_autodeauth = v ? 1 : 0;
    else { Serial.println(F("key: threshold | beacon | autodeauth")); return; }
    sanitize(); settings_save();
    Serial.println(F("[settings] disimpan"));
  }
  Serial.printf("[settings] dmon_threshold=%u  beacon_random=%u  evil_autodeauth=%u\n",
    s_cfg.dmon_threshold, s_cfg.beacon_random, s_cfg.evil_autodeauth);
}

void settings_init() {
  EEPROM.begin(CFG_SIZE);
  EEPROM.get(0, s_cfg);
  if (s_cfg.magic != CFG_MAGIC) { apply_defaults(); settings_save(); }
  sanitize();
  cli_register("settings", "lihat/ubah setting (settings <key> <val>)", cmd_settings);
}
