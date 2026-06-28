#include "cli.h"
#include <string.h>

#define NC_MAX_CMDS 16
#define NC_LINE_MAX 96
#define NC_ARGV_MAX 8

static nc_command s_cmds[NC_MAX_CMDS];
static uint8_t    s_count = 0;

static char    s_line[NC_LINE_MAX];
static uint8_t s_len = 0;

static nc_input_fn s_capture = nullptr;   // mode input terpandu
static const char* s_prompt  = "> ";

static void cmd_help(int argc, char** argv) {
  (void)argc; (void)argv;
  Serial.println(F("perintah tersedia:"));
  for (uint8_t i = 0; i < s_count; i++)
    Serial.printf("  %-9s - %s\n", s_cmds[i].name, s_cmds[i].help);
}

bool cli_register(const char* name, const char* help, nc_cmd_fn fn) {
  if (s_count >= NC_MAX_CMDS) return false;
  s_cmds[s_count++] = { name, help, fn };
  return true;
}

void cli_begin() {
  s_len = 0;
  cli_register("help", "daftar perintah", cmd_help);
  Serial.println(F("\nnethercap CLI siap. ketik 'help'."));
  Serial.print(s_prompt);
}

void cli_capture(nc_input_fn fn, const char* prompt) {
  s_capture = fn;
  s_prompt  = prompt ? prompt : "> ";
}
void cli_release() {
  s_capture = nullptr;
  s_prompt  = "> ";
}

static void dispatch(char* line) {
  char* argv[NC_ARGV_MAX];
  int   argc = 0;
  char* p = line;
  while (*p && argc < NC_ARGV_MAX) {
    while (*p == ' ') *p++ = '\0';          // lewati spasi
    if (!*p) break;
    argv[argc++] = p;                       // awal token
    while (*p && *p != ' ') p++;            // sampai spasi berikutnya
  }
  if (argc == 0) return;

  for (uint8_t i = 0; i < s_count; i++) {
    if (strcasecmp(argv[0], s_cmds[i].name) == 0) {
      s_cmds[i].fn(argc, argv);
      return;
    }
  }
  Serial.printf("perintah tak dikenal: %s (ketik 'help')\n", argv[0]);
}

void cli_update() {
  while (Serial.available()) {
    char c = (char) Serial.read();
    if (c == '\r') continue;

    if (c == '\n') {
      Serial.println();
      s_line[s_len] = '\0';
      if (s_capture)        s_capture(s_line);   // bisa memanggil cli_release()
      else if (s_len > 0)   dispatch(s_line);
      s_len = 0;
      Serial.print(s_prompt);                    // prompt sesuai mode terkini
    } else if (c == 8 || c == 127) {        // backspace
      if (s_len > 0) { s_len--; Serial.print(F("\b \b")); }
    } else if (s_len < NC_LINE_MAX - 1) {
      s_line[s_len++] = c;
      Serial.print(c);                      // echo
    }
  }
}
