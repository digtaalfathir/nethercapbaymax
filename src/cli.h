// nethercap :: CLI control plane
// Tabel command sederhana + dispatcher non-blocking dari Serial.
// Tiap modul mendaftarkan perintahnya sendiri lewat cli_register().

#pragma once
#include <Arduino.h>

typedef void (*nc_cmd_fn)(int argc, char** argv);

struct nc_command {
  const char* name;
  const char* help;
  nc_cmd_fn   fn;
};

void cli_begin();                                                   // banner + prompt
bool cli_register(const char* name, const char* help, nc_cmd_fn fn);
void cli_update();                                                  // panggil di loop()

// Mode input terpandu: arahkan baris mentah ke fn (mis. "pilih nomor AP")
// alih-alih ke command dispatcher. Panggil cli_release() untuk kembali normal.
typedef void (*nc_input_fn)(const char* line);
void cli_capture(nc_input_fn fn, const char* prompt);
void cli_release();
