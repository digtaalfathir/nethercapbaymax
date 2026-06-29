#include "buttons.h"

#define PIN_UP    5     // D1
#define PIN_DOWN  2     // D4
#define PIN_OK    0     // D3

#define DEBOUNCE_MS   30
#define REPEAT_DELAY  450    // mulai auto-repeat setelah ditahan segini
#define REPEAT_RATE   140    // jeda antar repeat
#define LONGPRESS_MS  600    // OK ditahan segini -> BACK

struct btn_t {
  uint8_t  pin;
  bool     stable;     // status debounced (true = ditekan)
  bool     lastRaw;
  uint32_t tChange;    // waktu perubahan raw terakhir
  uint32_t tDown;      // waktu mulai ditekan
  uint32_t tRep;       // repeat terakhir
  bool     longFired;  // BACK sudah dikirim utk tekanan ini
};

static btn_t bUp   = { PIN_UP,   false, false, 0, 0, 0, false };
static btn_t bDown = { PIN_DOWN, false, false, 0, 0, 0, false };
static btn_t bOk   = { PIN_OK,   false, false, 0, 0, 0, false };

void buttons_init() {
  pinMode(PIN_UP,   INPUT_PULLUP);
  pinMode(PIN_DOWN, INPUT_PULLUP);
  pinMode(PIN_OK,   INPUT_PULLUP);
}

// UP/DOWN: event saat press-edge + auto-repeat saat ditahan.
static nc_btn updateNav(btn_t& b, nc_btn ev, uint32_t now) {
  bool raw = (digitalRead(b.pin) == LOW);
  if (raw != b.lastRaw) { b.lastRaw = raw; b.tChange = now; }
  if ((now - b.tChange) >= DEBOUNCE_MS && raw != b.stable) {
    b.stable = raw;
    if (raw) { b.tDown = now; b.tRep = now; return ev; }   // press-edge
  }
  if (b.stable && raw && (now - b.tDown) >= REPEAT_DELAY && (now - b.tRep) >= REPEAT_RATE) {
    b.tRep = now; return ev;                               // auto-repeat
  }
  return BTN_NONE;
}

// OK: tekanan pendek -> BTN_OK (saat lepas), tekanan panjang -> BTN_BACK.
static nc_btn updateOk(btn_t& b, uint32_t now) {
  bool raw = (digitalRead(b.pin) == LOW);
  if (raw != b.lastRaw) { b.lastRaw = raw; b.tChange = now; }
  if ((now - b.tChange) >= DEBOUNCE_MS && raw != b.stable) {
    b.stable = raw;
    if (raw) { b.tDown = now; b.longFired = false; }       // mulai ditekan
    else if (!b.longFired) return BTN_OK;                  // lepas & belum long -> OK
  }
  if (b.stable && raw && !b.longFired && (now - b.tDown) >= LONGPRESS_MS) {
    b.longFired = true; return BTN_BACK;                   // tahan lama -> BACK
  }
  return BTN_NONE;
}

nc_btn buttons_poll() {
  uint32_t now = millis();
  nc_btn e;
  if ((e = updateOk(bOk, now))        != BTN_NONE) return e;
  if ((e = updateNav(bUp, BTN_UP, now))   != BTN_NONE) return e;
  if ((e = updateNav(bDown, BTN_DOWN, now)) != BTN_NONE) return e;
  return BTN_NONE;
}
