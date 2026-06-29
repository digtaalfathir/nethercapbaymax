#include "ui.h"
#include "buttons.h"
#include "sniffer.h"
#include "beacon.h"
#include "deauthmon.h"
#include "station.h"
#include "deauth.h"
#include "pdeauth.h"
#include "evil.h"
#include <TFT_eSPI.h>
#include <ESP8266WiFi.h>

#ifndef NETHERCAP_VERSION
#define NETHERCAP_VERSION "dev"
#endif

static TFT_eSPI tft;

#define W 240
#define H 280
#define MX     12        // margin kiri/kanan (hindari sudut membulat panel)
#define HDR_H  32
#define FTR_H  22

// warna (di-set saat init)
static uint16_t COL_ACCENT, COL_HDR, COL_DIM, COL_ALARM, COL_OKBG;

// ------------------------------------------------------------- state -------
// tujuan layar SCAN: lihat-saja atau pilih target untuk fitur
enum Purpose { P_VIEW, P_COUNT, P_DEAUTH, P_PDEAUTH, P_EVIL };

enum Screen { SC_MENU, SC_SCAN, SC_SNIFF, SC_DMON, SC_BEACON,
              SC_COUNT, SC_DEAUTH, SC_PDCLI, SC_PDEAUTH, SC_EVIL };
static Screen   s_screen   = SC_MENU;
static int      s_sel      = 0;
static bool     s_dirty    = true;
static uint32_t s_lastRefresh = 0;
static Purpose  s_pick     = P_VIEW;

struct MenuItem { const char* name; Screen screen; Purpose purpose; };
static const MenuItem MENU[] = {
  { "Scan AP",        SC_SCAN,   P_VIEW    },
  { "Sniffer",        SC_SNIFF,  P_VIEW    },
  { "Deauth Monitor", SC_DMON,   P_VIEW    },
  { "Beacon Spam",    SC_BEACON, P_VIEW    },
  { "Count Station",  SC_SCAN,   P_COUNT   },
  { "Deauth",         SC_SCAN,   P_DEAUTH  },
  { "Precise Deauth", SC_SCAN,   P_PDEAUTH },
  { "Evil Twin",      SC_SCAN,   P_EVIL    },
};
static const int MENU_N = sizeof(MENU) / sizeof(MENU[0]);

// hasil scan lokal
struct ap_t { char ssid[33]; uint8_t bssid[6]; uint8_t ch; int8_t rssi; };
static ap_t s_aps[16];
static int  s_apN = 0, s_apSel = 0, s_apTop = 0;

// client picker (precise deauth): index 0 = "semua", 1..N = client
static int  s_pdSel = 0, s_pdTop = 0;
static char s_pdLabel[20] = {0};

// target yang sedang diserang (untuk tampilan layar aktif)
static uint8_t s_tCh = 0;
static char    s_tSsid[20] = {0};

// ----------------------------------------------------------- helpers -------
static void header(const char* title) {
  tft.fillRect(0, 0, W, HDR_H, COL_HDR);
  tft.setTextFont(4); tft.setTextColor(TFT_WHITE, COL_HDR);
  tft.setTextDatum(MC_DATUM); tft.drawString(title, W / 2, HDR_H / 2);
  tft.setTextDatum(TL_DATUM);
}

static void footer(const char* hint) {
  tft.fillRect(0, H - FTR_H, W, FTR_H, TFT_BLACK);
  tft.setTextFont(1); tft.setTextColor(COL_DIM, TFT_BLACK);
  tft.setTextDatum(MC_DATUM); tft.drawString(hint, W / 2, H - 11);
  tft.setTextDatum(TL_DATUM);
}

static void clearBody() { tft.fillRect(0, HDR_H, W, H - HDR_H - FTR_H, TFT_BLACK); }

static void row(int y, const char* label, const String& val) {
  tft.setTextFont(2);
  tft.setTextColor(COL_DIM, TFT_BLACK);  tft.setCursor(MX + 2, y); tft.print(label);
  tft.setTextColor(TFT_WHITE, TFT_BLACK); tft.setCursor(124, y);   tft.print(val);
}

static String shortStr(const char* s, int n) {
  String r(s);
  if ((int)r.length() > n) r = r.substring(0, n - 1) + "~";
  return r;
}

// banner berwarna + teks (untuk layar aktif)
static void banner(uint16_t bg, const char* txt) {
  tft.fillRoundRect(MX, HDR_H + 8, W - 2 * MX, 40, 6, bg);
  tft.setTextFont(4); tft.setTextColor(TFT_WHITE, bg);
  tft.setTextDatum(MC_DATUM); tft.drawString(txt, W / 2, HDR_H + 28);
  tft.setTextDatum(TL_DATUM);
}

// ----------------------------------------------------------- screens -------
static void drawMenu() {
  tft.fillScreen(TFT_BLACK);
  header("Nethercap");
  tft.setTextFont(2);
  int y0 = HDR_H + 8;
  for (int i = 0; i < MENU_N; i++) {
    int y = y0 + i * 26;
    if (i == s_sel) {
      tft.fillRoundRect(MX, y, W - 2 * MX, 22, 4, COL_ACCENT);
      tft.setTextColor(TFT_WHITE, COL_ACCENT);
    } else {
      tft.setTextColor(0xCE59, TFT_BLACK);
    }
    tft.setCursor(MX + 8, y + 4);
    tft.print(MENU[i].name);
  }
  footer("UP/DN pilih   OK masuk");
}

static void doScan() {
  tft.fillScreen(TFT_BLACK); header("Scan AP");
  tft.setTextFont(2); tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setCursor(MX + 2, 60); tft.print("Memindai...");
  WiFi.mode(WIFI_STA);
  int n = WiFi.scanNetworks(false, true);
  s_apN = 0;
  for (int i = 0; i < n && s_apN < 16; i++) {
    String ss = WiFi.SSID(i);
    strncpy(s_aps[s_apN].ssid, ss.length() ? ss.c_str() : "<hidden>", 32);
    s_aps[s_apN].ssid[32] = 0;
    memcpy(s_aps[s_apN].bssid, WiFi.BSSID(i), 6);
    s_aps[s_apN].ch   = (uint8_t)WiFi.channel(i);
    s_aps[s_apN].rssi = (int8_t)WiFi.RSSI(i);
    s_apN++;
  }
  WiFi.scanDelete();
  s_apSel = 0; s_apTop = 0;
}

static void drawScan() {
  tft.fillScreen(TFT_BLACK);
  header(s_pick == P_VIEW ? "Scan AP" : "Pilih AP");
  tft.setTextFont(2);
  const int VIS = 7;
  if (s_apN == 0) {
    tft.setTextColor(COL_DIM, TFT_BLACK); tft.setCursor(MX + 2, 60); tft.print("(tidak ada AP)");
  }
  for (int i = 0; i < VIS && (s_apTop + i) < s_apN; i++) {
    int idx = s_apTop + i; int y = HDR_H + 6 + i * 27;
    if (idx == s_apSel) { tft.fillRoundRect(MX, y - 2, W - 2 * MX, 25, 4, COL_ACCENT); tft.setTextColor(TFT_WHITE, COL_ACCENT); }
    else                { tft.setTextColor(0xCE59, TFT_BLACK); }
    tft.setCursor(MX + 6, y + 3);
    char line[44];
    snprintf(line, sizeof(line), "%-12s c%-2d %d", s_aps[idx].ssid, s_aps[idx].ch, s_aps[idx].rssi);
    tft.print(line);
  }
  footer(s_pick == P_VIEW ? "OK rescan   tahan=back" : "OK pilih   tahan=back");
}

static void drawSniff(bool full) {
  if (full) { tft.fillScreen(TFT_BLACK); header("Sniffer"); footer("UP/DN ch  OK hop  tahan=back"); }
  clearBody();
  uint32_t total, mgmt, data, deauth;
  sniffer_get_counts(&total, &mgmt, &data, &deauth);
  int y = HDR_H + 10;
  String ch = String(sniffer_channel()) + (sniffer_get_hop() ? "  (hop)" : "  (lock)");
  row(y, "Channel", ch);            y += 30;
  row(y, "Total",   String(total)); y += 26;
  row(y, "Mgmt",    String(mgmt));  y += 26;
  row(y, "Data",    String(data));  y += 26;
  row(y, "Deauth",  String(deauth));
}

static void drawDmon(bool full) {
  if (full) { tft.fillScreen(TFT_BLACK); header("Deauth Monitor"); footer("OK uji alarm  tahan=back"); }
  clearBody();
  uint32_t total, rate; bool alarm;
  deauthmon_get(&total, &rate, &alarm);
  // banner status
  uint16_t bg = alarm ? COL_ALARM : COL_OKBG;
  tft.fillRoundRect(MX, HDR_H + 8, W - 2 * MX, 44, 6, bg);
  tft.setTextFont(4); tft.setTextColor(TFT_WHITE, bg);
  tft.setCursor(20, HDR_H + 18);
  tft.print(alarm ? "! SERANGAN" : "AMAN");
  int y = HDR_H + 66;
  row(y, "Rate/dtk", String(rate)); y += 28;
  row(y, "Total",    String(total));
}

static void drawBeacon(bool full) {
  if (full) { tft.fillScreen(TFT_BLACK); header("Beacon Spam"); footer("OK start/stop  UP+5 DN clr"); }
  clearBody();
  bool run = beacon_running();
  uint16_t bg = run ? COL_OKBG : COL_HDR;
  tft.fillRoundRect(MX, HDR_H + 8, W - 2 * MX, 44, 6, bg);
  tft.setTextFont(4); tft.setTextColor(TFT_WHITE, bg);
  tft.setCursor(20, HDR_H + 18);
  tft.print(run ? "RUNNING" : "STOP");
  int y = HDR_H + 66;
  row(y, "SSID", String(beacon_count()));
}

static void drawCount(bool full) {
  if (full) { tft.fillScreen(TFT_BLACK); header("Count Station"); footer("tahan OK = kembali"); }
  clearBody();
  row(HDR_H + 10, "AP",      shortStr(s_tSsid, 12));
  row(HDR_H + 36, "Channel", String(s_tCh));
  tft.setTextFont(4); tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.drawString(String(station_count_clients()) + " station", W / 2, HDR_H + 96);
  tft.setTextDatum(TL_DATUM);
}

static void drawDeauth(bool full) {
  if (full) { tft.fillScreen(TFT_BLACK); header("Deauth"); footer("tahan OK = kembali"); }
  clearBody();
  banner(COL_ALARM, "MENGGEMPUR");
  uint32_t sent = 0, fail = 0; deauth_stats(&sent, &fail);
  row(HDR_H + 60,  "AP",     shortStr(s_tSsid, 12));
  row(HDR_H + 86,  "Sukses", String(sent));
  row(HDR_H + 112, "Gagal",  String(fail));
}

static void drawPdClients(bool full) {
  if (full) { tft.fillScreen(TFT_BLACK); header("Pilih Client"); footer("OK serang  tahan=back"); }
  clearBody();
  int n = pdeauth_client_count();
  int total = n + 1;                          // index 0 = semua
  if (s_pdSel >= total) s_pdSel = total - 1;
  if (s_pdSel < s_pdTop) s_pdTop = s_pdSel;
  if (s_pdSel >= s_pdTop + 7) s_pdTop = s_pdSel - 6;
  tft.setTextFont(2);
  for (int i = 0; i < 7 && (s_pdTop + i) < total; i++) {
    int idx = s_pdTop + i; int y = HDR_H + 6 + i * 27;
    if (idx == s_pdSel) { tft.fillRoundRect(MX, y - 2, W - 2 * MX, 25, 4, COL_ACCENT); tft.setTextColor(TFT_WHITE, COL_ACCENT); }
    else                { tft.setTextColor(0xCE59, TFT_BLACK); }
    tft.setCursor(MX + 6, y + 3);
    if (idx == 0) tft.print(">> Semua client");
    else { char l[40]; snprintf(l, sizeof(l), "%s %d", pdeauth_client_mac(idx - 1), pdeauth_client_rssi(idx - 1)); tft.print(l); }
  }
  if (n == 0) { tft.setTextColor(COL_DIM, TFT_BLACK); tft.setCursor(MX + 2, HDR_H + 6 + 27); tft.print("(menunggu client...)"); }
}

static void drawPdeauth(bool full) {
  if (full) { tft.fillScreen(TFT_BLACK); header("Precise Deauth"); footer("tahan OK = kembali"); }
  clearBody();
  banner(COL_ALARM, "MENGGEMPUR");
  uint32_t sent = 0, fail = 0; pdeauth_stats(&sent, &fail);
  row(HDR_H + 60,  "Target", String(s_pdLabel));
  row(HDR_H + 86,  "Sukses", String(sent));
  row(HDR_H + 112, "Gagal",  String(fail));
}

static void drawEvil(bool full) {
  if (full) { tft.fillScreen(TFT_BLACK); header("Evil Twin"); footer("OK deauth on/off  tahan=back"); }
  clearBody();
  bool got = evil_got_password();
  banner(got ? COL_OKBG : COL_HDR, got ? "PASSWORD!" : "MENUNGGU");
  row(HDR_H + 58, "Twin",    shortStr(evil_ssid(), 12));
  row(HDR_H + 82, "Client",  String(evil_clients()));
  row(HDR_H + 106, "Auto-DA", evil_deauth_on() ? ("ON " + String(evil_deauth_count())) : String("OFF"));
  if (got) {
    tft.setTextFont(2); tft.setTextColor(COL_DIM, TFT_BLACK); tft.setCursor(MX + 2, HDR_H + 134); tft.print("Password:");
    tft.setTextColor(TFT_WHITE, TFT_BLACK); tft.setCursor(MX + 2, HDR_H + 154); tft.print(evil_password());
  }
}

// ---------------------------------------------------------- navigation ----
static void enterScreen(Screen sc) {
  s_screen = sc;
  s_dirty  = true;
  switch (sc) {
    case SC_SCAN:   doScan(); break;
    case SC_SNIFF:  sniffer_set_hop(true); sniffer_set_verbose(false);
                    if (!sniffer_running()) sniffer_start(); break;
    case SC_DMON:   deauthmon_start(); break;
    case SC_PDCLI:  s_pdSel = 0; s_pdTop = 0; break;
    default: break;
  }
}

static void exitToMenu() {
  switch (s_screen) {
    case SC_SNIFF:   sniffer_stop();      break;
    case SC_DMON:    deauthmon_stop();    break;
    case SC_BEACON:  beacon_stop();       break;
    case SC_COUNT:   station_count_stop();break;
    case SC_DEAUTH:  deauth_stop();       break;
    case SC_PDCLI:
    case SC_PDEAUTH: pdeauth_stop();      break;
    case SC_EVIL:    evil_stop();         break;
    default: break;
  }
  s_screen = SC_MENU;
  s_dirty  = true;
}

// luncurkan fitur untuk AP yang dipilih di layar scan
static void launchSelected() {
  if (s_apN == 0) return;
  ap_t& a = s_aps[s_apSel];
  s_tCh = a.ch;
  strncpy(s_tSsid, a.ssid, sizeof(s_tSsid)); s_tSsid[sizeof(s_tSsid) - 1] = 0;
  switch (s_pick) {
    case P_COUNT:   station_count_on(a.bssid, a.ch, a.ssid);  enterScreen(SC_COUNT);  break;
    case P_DEAUTH:  deauth_attack(a.bssid, a.ch, a.ssid);     enterScreen(SC_DEAUTH); break;
    case P_PDEAUTH: pdeauth_collect_on(a.bssid, a.ch, a.ssid); enterScreen(SC_PDCLI); break;
    case P_EVIL:    evil_attack(a.bssid, a.ch, a.ssid);       enterScreen(SC_EVIL);   break;
    default: break;
  }
}

static void handleButton(nc_btn ev) {
  switch (s_screen) {
    case SC_MENU:
      if (ev == BTN_UP)   { s_sel = (s_sel - 1 + MENU_N) % MENU_N; s_dirty = true; }
      if (ev == BTN_DOWN) { s_sel = (s_sel + 1) % MENU_N;         s_dirty = true; }
      if (ev == BTN_OK)   { s_pick = MENU[s_sel].purpose; enterScreen(MENU[s_sel].screen); }
      break;

    case SC_SCAN:
      if (ev == BTN_UP   && s_apSel > 0)        { s_apSel--; if (s_apSel < s_apTop) s_apTop = s_apSel; s_dirty = true; }
      if (ev == BTN_DOWN && s_apSel < s_apN - 1){ s_apSel++; if (s_apSel >= s_apTop + 7) s_apTop = s_apSel - 6; s_dirty = true; }
      if (ev == BTN_OK)   { if (s_pick == P_VIEW) { doScan(); s_dirty = true; } else launchSelected(); }
      if (ev == BTN_BACK) exitToMenu();
      break;

    case SC_SNIFF:
      if (ev == BTN_UP)   { sniffer_set_hop(false); sniffer_set_channel((sniffer_channel() % 13) + 1); s_dirty = true; }
      if (ev == BTN_DOWN) { sniffer_set_hop(false); sniffer_set_channel(sniffer_channel() <= 1 ? 13 : sniffer_channel() - 1); s_dirty = true; }
      if (ev == BTN_OK)   { sniffer_set_hop(!sniffer_get_hop()); s_dirty = true; }
      if (ev == BTN_BACK) exitToMenu();
      break;

    case SC_DMON:
      if (ev == BTN_OK)   deauthmon_test();
      if (ev == BTN_BACK) exitToMenu();
      break;

    case SC_BEACON:
      if (ev == BTN_OK)   { if (beacon_running()) beacon_stop(); else { if (beacon_count() == 0) beacon_add_random(5); beacon_start(); } s_dirty = true; }
      if (ev == BTN_UP)   { beacon_add_random(5); s_dirty = true; }
      if (ev == BTN_DOWN) { beacon_stop(); beacon_clear(); s_dirty = true; }
      if (ev == BTN_BACK) exitToMenu();
      break;

    case SC_PDCLI: {
      int total = pdeauth_client_count() + 1;
      if (ev == BTN_UP   && s_pdSel > 0)         { s_pdSel--; s_dirty = true; }
      if (ev == BTN_DOWN && s_pdSel < total - 1) { s_pdSel++; s_dirty = true; }
      if (ev == BTN_OK) {
        bool go = true;
        if (s_pdSel == 0) {
          if (pdeauth_client_count() == 0) go = false;     // belum ada client
          else { pdeauth_attack_all(); strncpy(s_pdLabel, "semua", sizeof(s_pdLabel)); }
        } else {
          int ci = s_pdSel - 1;
          strncpy(s_pdLabel, pdeauth_client_mac(ci), sizeof(s_pdLabel)); s_pdLabel[sizeof(s_pdLabel)-1]=0;
          pdeauth_attack_index(ci);
        }
        if (go) enterScreen(SC_PDEAUTH);
      }
      if (ev == BTN_BACK) exitToMenu();
      break;
    }

    case SC_EVIL:
      if (ev == BTN_OK)   { evil_toggle_deauth(); s_dirty = true; }
      if (ev == BTN_BACK) exitToMenu();
      break;

    case SC_COUNT:
    case SC_DEAUTH:
    case SC_PDEAUTH:
      if (ev == BTN_BACK) exitToMenu();
      break;
  }
}

static void drawScreen(bool full) {
  switch (s_screen) {
    case SC_MENU:    drawMenu();         break;
    case SC_SCAN:    drawScan();         break;
    case SC_SNIFF:   drawSniff(full);    break;
    case SC_DMON:    drawDmon(full);     break;
    case SC_BEACON:  drawBeacon(full);   break;
    case SC_COUNT:   drawCount(full);    break;
    case SC_DEAUTH:  drawDeauth(full);   break;
    case SC_PDCLI:   drawPdClients(full);break;
    case SC_PDEAUTH: drawPdeauth(full);  break;
    case SC_EVIL:    drawEvil(full);     break;
  }
}

// --------------------------------------------------------------- api -------
void ui_init() {
  buttons_init();
  tft.init();
  tft.setRotation(0);                 // potret 240x280
  COL_ACCENT = tft.color565(24, 110, 210);
  COL_HDR    = tft.color565(12, 32, 60);
  COL_DIM    = tft.color565(150, 155, 165);
  COL_ALARM  = tft.color565(200, 40, 40);
  COL_OKBG   = tft.color565(20, 120, 70);

  // splash (di-center)
  tft.fillScreen(TFT_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.setTextFont(4); tft.setTextColor(COL_ACCENT, TFT_BLACK);
  tft.drawString("Nethercap", W / 2, 116);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.drawString("Baymax", W / 2, 150);
  tft.setTextFont(2); tft.setTextColor(COL_DIM, TFT_BLACK);
  tft.drawString("v" NETHERCAP_VERSION, W / 2, 182);
  tft.setTextDatum(TL_DATUM);
  delay(1400);

  s_screen = SC_MENU; s_dirty = true;
}

void ui_loop() {
  nc_btn ev = buttons_poll();
  if (ev != BTN_NONE) handleButton(ev);

  uint32_t now = millis();
  bool live = (s_screen != SC_MENU && s_screen != SC_SCAN);
  if (s_dirty) {
    drawScreen(true);
    s_dirty = false;
    s_lastRefresh = now;
  } else if (live && (now - s_lastRefresh) >= 600) {
    drawScreen(false);
    s_lastRefresh = now;
  }
}
