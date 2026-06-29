# nethercap — WiFi Security Research Toolkit (ESP8266)

Toolkit WiFi security berbasis **Wemos D1 Mini (ESP8266)** untuk penelitian, pembelajaran, dan testing keamanan jaringan di lingkungan lokal/lab. Bisa dioperasikan **sepenuhnya dari layar TFT + 3 tombol** (standalone, tanpa laptop) maupun lewat **CLI serial**.

Fitur: WiFi scanner & sniffer, count station, beacon spam, deauth monitor (defensif), deauth, precise deauth, dan evil twin dengan captive portal + verifikasi password + auto-deauth.

**Versi:** 0.2.0 · **Status:** 7 modul aktif & teruji, UI TFT (Phase 2) lengkap.

> ⚠️ **Untuk lab/testing lokal & edukasi saja.** Lihat [Catatan Legal](#catatan-legal--etis).

---

## Daftar Isi
- [Hardware & Wiring](#hardware--wiring)
- [Setup & Build](#setup--build)
- [Dua Cara Kontrol: TFT & CLI](#dua-cara-kontrol-tft--cli)
- [Fitur & Cara Pakai](#fitur--cara-pakai)
- [Evil Twin (detail)](#evil-twin-detail)
- [Arsitektur Kode](#arsitektur-kode)
- [SDK Patch (deauth)](#sdk-patch-deauth)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Catatan Legal & Etis](#catatan-legal--etis)

---

## Hardware & Wiring

| Komponen | Detail |
|---|---|
| **MCU** | Wemos D1 Mini (ESP8266, 4MB flash) |
| **Display** | TFT 240×280 **ST7789** (SPI, mis. IPS 1.69") |
| **Input** | 3 push button (UP / DOWN / OK) |
| **Power** | USB micro-B / power bank |

### TFT (hardware SPI)

| TFT | Wemos | GPIO | Keterangan |
|---|---|---|---|
| VCC | 3V3 | — | 3.3V |
| GND | GND | — | Ground |
| SCL/SCK | D5 | 14 | SPI Clock (HSPI) |
| SDA/MOSI | D7 | 13 | SPI MOSI (HSPI) |
| RES/RST | D0 | 16 | Reset |
| DC/A0 | D2 | 4 | Data/Command |
| CS | D8 | 15 | Chip Select |
| BLK/LED | 3V3 | — | Backlight (selalu nyala) |

### Tombol (kaki satunya ke GND, pakai internal pull-up)

| Tombol | Wemos | GPIO | Catatan |
|---|---|---|---|
| **UP** | D1 | 5 | bebas |
| **DOWN** | D4 | 2 | shared LED onboard (kedip dikit, harmless) |
| **OK** | D3 | 0 | **jangan ditahan saat power-on/reset** (masuk flash mode) |

> **OK tahan >0.6 detik = BACK** (karena cuma 3 tombol). GPIO12/D6 (MISO) **tidak bisa** dipakai tombol karena diklaim peripheral SPI saat TFT aktif.

---

## Setup & Build

Pakai **PlatformIO** (extension di VSCode). Library & toolchain auto-download saat build pertama.

```bash
# Izin serial (Linux/Zorin) — sekali saja
sudo usermod -aG dialout $USER          # lalu logout/login ulang
sudo apt remove brltty                  # fix bug CH340 "dibajak" brltty

# Build + upload + monitor
pio run -t upload && pio device monitor
```

> ⚠️ Saat upload, **jangan tahan tombol OK** (GPIO0 = flash mode).

Konfigurasi TFT & SDK-patch sudah disetel di [`platformio.ini`](platformio.ini) (build_flags TFT_eSPI + `extra_scripts = pre:patch_sdk.py`). Tidak perlu edit library.

---

## Dua Cara Kontrol: TFT & CLI

Keduanya jalan **paralel** dan mengontrol engine yang sama.

### TFT + tombol (standalone)
- **UP/DOWN** = navigasi · **OK** = pilih/aksi · **OK ditahan** = back/stop
- Boot → splash "Nethercap Baymax" → menu 8 fitur
- Fitur yang butuh target (count/deauth/precise/evil) → pilih AP dari layar scan → layar aksi live

### CLI serial (115200 baud)
Ketik `help` untuk daftar perintah:

| Perintah | Fungsi |
|---|---|
| `help` / `info` | bantuan / status perangkat |
| `scan` | scan AP aktif |
| `sniff` / `sniff stop` | promiscuous sniffer |
| `channel <1-13>` / `hop [on\|off]` | kontrol channel |
| `stats` | counter frame |
| `count` / `count stop` | count station (pilih AP) |
| `stations` / `stations clear` | dump semua AP→client |
| `beacon` | menu beacon spam |
| `dmon` / `dmon stop` / `dmon test` | deauth monitor |
| `deauth` / `deauth stop` | deauth broadcast (pilih AP) |
| `pdeauth` / `pdeauth stop` | precise deauth per-client |
| `evil` / `evil stop` | evil twin + portal |

---

## Fitur & Cara Pakai

### 1. Sniffer & Scanner
Fondasi semua modul. Promiscuous capture frame 802.11 + channel hopping.
- **TFT → Scan AP**: list AP (scroll, OK rescan).
- **TFT → Sniffer**: counter live (total/mgmt/data/deauth); UP/DN ganti channel, OK toggle hop.
- **CLI**: `scan`, `sniff`, `channel`, `hop`, `stats`.

### 2. Count Station
Hitung client yang terhubung ke 1 AP target.
- **Flow**: pilih AP → layar live **"N station"**.
- Channel dikunci ke AP target (akurat). MAC randomization bisa bikin angka over-estimate.
- **CLI**: `count` → pilih nomor → `count stop`.

### 3. Beacon Spam
Broadcast banyak SSID palsu (sweep ch 1-13).
- **TFT → Beacon Spam**: OK start/stop, UP +5 SSID acak, DN clear.
- **CLI**: `beacon` → menu (manual/acak/start).
- Pacing `delay(1)` per frame supaya buffer TX tidak penuh.

### 4. Deauth Monitor (defensif)
Deteksi serangan deauth/disassoc + alarm saat burst.
- **TFT → Deauth Monitor**: banner **AMAN/SERANGAN** + rate; OK = uji alarm (suntik sintetis).
- **CLI**: `dmon`, `dmon test`, `dmon stop`. Ambang default 8 frame/detik ([deauthmon.cpp](src/deauthmon.cpp) `DM_THRESHOLD`).

### 5. Deauth (broadcast)
Tendang semua client dari AP target.
- **Flow**: pilih AP → banner **MENGGEMPUR** + sukses/gagal live.
- Frame: mgmt subtype 12 + 10, addr1=broadcast, addr2/3=BSSID spoofed.
- **CLI**: `deauth` → pilih nomor → `deauth stop`.

### 6. Precise Deauth (per-client)
Deauth unicast 2-arah ke 1 client tertentu (lebih terarah).
- **Flow**: pilih AP → kumpulkan client live → pilih nomor client (atau **">> Semua client"**) → serang.
- **CLI**: `pdeauth` → pilih AP → ketik nomor client / `a` semua / `r` reset / `q`.

### 7. Evil Twin
Lihat bagian khusus di bawah.

> **Catatan**: deauth & precise-deauth bergantung pada [SDK patch](#sdk-patch-deauth). **WPA3/PMF (802.11w) kebal** terhadap deauth — itu fitur keamanan, bukan bug.

---

## Evil Twin (detail)

AP kembar (SSID identik, **terbuka**) + captive portal yang menangkap password Wi-Fi dan **memverifikasinya ke AP asli**.

### Flow
```
evil → pilih AP → twin nyala (Auto-deauth default OFF)
  → korban masuk twin → captive portal "Masuk ke Wi-Fi" (minta password)
     → SALAH : portal minta ulang
     → BENAR : halaman "menyelesaikan koneksi" (progress bar ~8s)
               → deauth auto-OFF → twin auto-bongkar (~9s)
               → korban auto-reconnect ke AP asli (mulus, tak curiga)
```

### Auto-deauth (toggle dengan OK di layar Evil Twin)
| | OFF (default) | ON |
|---|---|---|
| AP asli | tetap normal | digempur deauth terus |
| Korban masuk twin | sukarela (kepancing) | dipaksa pindah |
| Deteksi | senyap | terdeteksi `dmon` |
| Cocok | WiFi publik / device baru | maksa kick dari WiFi aktif |

### Teknis penting
- **Mode AP murni** saat portal (STA dimatikan) → DHCP stabil; STA hanya nyala sebentar saat verifikasi password.
- **MAC default ESP** (BSSID twin ≠ AP asli) → auto-deauth tak menendang client twin sendiri. *(Clone MAC custom dihindari karena bikin asosiasi/DHCP gagal di ESP8266.)*
- **Verifikasi real-time**: `WiFi.begin(ssid, pwd)` ke AP asli — connect = password benar.
- **Auto-teardown** saat password benar → jaringan kembali normal.

### Batasan
Device yang sudah **menyimpan AP asli sebagai WPA2** kadang menolak join twin terbuka (proteksi anti-downgrade OS). Evil twin paling ampuh untuk **WiFi publik/terbuka** atau device yang belum menyimpan network target.

---

## Arsitektur Kode

```
src/
  main.cpp        entry: init semua modul + loop
  cli.h/.cpp      control plane serial (command + mode input terpandu)
  buttons.h/.cpp  3 tombol (debounce + long-press = back)
  ui.h/.cpp       UI TFT (menu + layar tiap fitur)
  sniffer.h/.cpp  promiscuous engine (fondasi) + ring buffer + channel hop
  station.h/.cpp  count station
  beacon.h/.cpp   beacon spam
  deauthmon.h/.cpp deauth monitor (defensif)
  deauth.h/.cpp   deauth broadcast
  pdeauth.h/.cpp  precise deauth per-client
  evil.h/.cpp     evil twin + captive portal + auto-deauth
patch_sdk.py      pre-build: buka blokir injection deauth di SDK
platformio.ini    config board + TFT_eSPI + SDK patch hook
```

**Pola engine→handler**: modul analisis (station/dmon/pdeauth) memasang handler ke sniffer via `sniffer_add_handler()`. Modul attack & UI memanggil **API programatik** tiap modul (`*_attack`, `*_on`, `*_stats`) — jadi CLI dan TFT adalah dua "remote" ke engine yang sama tanpa duplikasi logika.

---

## SDK Patch (deauth)

Deauth/disassoc diblok di library ESP8266 (`ieee80211_freedom_output` cuma izinkan data/beacon/probe). [`patch_sdk.py`](patch_sdk.py) (pre-build, otomatis) mem-patch 1 instruksi di `libnet80211.a` semua versi NONOSDK agar **semua management frame** lolos:

- Idempotent + backup `.orig` otomatis · re-apply tiap build
- **Global** (`~/.platformio/...`) → mempengaruhi project ESP8266 lain di mesin ini
- **Revert**: hapus baris `extra_scripts` di `platformio.ini`, atau restore dari `libnet80211.a.orig` / reinstall platform

---

## Troubleshooting

**TFT (tweak di [platformio.ini](platformio.ini) / [ui.cpp](src/ui.cpp)):**
| Gejala | Fix |
|---|---|
| Blank/putih | cek wiring DC=D2, CS=D8, RST=D0, VCC=3V3 |
| Warna negatif | `-D TFT_INVERSION_OFF=1` |
| Merah↔Biru tertukar | `-D TFT_RGB_ORDER=TFT_BGR` |
| Gambar geser/kebalik | ubah `tft.setRotation(0)` (coba 2) di `ui_init()` |
| Tepi kepotong | naikkan `MX` (margin) di ui.cpp |

**Lain-lain:**
- `/dev/ttyUSB0: Permission denied` → group `dialout` belum aktif (re-login).
- Upload gagal 921600 → set `upload_speed = 115200`.
- Beacon/deauth `gagal` tinggi → pastikan SDK patch ke-apply (lihat log build `[nethercap] ... DIPATCH`).
- Sniffer `dropped` naik di area ramai → wajar (ring buffer 24, callback sengaja ringan). Kunci 1 channel untuk akurasi.
- Evil twin: HP gagal dapat IP → pastikan pakai versi terbaru (MAC clone sudah dibuang). Device yang simpan WPA2 asli → "forget" dulu untuk test.

---

## Roadmap

Belum dikerjakan (urut prioritas):
1. Credential logging persistent (SPIFFS) + halaman `/log`
2. Multi-SSID evil twin
3. OLED tambahan / indikator status
4. Settings persistent (LittleFS)
5. PCAP export (Wireshark), event logger
6. OUI lookup (vendor MAC), channel graph

---

## Catatan Legal & Etis

**Hanya untuk jaringan milik sendiri, lab terkontrol, atau pentest dengan izin tertulis.**

- ✅ **Sah**: test router sendiri, pembelajaran 802.11, CTF, red-team berizin.
- ❌ **Ilegal**: menyerang jaringan/orang tanpa otorisasi, mencuri kredensial, DoS layanan publik.

Beberapa fitur (deauth, evil twin, password capture) ilegal tanpa otorisasi. Gunakan dengan bertanggung jawab.

---

*nethercap — eksplorasi keamanan WiFi di ESP8266. Stay ethical, stay learning.* 🛡️
