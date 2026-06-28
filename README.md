# nethercap — WiFi Security Research Toolkit untuk ESP8266

Toolkit WiFi security berbasis ESP8266 Wemos D1 Mini untuk penelitian, pembelajaran, dan testing keamanan jaringan di lingkungan lokal/lab. Implementasi dari berbagai teknik WiFi yang sering dibahas di komunitas security: beacon spam, station counting, deauth detection, deauth injection, precise deauth, dan evil twin dengan credential capture.

**Status**: Semua modul (7) aktif dan teruji. Dokumentasi & roadmap selesai. Siap untuk eksplorasi & customization.

---

## Hardware Requirements

- **Microcontroller**: Wemos D1 Mini (ESP8266) — board populer, murah, banyak referensi
  - Alternatif: ESP8266 DevKit V1, atau ESP8266 lainnya yang compatible Arduino
- **Power**: USB micro-B atau power bank (0.5A cukup)
- **Serial adapter**: CH340 (included di Wemos D1 Mini)
- **Opsional**: OLED display (SSD1306) untuk tampilan real-time; SD card untuk log capture (PCAP, credentials)

### Setup Pertama Kali (Linux/Zorin)

```bash
# 1. Install driver CH340 & izin serial
sudo apt install -y git python3-venv python3-pip
sudo usermod -aG dialout $USER
# Logout & login ulang agar group aktif

# 2. Clone & masuk folder project
git clone https://github.com/yourusername/nethercap.git
cd nethercap

# 3. PlatformIO akan auto-download framework & tools saat build pertama
# Jika belum install PlatformIO IDE extension di VSCode: buka Extensions, cari "PlatformIO IDE", install

# 4. Build & flash
pio run -t upload && pio device monitor
# Monitor dibuka otomatis, lihat boot message & prompt ">"
```

**Troubleshooting setup:**
- `/dev/ttyUSB0: Permission denied` → pastikan `dialout` group active (`groups` di terminal)
- `board not found` → pastikan Wemos colok, cek `ls /dev/ttyUSB*`
- Upload gagal timeout → ubah `upload_speed` di `platformio.ini` dari 921600 → 115200

---

## Fitur & Modul

### 1. WiFi Scanner & Sniffer Engine
**Command**: `scan`, `sniff`, `channel`, `hop`, `stats`

Fondasi semua modul detection & attack. Capture frame 802.11 mentah, parse header, channel hopping.

```
> scan                              # scan AP aktif (STA mode)
> sniff                             # mulai promiscuous sniffer
> channel 11                        # kunci channel 11 (hop off)
> hop on                            # balik ke channel hopping 1-13
> stats                             # lihat counter frame per tipe
> sniff stop                        # berhenti sniffer
```

**Cara kerja**: engine menjalankan callback promiscuous & kumpulkan frame di ring buffer, cetak per-frame + stats periodik. Verbose-nya bisa off biar display bersih saat collect data (diatur otomatis modul lain).

---

### 2. Count Station (Terpandu)
**Command**: `count`

Kumpulkan daftar AP + client-nya. Flow: scan AP → pilih nomor → device kunci channel & collect client real-time.

```
> count
=== pilih AP untuk Count Station ===
  0) ch11  -45dBm  6C:A5:D1:32:9E:A0  Stechoq Robotika Indonesia
  1) ch11  -76dBm  FC:A6:CD:83:8A:30  SUADAYA
ketik nomor AP (atau 'q' batal):
count AP#> 0
[count] Stechoq... ch11 : 2 station
   1) A4:83:E7:11:22:33  -55dBm  pkts=210  age=0s
   2) 3C:5A:B4:44:55:66  -61dBm  pkts=18   age=2s
```

**Catatan**: MAC randomization di HP modern bikin count bisa over-estimate. Saat client benar asosiasi, MAC stabil muncul di bawah AP-nya. `count stop` untuk berhenti.

---

### 3. Beacon Spam
**Command**: `beacon`

Broadcast beacon frame dengan SSID palsu (manual atau random). Muncul di list WiFi device sekitar.

```
> beacon
=== BEACON SPAM === (0 SSID, stop)
  1) tambah SSID manual
  2) generate acak
  3) lihat daftar
  4) hapus semua
  5) START spam
  6) STOP spam
pilih (1-6, 'q' keluar):
beacon> 2
berapa SSID acak? (1-32):
jumlah> 15
  + 15 SSID acak (total 15)

beacon> 5
[beacon] START — 15 SSID di-broadcast (sweep ch1-13). Cari ini di scan:
   * aXk9Qm              02:1A:3F:8C:DD:01
   * ...
[beacon] STOP — sukses 5430, gagal 0
```

**Fitur**: sweep channel 1-13 otomatis; pacing `delay(1)` antar-frame biar buffer TX tidak penuh. BSSID di-generate random (locally administered). Kalau semua gagal → pastikan promiscuous enable (sniffer harus jalan atau manual enable di kode).

---

### 4. Deauth Monitor (Deteksi/Defensif)
**Command**: `dmon`

Monitor frame deauth & disassoc, hitung rate, alarm saat burst (ciri serangan deauth flood). Sisi penanganan — identifikasi serangan & sumber-nya.

```
> dmon
[dmon] MONITOR aktif — ambah 8 deauth/detik, hop on.
       'dmon stop' berhenti | 'dmon test' uji alarm
[dmon] clear — tidak ada deauth/disassoc

# 1 detik kemudian, rate naik
[dmon] 3 deauth/disassoc per detik (di bawah ambang)

# Saat > ambang
*** ALARM DEAUTH *** 30 frame/detik (ambang 8) — kemungkinan serangan!
  sumber terdeteksi (1):
   - src DE:AD:BE:EF:13:37  bssid 6C:A5:D1:32:9E:A0  count=30  ch6  -42dBm  age=0s
```

**Test alarm**: `dmon test` suntik 30 frame sintetis tanpa penyerang nyata (verifikasi logika jalan). Threshold bisa di-tune di `DM_THRESHOLD` ([deauthmon.cpp:21](src/deauthmon.cpp#L21)).

---

### 5. Deauth (Broadcast)
**Command**: `deauth`

Inject frame deauth broadcast ke AP target (semua client sekaligus). Alasan (2) disassoc.

```
> deauth
[deauth] memindai AP...
=== pilih AP untuk DEAUTH ===
  0) ch11  -49dBm  6C:A5:D1:32:9E:A0  Stechoq Robotika Indonesia
ketik nomor AP (atau 'q' batal):
deauth AP#> 0
[deauth] TARGET Stechoq... ch11 : sukses=4120 gagal=0
# ... tiap 2 detik
[deauth] TARGET ... ch11 : sukses=8540 gagal=0
deauth stop
[deauth] STOP — sukses=8540 gagal=0
```

**Catatan**: WPA3/PMF (802.11w) **kebal** — frame deauth unauthenticated ditolak. HP modern + router serius sudah PMF enable. Broadcast deauth efektif pada setup lama atau device yang abaikan broadcast.

> **SDK Patch**: deauth diblok di `wifi_send_pkt_freedom` level library SDK (whitelist subtype). Project ini include pre-build script `patch_sdk.py` yang membuka blok itu (1 instruksi di libnet80211.a). Patch idempotent & global (~/.platformio) — revert dengan delete script atau reinstall platform.

---

### 6. Precise Deauth (Per-Client)
**Command**: `pdeauth`

Deauth **unicast** ke 1 client spesifik (2 arah: AP→client + client→AP). Lebih efektif & targeted dari broadcast.

```
> pdeauth
[pdeauth] memindai AP...
=== pilih AP untuk PRECISE DEAUTH ===
  0) ch11  -55dBm  6C:A5:D1:32:9E:A0  Stechoq Robotika Indonesia
ketik nomor AP (atau 'q' batal):
pdeauth AP#> 0
[pdeauth] AP Stechoq... ch11 — mengumpulkan client...
[pdeauth] client AP 6C:A5:D1:32:9E:A0 ch11 — 2 terlihat:
   0) A4:83:E7:11:22:33  -55dBm  pkts=84  age=0s
   1) 3C:5A:B4:44:55:66  -61dBm  pkts=12  age=1s
   nomor=deauth client itu | 'a'=semua | 'r'=reset | 'q'=batal
client#> 0
[pdeauth] DEAUTH client A4:83:E7:11:22:33 di AP 6C:A5:D1:32:9E:A0 ch11
[pdeauth] -> A4:83:E7:11:22:33 : sukses=3120 gagal=210
pdeauth stop
[pdeauth] STOP — sukses=3120 gagal=210
```

**Flow**: fase collect (sniffer locked ch, handler rekam hanya client AP target) → user pilih nomor client (atau `a`=semua) → fase attack (unicast 2-arah, paced).

---

### 7. Evil Twin + Captive Portal
**Command**: `evil`

AP rogue yang clone SSID + BSSID asli, open network (tanpa password). Saat client masuk, serve captive portal → minta re-enter password → **verifikasi password ke AP asli (STA)** → tangkap jika benar, atau minta ulang jika salah.

```
> evil
[evil] memindai AP...
=== pilih AP untuk EVIL TWIN ===
  0) ch11  -55dBm  6C:A5:D1:32:9E:A0  Stechoq Robotika Indonesia
ketik nomor AP (atau 'q' batal):
evil AP#> 0
[evil] AKTIF — twin 'Stechoq...' ch11, BSSID 6C:A5:D1:32:9E:A0
       portal di http://192.168.4.1/  — tunggu korban masuk. 'evil stop' utk berhenti

# Korban nyambung & isi password
[evil] >>> PASSWORD DICOBA: "password123"  (dari 192.168.1.50)
[evil] password SALAH: "password123" — portal minta ulang
[evil] 'Stechoq...' ch11 | client tersambung: 1

# Korban ulang & benar kali ini
[evil] >>> PASSWORD DICOBA: "benarnyapassword"  (dari 192.168.1.50)

[evil] ====================================
[evil]  PASSWORD BENAR: "benarnyapassword"
[evil]  SSID: Stechoq Robotika Indonesia
[evil] ====================================
[evil] 'Stechoq...' ch11 | client tersambung: 1 | PASSWORD TERTANGKAP
```

**Teknis**:
- **WiFi mode AP+STA**: AP jadi twin, STA untuk verifikasi password ke AP asli
- **BSSID clone**: `wifi_set_macaddr(SOFTAP_IF, bssid)` (best-effort, beberapa chip ignore)
- **Captive portal**: DNS spoofing (catch-all) + web server HTTP di 192.168.4.1
- **Verifikasi real-time**: `WiFi.begin(ssid, pwd)` non-blocking, lihat koneksi sukses/timeout → tentukan password benar/salah
- **UI**: HTML profesional (Bahasa Indonesia), form password, feedback error

**Improvement untuk v2** (roadmap):
- Auto-deauth AP asli saat twin aktif (paksa client switch)
- Simpan credentials ke SPIFFS (persistent logging)
- Web log page (`/log`) untuk lihat captured passwords

---

## Command Summary

| Command | Fungsi |
|---|---|
| `help` | Daftar semua perintah |
| `info` | Info chip (ID, flash, free RAM, status sniffer) |
| `scan` | Scan AP aktif (STA mode) |
| `sniff` | Mulai/stop promiscuous sniffer |
| `channel <1-13>` | Kunci channel tetap (hop off) |
| `hop [on\|off]` | Toggle channel hopping |
| `stats` | Cetak counter frame per tipe |
| `count` | Count station terpandu (pilih AP → collect client live) |
| `stations` | Dump semua AP→client (mode bebas) |
| `beacon` | Menu beacon spam (manual/acak/start) |
| `dmon` | Deauth monitor (alert saat burst) |
| `deauth` | Deauth broadcast (pilih AP → gempur) |
| `pdeauth` | Precise deauth per-client (pilih AP → client → attack) |
| `evil` | Evil twin + portal (clone AP → capture password) |

---

## Catatan Teknis & Troubleshooting

### SDK Patch Deauth
Deauth/disassoc diblok di level library ESP8266 (`ieee80211_freedom_output`). Project include `patch_sdk.py` yang:
1. Backup original `libnet80211.a` → `libnet80211.a.orig`
2. Patch 1 instruksi (Xtensa assembly) di semua NONOSDK versi
3. Jalankan otomatis saat build (`extra_scripts` di platformio.ini)
4. Idempotent — aman di-run berkali-kali

Jika mau revert: hapus `extra_scripts` line di platformio.ini, atau `cp ~/.platformio/packages/.../libnet80211.a.orig ~/.platformio/packages/.../libnet80211.a`.

### Frame Capture Rate & Dropping
Ring buffer sniffer ukuran 24 frame — saat traffic padat, frame bisa di-drop (print "dropped" di stats). Ini **trade-off**: callback ringan (jaga responsivitas) vs buffer penuh → frame hilang. Kalau butuh capture 100%, bisa naikkan `RING_SZ` di [sniffer.cpp:28](src/sniffer.cpp#L28) (tapi naikin RAM usage).

### Channel Hopping vs Accuracy
Hop on (default) = sweep ch1-13 @300ms per channel. Client di channel lain bisa kelewat saat lagi hop. Untuk **akurat 1 AP**: `channel 11` (kunci, hop off). Trade-off coverage vs precision.

### MAC Randomization
HP modern pakai MAC random saat probe-req & sebelum asosiasi penuh. Jadi daftar client bisa "membengkak" dengan MAC-MAC berbeda dari device yang sama. Saat benar asosiasi, MAC stabil → muncul di tabel dengan benar.

### Threshold Deauth Monitor
Default `DM_THRESHOLD = 8` frame/detik (2 frame deauth + 2 disassoc per client, 2 client = 8). Kalau banyak false alarm di area ramai, naikkan threshold di [deauthmon.cpp:21](src/deauthmon.cpp#L21).

### Encryption & Payload
Sniffer hanya baca **header + metadata** frame (MAC, channel, RSSI, tipe). **Payload frame data encrypted** (WPA2/WPA3) **tidak decryptable tanpa handshake + PSK** — ini by design WiFi. Evil twin bisa tangkap *password teks*, bukan payload.

---

## Performance & Resource

**RAM**: ~50% terpakai saat all modules loaded
```
sniffer engine     ~10KB
count station      ~2KB  (tabel 24AP + 64 client)
deauth monitor     ~1KB  (tabel 16 sumber)
precise deauth     ~2KB  (tabel 24AP + 32 client)
beacon spam        ~1KB  (list 32 SSID)
evil twin          ~8KB  (web server + DNS)
sisa buffer        ~41KB
```

**Flash**: ~31% (dengan evil twin web server)
```
framework     ~200KB
core libs     ~80KB
project code  ~47KB
```

**Rate promiscuous**: ~100-200 frame/s normal area; padat -> ring drop.

---

## Learning Resources & Next Steps

### Dokumentasi Internal
- [sniffer.cpp](src/sniffer.cpp) — promiscuous callback, ring buffer, channel hopping
- [station.cpp](src/station.cpp) — table AS, To-DS/From-DS parsing
- [beacon.cpp](src/beacon.cpp) — beacon frame building, `wifi_send_pkt_freedom`
- [deauthmon.cpp](src/deauthmon.cpp) — frame filtering, rate window, alarm threshold
- [evil.cpp](src/evil.cpp) — web server, DNS spoof, STA verifikasi

### Ide Customization
1. **OLED display** — real-time stats (top 5 AP, live rate, etc)
2. **SD card logging** — PCAP export (`libpcap` format), credential persist
3. **Web UI** — replace CLI dengan web dashboard, live graph
4. **BLE sniffer** — tangkap advertising BLE (sama modul)
5. **WiFi 6 (802.11ax)** — ESP32-C6 support (next gen)
6. **Evil twin improvement** — auto-deauth AP asli, fake portal phishing, email exfil

### Reference Terbuka
- **esp8266_deauther** (Spacehuhn) — OG deauther, code clean untuk beacon/deauth
- **WiFi security research** — lihat IEEE 802.11 spec (frame format, reason codes)
- **Xtensa assembly** — untuk custom SDK patch

---

## Catatan Legal & Etis

**Project ini untuk lab/testing lokal saja.** Beberapa teknik (deauth, evil twin, password capture) **illegal tanpa otorisasi**:

- ✅ **Aman**: testing di jaringan milikmu sendiri, environment lab terkontrol, penelitian educational
- ❌ **Ilegal**: attack jaringan orang lain, target tanpa izin, pengguna tanpa notifikasi

Use case sah:
- Test keamanan router milikmu
- Pembelajaran tentang 802.11
- Penetration testing dengan approval written dari client
- CTF/security competition
- Red team exercise di perusahaan sendiri

**Jangan**: gunakan nethercap untuk denial-of-service, stealing credentials dari orang lain, atau merusak layanan publik.

---

## Lisensi & Attribution

**License**: MIT (bebas digunakan, modifikasi, distribute — dengan attribution)

**Inspiration & Reference**:
- Espressif ESP8266 SDK & API
- esp8266_deauther (Spacehuhn)
- WiFi 802.11 protocol spec (IEEE)
- Arduino core for ESP8266
- DNSServer & ESP8266WebServer (Arduino built-in)

---

## Kontribusi & Feedback

Report bug, request fitur, atau improve dokumentasi? **Contribution welcome** — fork, improve, PR.

Atau direct message ke contact project di GitHub.

---

**Enjoy exploring WiFi security! Stay ethical, stay learning.** 🛡️
