#!/usr/bin/env python3
# nethercap :: pre-build patch
#
# ESP8266 SDK memblok injection frame deauth/disassoc di dalam
# ieee80211_freedom_output() (dipanggil oleh wifi_send_pkt_freedom).
# Whitelist-nya cuma mengizinkan: data, beacon, probe-req, probe-resp.
#
# Patch ini mengubah 1 instruksi di libnet80211.a:
#   0x85: beqi a0,128,accept   (cuma terima beacon, subtype 8)
#     ->  j    accept          (terima SEMUA management frame, type 0)
# Akibatnya deauth (sub 12) & disassoc (sub 10) ikut lolos -> bisa di-inject.
#
# Aman: penggantian byte sama-panjang (3->3) jadi struktur archive .a utuh.
# Idempotent + backup .orig. Re-apply otomatis tiap build.

Import("env")
import os, glob, shutil

# Jendela byte unik di sekitar whitelist subtype (little-endian, dari disassembly)
#   47 83 0a            bany a3,a4,reject     (pastikan type==0)
#   26 e0 1b            beqi a0,128,accept    <-- diubah
#   26 d0 18            beqi a0,64,accept
#   5c 02               movi.n a2,80
#   27 10 13            beq  a0,a2,accept
#   7c e2               movi.n a2,-2 (reject)
ORIG = bytes([0x47,0x83,0x0a, 0x26,0xe0,0x1b, 0x26,0xd0,0x18,
              0x5c,0x02, 0x27,0x10,0x13, 0x7c,0xe2])
# 26 e0 1b (beqi a0,128,accept) -> c6 06 00 (j accept)
PATCHED = bytes([0x47,0x83,0x0a, 0xc6,0x06,0x00, 0x26,0xd0,0x18,
                 0x5c,0x02, 0x27,0x10,0x13, 0x7c,0xe2])


def patch_archive(path):
    data = bytearray(open(path, "rb").read())
    if data.find(PATCHED) != -1:
        return "sudah-dipatch"
    idx = data.find(ORIG)
    if idx == -1:
        return "pola-tidak-ketemu"
    if not os.path.exists(path + ".orig"):
        shutil.copy2(path, path + ".orig")          # backup sekali
    data[idx:idx+len(ORIG)] = PATCHED
    open(path, "wb").write(data)
    return "DIPATCH"


fw = env.PioPlatform().get_package_dir("framework-arduinoespressif8266")
libs = sorted(glob.glob(os.path.join(fw, "tools", "sdk", "lib", "NONOSDK*", "libnet80211.a")))

print("[nethercap] aktifkan injection deauth (patch libnet80211.a):")
if not libs:
    print("   ! libnet80211.a tidak ditemukan — deauth akan tetap diblok")
for lib in libs:
    res = patch_archive(lib)
    print("   %-16s %s" % (res, os.path.relpath(lib, fw)))
