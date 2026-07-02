#!/usr/bin/env python3
"""img2h.py — konversi gambar (PNG/JPG/...) ke header C RGB565 untuk TFT_eSPI.

Hasilnya di-#include dari ui.cpp dan langsung tampil sebagai foto lock screen.

Contoh:
    python3 tools/img2h.py foto.png
    python3 tools/img2h.py foto.jpg -o src/lock_img.h
    python3 tools/img2h.py foto.png --fit contain          # letterbox (tanpa crop)
    python3 tools/img2h.py foto.jpg --focus-y 0.85         # crop bias ke bawah (objek di bawah)
    python3 tools/img2h.py foto.jpg --preview cek.png      # simpan hasil crop utk dicek dulu

Butuh Pillow:  pip install pillow

Catatan warna: array ditulis dalam RGB565 "native" dan ui.cpp memakai
tft.setSwapBytes(true). Kalau warna terlihat aneh/terbalik di layar,
ubah setSwapBytes(true) -> false di drawLock() (src/ui.cpp).
"""
import argparse
import os
import sys

try:
    from PIL import Image
except ImportError:
    sys.exit("Butuh Pillow. Install dulu:  pip install pillow")

try:
    RESAMPLE = Image.Resampling.LANCZOS      # Pillow >= 9.1
except AttributeError:
    RESAMPLE = Image.LANCZOS                 # Pillow lama


def to_rgb565(r, g, b):
    return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)


def fit_cover(img, w, h, fx=0.5, fy=0.5):
    """Skala agar menutupi penuh WxH lalu crop (mirip object-fit: cover).

    fx/fy (0..1) memilih bagian mana yang dipertahankan saat crop:
    0=kiri/atas, 0.5=tengah, 1=kanan/bawah. Pakai fy besar kalau objek
    ada di bagian bawah foto (biar kaki tidak terpotong)."""
    sw, sh = img.size
    scale = max(w / sw, h / sh)
    nw, nh = max(1, round(sw * scale)), max(1, round(sh * scale))
    img = img.resize((nw, nh), RESAMPLE)
    left = round((nw - w) * min(max(fx, 0.0), 1.0))
    top = round((nh - h) * min(max(fy, 0.0), 1.0))
    return img.crop((left, top, left + w, top + h))


def fit_contain(img, w, h, bg=(0, 0, 0)):
    """Skala agar muat penuh (aspek terjaga), sisanya diisi latar (letterbox)."""
    sw, sh = img.size
    scale = min(w / sw, h / sh)
    nw, nh = max(1, round(sw * scale)), max(1, round(sh * scale))
    img = img.resize((nw, nh), RESAMPLE)
    canvas = Image.new("RGB", (w, h), bg)
    canvas.paste(img, ((w - nw) // 2, (h - nh) // 2))
    return canvas


def main():
    ap = argparse.ArgumentParser(
        description="Konversi gambar -> header C RGB565 (TFT_eSPI pushImage)")
    ap.add_argument("input", help="file gambar sumber (PNG/JPG/...)")
    ap.add_argument("-o", "--output", default="src/lock_img.h",
                    help="file header keluaran (default: src/lock_img.h)")
    ap.add_argument("--width", type=int, default=240, help="lebar target (default 240)")
    ap.add_argument("--height", type=int, default=280, help="tinggi target (default 280)")
    ap.add_argument("--name", default="lock_img",
                    help="nama array (default lock_img; ui.cpp mengharapkan ini)")
    ap.add_argument("--fit", choices=["cover", "contain"], default="cover",
                    help="cover=crop penuh (default), contain=letterbox")
    ap.add_argument("--crop", default=None,
                    help="pra-crop 'L,T,R,B' (piksel) sebelum fit; utk membingkai objek")
    ap.add_argument("--focus-x", type=float, default=0.5,
                    help="posisi crop horizontal 0..1 (mode cover; default 0.5=tengah)")
    ap.add_argument("--focus-y", type=float, default=0.5,
                    help="posisi crop vertikal 0..1 (mode cover; default 0.5=tengah)")
    ap.add_argument("--preview", default=None,
                    help="simpan hasil akhir sebagai PNG untuk dicek (opsional)")
    args = ap.parse_args()

    img = Image.open(args.input).convert("RGB")
    if args.crop:
        l, t, r, b = (int(v) for v in args.crop.split(","))
        img = img.crop((l, t, r, b))
    w, h = args.width, args.height
    if args.fit == "cover":
        img = fit_cover(img, w, h, args.focus_x, args.focus_y)
    else:
        img = fit_contain(img, w, h)

    if args.preview:
        img.save(args.preview)
        print("preview -> %s" % args.preview)

    raw = img.tobytes()          # RGB, 3 byte per piksel
    name, up = args.name, args.name.upper()

    lines = [
        "#pragma once",
        "// Auto-generated oleh tools/img2h.py — JANGAN diedit manual.",
        f"// Sumber: {os.path.basename(args.input)}  ->  {w}x{h} RGB565 ({args.fit})",
        "#include <Arduino.h>",
        "",
        "#define LOCK_IMG_AVAILABLE 1",
        f"#define {up}_W {w}",
        f"#define {up}_H {h}",
        f"static const uint16_t {name}[{up}_W * {up}_H] PROGMEM = {{",
    ]

    row = []
    for i in range(0, len(raw), 3):
        row.append("0x%04X" % to_rgb565(raw[i], raw[i + 1], raw[i + 2]))
        if len(row) == 12:
            lines.append("  " + ",".join(row) + ",")
            row = []
    if row:
        lines.append("  " + ",".join(row) + ",")
    lines.append("};")
    lines.append("")

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w") as f:
        f.write("\n".join(lines))

    n = w * h
    print("OK -> %s  (%dx%d, %d px, %d byte di flash)" % (args.output, w, h, n, n * 2))


if __name__ == "__main__":
    main()
