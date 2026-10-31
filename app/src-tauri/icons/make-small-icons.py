"""Swap the small icon sizes for the letters-only monogram.

At small sizes the frame around the TST monogram eats the pixels the letters
need, so everything 50 px and under uses the letters alone; the full framed
logo stays for the large sizes (64 px and up, the installer).

Run after `cargo tauri icon icons/app-icon.png`:  python make-small-icons.py

It writes:
- tray.png: the letters, frame removed, half-transparent gold made opaque,
  centred on a 256 px square. tray.rs draws the tray icon from it.
- The 16/24/32/48 px entries of icon.ico, the 16 and 32 px entries of
  icon.icns, and 32x32.png, Square30x30Logo.png, Square44x44Logo.png and
  StoreLogo.png, all from tray.png with the same thin dark edge as the tray.
"""
import io
import os
import struct
from PIL import Image, ImageDraw, ImageFilter

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = 256
EDGE = (70, 40, 0)  # same as tray.rs
SMALL_PNGS = {"32x32.png": 32, "Square30x30Logo.png": 30, "Square44x44Logo.png": 44, "StoreLogo.png": 50}
SMALL_ICO = {16, 24, 32, 48}


def path(name):
    return os.path.join(HERE, name)


def letters():
    im = Image.open(path("app-icon.png")).convert("RGBA")
    alpha = im.getchannel("A")
    solid = alpha.point(lambda v: 255 if v > 100 else 0)

    # The frame is the first solid pixel in from the left edge, halfway down;
    # flood it to tell it apart from the letters inside.
    y = im.height // 2
    x = next(x for x in range(im.width) if solid.getpixel((x, y)) == 255)
    ImageDraw.floodfill(solid, (x + 3, y), 128)
    frame = solid.point(lambda v: 255 if v == 128 else 0).filter(ImageFilter.MaxFilter(9))
    inner = solid.point(lambda v: 255 if v == 255 else 0)

    alpha = Image.composite(Image.new("L", im.size, 0), alpha, frame)
    alpha = alpha.point(lambda v: min(255, int(v * 1.7)))
    im.putalpha(alpha)
    im = im.crop(inner.getbbox())

    k = OUT / max(im.size)
    im = im.resize((round(im.width * k), round(im.height * k)), Image.LANCZOS)
    out = Image.new("RGBA", (OUT, OUT), (0, 0, 0, 0))
    out.alpha_composite(im, ((OUT - im.width) // 2, (OUT - im.height) // 2))
    return out


def small(src, s):
    """`src` at `s` px with a 1 px dark edge (85% of the 3x3 max alpha), as tray.rs does."""
    logo = src.resize((s, s), Image.LANCZOS)
    edge = logo.getchannel("A").filter(ImageFilter.MaxFilter(3)).point(lambda v: v * 85 // 100)
    out = Image.new("RGBA", (s, s), EDGE + (0,))
    out.putalpha(edge)
    out.alpha_composite(logo)
    return out


def png_bytes(im):
    buf = io.BytesIO()
    im.save(buf, "PNG", optimize=True)
    return buf.getvalue()


def patch_ico(src):
    """Replace the small entries of icon.ico; the large ones are kept byte for byte."""
    data = open(path("icon.ico"), "rb").read()
    count = struct.unpack("<3H", data[:6])[2]
    entries = []
    for i in range(count):
        w, h, colors, res, planes, bpp, size, off = struct.unpack("<4B2H2I", data[6 + 16 * i : 22 + 16 * i])
        px = w or 256
        body = png_bytes(small(src, px)) if px in SMALL_ICO else data[off : off + size]
        entries.append((w, h, colors, res, planes, bpp, body))
    missing = SMALL_ICO - {e[0] or 256 for e in entries}
    assert not missing, f"icon.ico has no {sorted(missing)} px entries"
    out = bytearray(struct.pack("<3H", 0, 1, len(entries)))
    off = 6 + 16 * len(entries)
    for w, h, colors, res, planes, bpp, body in entries:
        out += struct.pack("<4B2H2I", w, h, colors, res, planes, bpp, len(body), off)
        off += len(body)
    for e in entries:
        out += e[6]
    open(path("icon.ico"), "wb").write(out)


def rle(channel):
    """The ICNS is32/il32 channel encoding, written as plain literal runs."""
    out = bytearray()
    for i in range(0, len(channel), 128):
        chunk = channel[i : i + 128]
        out.append(len(chunk) - 1)
        out += chunk
    return bytes(out)


def patch_icns(src):
    """Replace the 16 px (is32/s8mk) and 32 px (il32/l8mk, ic11 = 16@2x) entries of icon.icns."""
    data = open(path("icon.icns"), "rb").read()
    assert data[:4] == b"icns"
    new = {}
    for kind, mask, s in [(b"is32", b"s8mk", 16), (b"il32", b"l8mk", 32)]:
        im = small(src, s)
        r, g, b, a = im.split()
        new[kind] = rle(r.tobytes()) + rle(g.tobytes()) + rle(b.tobytes())
        new[mask] = a.tobytes()
    new[b"ic11"] = png_bytes(small(src, 32))
    chunks, p = [], 8
    while p < len(data):
        kind, length = struct.unpack(">4sI", data[p : p + 8])
        chunks.append((kind, new.pop(kind, data[p + 8 : p + length])))
        p += length
    assert not new, f"icon.icns has no {sorted(new)} entries"
    body = b"".join(struct.pack(">4sI", k, len(v) + 8) + v for k, v in chunks)
    open(path("icon.icns"), "wb").write(b"icns" + struct.pack(">I", len(body) + 8) + body)


src = letters()
src.save(path("tray.png"), optimize=True)
for name, s in SMALL_PNGS.items():
    small(src, s).save(path(name), optimize=True)
patch_ico(src)
patch_icns(src)
