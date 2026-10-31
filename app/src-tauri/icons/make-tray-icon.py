"""Make icons/tray.png (the tray icon's source) from icons/app-icon.png.

At 16 px the frame around the monogram eats the pixels the letters need, so the
tray uses the letters alone: the frame is removed, the letters cropped and
centred on a square, and their partly transparent gold made opaque so it
doesn't wash out on a light taskbar. tray.rs scales this down and adds a thin
dark edge at runtime.

Run from anywhere after changing app-icon.png:  python make-tray-icon.py
"""
import os
from PIL import Image, ImageDraw, ImageFilter

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = 256

im = Image.open(os.path.join(HERE, "app-icon.png")).convert("RGBA")
alpha = im.getchannel("A")
solid = alpha.point(lambda v: 255 if v > 100 else 0)

# The frame is the first solid pixel in from the left edge, halfway down;
# flood it to tell it apart from the letters inside.
y = im.height // 2
x = next(x for x in range(im.width) if solid.getpixel((x, y)) == 255)
ImageDraw.floodfill(solid, (x + 3, y), 128)
frame = solid.point(lambda v: 255 if v == 128 else 0).filter(ImageFilter.MaxFilter(9))
letters = solid.point(lambda v: 255 if v == 255 else 0)

alpha = Image.composite(Image.new("L", im.size, 0), alpha, frame)
alpha = alpha.point(lambda v: min(255, int(v * 1.7)))
im.putalpha(alpha)
im = im.crop(letters.getbbox())

k = OUT / max(im.size)
im = im.resize((round(im.width * k), round(im.height * k)), Image.LANCZOS)
out = Image.new("RGBA", (OUT, OUT), (0, 0, 0, 0))
out.alpha_composite(im, ((OUT - im.width) // 2, (OUT - im.height) // 2))
out.save(os.path.join(HERE, "tray.png"), optimize=True)
