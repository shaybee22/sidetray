//! Photo preparation before upload (SPEC.md, "Media"): apply the EXIF
//! orientation, scale the longest side to at most 2048 px, encode WebP at
//! quality 80, and make a 400 px thumbnail.
//!
//! EXIF (GPS included) and every other metadata block are dropped because the
//! output is encoded from raw pixels: nothing from the original file is copied.
//!
//! Animated GIF, WebP and PNG keep only their first frame (the feed shows still
//! WebP); `Processed::still` says so, and the app tells the person.
//!
//! HEIC/HEIF (and AVIF) aren't in the image library. On Android the platform
//! decoder reads them (Android 9 and newer); the pixels then go through the
//! same steps, so nothing from the original file survives there either. On a
//! computer they're refused with a message saying so.

use anyhow::{anyhow, bail, Context, Result};
use image::{imageops::FilterType, AnimationDecoder, DynamicImage, ImageDecoder, ImageFormat, ImageReader};
use std::io::Cursor;

pub const MAX_SIDE: u32 = 2048;
pub const THUMB_SIDE: u32 = 400;
pub const QUALITY: f32 = 80.0;
pub const THUMB_QUALITY: f32 = 75.0;
/// Refuse inputs larger than this before decoding.
pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct Processed {
    pub full: Vec<u8>,
    pub thumb: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// The input was animated and only its first frame was kept.
    pub still: bool,
}

pub fn process(bytes: &[u8]) -> Result<Processed> {
    if bytes.len() > MAX_INPUT_BYTES {
        bail!("that file is over {} MB", MAX_INPUT_BYTES / 1024 / 1024);
    }
    let (img, still) = match decode(bytes) {
        Ok(decoded) => decoded,
        Err(e) => match platform_decode(bytes)? {
            Some(img) => (img, false),
            None if is_heif(bytes) => bail!("{HEIF_UNSUPPORTED}"),
            None => return Err(e),
        },
    };

    let full = fit(&img, MAX_SIDE);
    let thumb = fit(&full, THUMB_SIDE);
    Ok(Processed {
        width: full.width(),
        height: full.height(),
        full: encode_webp(&full, QUALITY),
        thumb: encode_webp(&thumb, THUMB_QUALITY),
        still,
    })
}

#[cfg(target_os = "android")]
const UNREADABLE: &str = "that isn't a photo this app can read (JPEG, PNG, GIF, WebP, BMP or HEIC)";
#[cfg(not(target_os = "android"))]
const UNREADABLE: &str = "that isn't a photo this app can read (JPEG, PNG, GIF, WebP or BMP)";

#[cfg(target_os = "android")]
const HEIF_UNSUPPORTED: &str =
    "this phone can't open that HEIC/HEIF photo (it needs Android 9 or newer). Save it as a JPEG first, then add that";
#[cfg(not(target_os = "android"))]
const HEIF_UNSUPPORTED: &str = "HEIC/HEIF photos (the format iPhones and many phone cameras use) can't be opened on a computer yet. Save it as a JPEG first, or send it from the Side Tray app on an Android phone";

/// The image library: the photo with its EXIF orientation applied, and whether it was animated.
fn decode(bytes: &[u8]) -> Result<(DynamicImage, bool)> {
    let reader = ImageReader::new(Cursor::new(bytes)).with_guessed_format()?;
    if reader.format().is_none() {
        return Err(anyhow!(UNREADABLE));
    }
    let still = is_animated(bytes, reader.format());
    let mut decoder = reader.into_decoder().context("reading the photo")?;
    let orientation = decoder.orientation().unwrap_or(image::metadata::Orientation::NoTransforms);
    let mut img = DynamicImage::from_decoder(decoder).context("decoding the photo")?;
    img.apply_orientation(orientation);
    Ok((img, still))
}

/// Android's own decoder, for what the image library can't read (HEIC/HEIF, AVIF).
#[cfg(target_os = "android")]
fn platform_decode(bytes: &[u8]) -> Result<Option<DynamicImage>> {
    Ok(crate::android::decode_image(bytes, MAX_SIDE)?.map(DynamicImage::ImageRgba8))
}

#[cfg(not(target_os = "android"))]
fn platform_decode(_bytes: &[u8]) -> Result<Option<DynamicImage>> {
    Ok(None)
}

/// An ISO base media file whose brands say HEIF (HEIC, or AVIF).
pub fn is_heif(bytes: &[u8]) -> bool {
    const BRANDS: [&[u8; 4]; 10] = [b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"mif1", b"msf1", b"avif", b"avis"];
    if bytes.len() < 16 || &bytes[4..8] != b"ftyp" {
        return false;
    }
    let size = (u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize).clamp(16, bytes.len().min(256));
    // Major brand at 8, minor version at 12, compatible brands from 16.
    let major: &[u8; 4] = bytes[8..12].try_into().unwrap();
    std::iter::once(major)
        .chain(bytes[16..size].as_chunks::<4>().0)
        .any(|b| BRANDS.contains(&b))
}

/// More than one frame: an animated GIF, WebP or PNG (APNG).
fn is_animated(bytes: &[u8], format: Option<ImageFormat>) -> bool {
    use image::codecs::{gif::GifDecoder, png::PngDecoder, webp::WebPDecoder};
    let c = || Cursor::new(bytes);
    match format {
        Some(ImageFormat::Gif) => GifDecoder::new(c()).is_ok_and(|d| d.into_frames().take(2).filter(|f| f.is_ok()).count() > 1),
        Some(ImageFormat::WebP) => WebPDecoder::new(c()).is_ok_and(|d| d.has_animation()),
        Some(ImageFormat::Png) => PngDecoder::new(c()).is_ok_and(|d| d.is_apng().unwrap_or(false)),
        _ => false,
    }
}

fn fit(img: &DynamicImage, side: u32) -> DynamicImage {
    if img.width().max(img.height()) <= side {
        img.clone()
    } else {
        // Keeps the aspect ratio, longest side = `side`.
        img.resize(side, side, FilterType::Lanczos3)
    }
}

pub fn encode_webp(img: &DynamicImage, quality: f32) -> Vec<u8> {
    let (w, h) = (img.width(), img.height());
    if img.color().has_alpha() {
        let rgba = img.to_rgba8();
        webp::Encoder::from_rgba(&rgba, w, h).encode(quality).to_vec()
    } else {
        let rgb = img.to_rgb8();
        webp::Encoder::from_rgb(&rgb, w, h).encode(quality).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{codecs::jpeg::JpegEncoder, RgbImage};

    const MARKER: &[u8] = b"GPS-SECRET-MARKER-51.5N";

    /// A JPEG with an EXIF block holding an orientation tag and a marker string.
    fn jpeg_with_exif(w: u32, h: u32, orientation: u16) -> Vec<u8> {
        let img = RgbImage::from_fn(w, h, |x, y| image::Rgb([(x % 256) as u8, (y % 256) as u8, 128]));
        let mut jpeg = Vec::new();
        JpegEncoder::new_with_quality(&mut jpeg, 90).encode_image(&img).unwrap();

        // TIFF (little endian): IFD0 with Orientation (SHORT) and ImageDescription (ASCII).
        let mut tiff = b"II*\0".to_vec();
        tiff.extend_from_slice(&8u32.to_le_bytes());
        tiff.extend_from_slice(&2u16.to_le_bytes());
        let desc_offset = 8 + 2 + 2 * 12 + 4;
        tiff.extend_from_slice(&0x0112u16.to_le_bytes());
        tiff.extend_from_slice(&3u16.to_le_bytes());
        tiff.extend_from_slice(&1u32.to_le_bytes());
        tiff.extend_from_slice(&orientation.to_le_bytes());
        tiff.extend_from_slice(&[0, 0]);
        tiff.extend_from_slice(&0x010Eu16.to_le_bytes());
        tiff.extend_from_slice(&2u16.to_le_bytes());
        tiff.extend_from_slice(&(MARKER.len() as u32 + 1).to_le_bytes());
        tiff.extend_from_slice(&(desc_offset as u32).to_le_bytes());
        tiff.extend_from_slice(&0u32.to_le_bytes());
        tiff.extend_from_slice(MARKER);
        tiff.push(0);
        let mut app1 = b"Exif\0\0".to_vec();
        app1.extend_from_slice(&tiff);

        let mut out = jpeg[..2].to_vec(); // SOI
        out.extend_from_slice(&[0xFF, 0xE1]);
        out.extend_from_slice(&((app1.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&app1);
        out.extend_from_slice(&jpeg[2..]);
        assert!(out.windows(MARKER.len()).any(|w| w == MARKER));
        out
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn dims(webp: &[u8]) -> (u32, u32) {
        let img = image::load_from_memory_with_format(webp, image::ImageFormat::WebP).unwrap();
        (img.width(), img.height())
    }

    #[test]
    fn large_photo_is_scaled_stripped_and_thumbnailed() {
        let p = process(&jpeg_with_exif(3000, 2000, 1)).unwrap();
        assert_eq!((p.width, p.height), (2048, 1365));
        assert_eq!(dims(&p.full), (2048, 1365));
        assert_eq!(dims(&p.thumb), (400, 267));
        for out in [&p.full, &p.thumb] {
            assert_eq!(&out[..4], b"RIFF");
            assert_eq!(&out[8..12], b"WEBP");
            assert!(!contains(out, MARKER));
            assert!(!contains(out, b"Exif"));
            assert!(!contains(out, b"EXIF"));
        }
    }

    #[test]
    fn exif_orientation_is_applied_before_stripping() {
        // Orientation 6: stored landscape, displayed rotated 90 degrees clockwise.
        let p = process(&jpeg_with_exif(300, 100, 6)).unwrap();
        assert_eq!((p.width, p.height), (100, 300));
        assert!(!contains(&p.full, MARKER));
    }

    #[test]
    fn small_photo_keeps_its_size() {
        let p = process(&jpeg_with_exif(640, 480, 1)).unwrap();
        assert_eq!((p.width, p.height), (640, 480));
        assert_eq!(dims(&p.thumb), (400, 300));
    }

    fn gif(frames: usize) -> Vec<u8> {
        use image::codecs::gif::GifEncoder;
        use image::{Delay, Frame, RgbaImage};
        let mut out = Vec::new();
        {
            let mut enc = GifEncoder::new(&mut out);
            for i in 0..frames {
                let img = RgbaImage::from_pixel(60, 40, image::Rgba([(i * 80) as u8, 0, 0, 255]));
                enc.encode_frame(Frame::from_parts(img, 0, 0, Delay::from_numer_denom_ms(100, 1))).unwrap();
            }
        }
        out
    }

    #[test]
    fn animated_gif_becomes_a_still_and_says_so() {
        let p = process(&gif(3)).unwrap();
        assert!(p.still);
        assert_eq!((p.width, p.height), (60, 40));
        assert_eq!(&p.full[8..12], b"WEBP");
    }

    #[test]
    fn single_frame_gif_and_jpeg_are_not_flagged() {
        assert!(!process(&gif(1)).unwrap().still);
        assert!(!process(&jpeg_with_exif(64, 64, 1)).unwrap().still);
    }

    #[test]
    fn bmp_is_accepted() {
        let img = image::RgbImage::from_pixel(30, 20, image::Rgb([1, 2, 3]));
        let mut bmp = Vec::new();
        img.write_to(&mut Cursor::new(&mut bmp), ImageFormat::Bmp).unwrap();
        assert_eq!(process(&bmp).unwrap().width, 30);
    }

    #[test]
    fn non_images_are_refused() {
        assert!(process(b"hello, not a photo").is_err());
    }

    /// The start of an iPhone HEIC: an `ftyp` box, major brand heic, compatible mif1 and heic.
    fn heic_header() -> Vec<u8> {
        let mut b = 24u32.to_be_bytes().to_vec();
        b.extend_from_slice(b"ftypheic\0\0\0\0mif1heic");
        b.extend_from_slice(&[0u8; 64]);
        b
    }

    #[test]
    fn heif_is_recognised() {
        assert!(is_heif(&heic_header()));
        let mut avif = 28u32.to_be_bytes().to_vec();
        avif.extend_from_slice(b"ftypmp42\0\0\0\0isommp42avif");
        assert!(is_heif(&avif));
        let mut mp4 = 24u32.to_be_bytes().to_vec();
        mp4.extend_from_slice(b"ftypisom\0\0\0\0isommp42");
        assert!(!is_heif(&mp4));
        assert!(!is_heif(&jpeg_with_exif(8, 8, 1)));
    }

    #[test]
    fn heif_on_a_computer_says_what_to_do() {
        let e = process(&heic_header()).err().unwrap().to_string();
        assert!(e.contains("HEIC/HEIF"), "{e}");
        assert!(e.contains("JPEG"), "{e}");
    }
}
