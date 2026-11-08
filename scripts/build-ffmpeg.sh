#!/usr/bin/env bash
# Builds the trimmed, LGPL-only ffmpeg.exe that the Windows app bundles to
# prepare videos (Phase 9). Cross-compiles on Linux (Ubuntu or WSL) with
# mingw-w64:
#
#   sudo apt-get install mingw-w64 nasm make pkg-config xz-utils curl
#   scripts/build-ffmpeg.sh            # writes app/src-tauri/binaries/ffmpeg-x86_64-pc-windows-msvc.exe
#
# Only what the app needs is built in: the demuxers and decoders for common
# phone and camera videos, Windows' own H.264 encoder (Media Foundation,
# h264_mf), ffmpeg's AAC encoder, the MP4 muxer, and a JPEG encoder for the
# poster frame. No GPL or "version 3" parts and no external libraries, so the
# result is LGPL 2.1 or later; README.md says where its source is.
set -euo pipefail

VERSION=9.0.2
SHA256=8c3850283eb25fa026482078a04051e0be17347b09ef81a0849bec15a96e002e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/app/src-tauri/binaries/ffmpeg-x86_64-pc-windows-msvc.exe"
WORK="${FFMPEG_BUILD_DIR:-${TMPDIR:-/tmp}/sidetray-ffmpeg}"

mkdir -p "$WORK" "$(dirname "$OUT")"
cd "$WORK"
tarball="ffmpeg-$VERSION.tar.xz"
if [ ! -f "$tarball" ]; then
    curl -fsSL "https://ffmpeg.org/releases/$tarball" -o "$tarball.part"
    mv "$tarball.part" "$tarball"
fi
echo "$SHA256  $tarball" | sha256sum -c -
rm -rf "ffmpeg-$VERSION"
tar xf "$tarball"
cd "ffmpeg-$VERSION"

./configure \
    --target-os=mingw32 --arch=x86_64 --cross-prefix=x86_64-w64-mingw32- \
    --enable-static --disable-shared --extra-ldflags=-static \
    --disable-autodetect --disable-everything --disable-debug --disable-doc \
    --disable-network --disable-programs --enable-ffmpeg \
    --enable-w32threads --enable-mediafoundation \
    --enable-d3d11va \
    --enable-protocol=file,pipe \
    --enable-demuxer=mov,matroska,avi,mpegts,mpegps,flv,h264,hevc,m4v,ogg,wav \
    --enable-decoder=h264,hevc,vp8,vp9,mpeg4,mpeg2video,mpeg1video,mjpeg,h263,msmpeg4v3,prores,dvvideo \
    --enable-decoder=aac,aac_latm,mp3float,mp2float,ac3,eac3,opus,vorbis,flac,alac,amrnb,amrwb \
    --enable-decoder=pcm_s16le,pcm_s16be,pcm_s24le,pcm_s32le,pcm_f32le,pcm_u8,pcm_alaw,pcm_mulaw \
    --enable-parser=h264,hevc,mpeg4video,mpegvideo,vp8,vp9,aac,aac_latm,ac3,mpegaudio,opus,vorbis,flac \
    --enable-encoder=h264_mf,aac,mjpeg \
    --enable-muxer=mp4,image2,image2pipe,null \
    --enable-filter=scale,fps,format,aformat,aresample,anull,null,transpose,hflip,vflip,setsar,trim,atrim \
    --enable-swscale --enable-swresample

make -j"$(nproc)"
x86_64-w64-mingw32-strip -o "$OUT" ffmpeg.exe
ls -l "$OUT"
