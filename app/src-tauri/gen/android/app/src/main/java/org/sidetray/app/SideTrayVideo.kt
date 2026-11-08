package org.sidetray.app

import android.content.Context
import android.graphics.Bitmap
import android.net.ConnectivityManager
import android.media.MediaCodecInfo
import android.media.MediaCodecList
import android.media.MediaExtractor
import android.media.MediaFormat
import android.media.MediaMetadataRetriever
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.annotation.OptIn
import androidx.media3.common.MediaItem
import androidx.media3.common.MimeTypes
import androidx.media3.common.util.UnstableApi
import androidx.media3.effect.FrameDropEffect
import androidx.media3.effect.Presentation
import androidx.media3.transformer.AudioEncoderSettings
import androidx.media3.transformer.Composition
import androidx.media3.transformer.DefaultEncoderFactory
import androidx.media3.transformer.EditedMediaItem
import androidx.media3.transformer.EditedMediaItemSequence
import androidx.media3.transformer.Effects
import androidx.media3.transformer.ExportException
import androidx.media3.transformer.ExportResult
import androidx.media3.transformer.ProgressHolder
import androidx.media3.transformer.Transformer
import androidx.media3.transformer.VideoEncoderSettings
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * Videos on Android (SPEC.md Phase 9c), called from Rust over JNI (src/android.rs):
 * probing a clip, transcoding it with Media3 Transformer on the phone's
 * hardware encoder, and taking the poster frame. One transcode at a time; Rust
 * polls `transcodeState` for progress and the result.
 *
 * A source is a `content://` URI (the picker, a share) or a file path.
 */
@OptIn(UnstableApi::class)
object SideTrayVideo {
  private const val TAG = "SideTrayVideo"
  private val main = Handler(Looper.getMainLooper())
  private val lock = Any()

  private var transformer: Transformer? = null
  private var outPath: String? = null
  /** "idle", "running", "done", "error", "cancelled". */
  private var state = "idle"
  private var progress = 0
  private var error: String? = null
  private var startedAt = 0L
  private var finishedAt = 0L

  private fun context(): Context =
    SideTrayAndroid.context() ?: throw IllegalStateException("Android isn't ready yet")

  private fun uri(src: String): Uri =
    if (src.startsWith("content://") || src.startsWith("file://")) Uri.parse(src) else Uri.fromFile(File(src))

  /** Whether the current network is metered (mobile data, a hotspot, metered Wi-Fi). */
  @JvmStatic
  fun isMetered(): Boolean {
    val cm = context().getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    return cm.isActiveNetworkMetered
  }

  /** Whether this phone can make videos: an H.264 and an AAC encoder. */
  @JvmStatic
  fun canEncode(): Boolean {
    val list = MediaCodecList(MediaCodecList.REGULAR_CODECS).codecInfos.filter { it.isEncoder }
    fun has(mime: String) = list.any { c -> c.supportedTypes.any { it.equals(mime, ignoreCase = true) } }
    return has(MediaFormat.MIMETYPE_VIDEO_AVC) && has(MediaFormat.MIMETYPE_AUDIO_AAC)
  }

  /**
   * {duration_ms, width, height (as displayed, rotation applied), audio_channels
   * (0: no audio), hdr, video} as JSON, or {"error"}.
   */
  @JvmStatic
  fun probeVideo(src: String): String = try {
    val ctx = context()
    val u = uri(src)
    val r = MediaMetadataRetriever()
    val out = JSONObject()
    try {
      r.setDataSource(ctx, u)
      val dur = r.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull() ?: 0L
      var w = r.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH)?.toIntOrNull() ?: 0
      var h = r.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT)?.toIntOrNull() ?: 0
      val rot = r.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_ROTATION)?.toIntOrNull() ?: 0
      if (rot == 90 || rot == 270) { val t = w; w = h; h = t }
      out.put("duration_ms", dur).put("width", w).put("height", h)
      out.put("video", r.extractMetadata(MediaMetadataRetriever.METADATA_KEY_HAS_VIDEO) == "yes")
    } finally {
      r.release()
    }
    var channels = 0
    var hdr = false
    val ex = MediaExtractor()
    try {
      ex.setDataSource(ctx, u, null)
      for (i in 0 until ex.trackCount) {
        val f = ex.getTrackFormat(i)
        val mime = f.getString(MediaFormat.KEY_MIME) ?: continue
        if (mime.startsWith("audio/") && channels == 0 && f.containsKey(MediaFormat.KEY_CHANNEL_COUNT)) {
          channels = f.getInteger(MediaFormat.KEY_CHANNEL_COUNT)
        }
        if (mime.startsWith("video/") && f.containsKey(MediaFormat.KEY_COLOR_TRANSFER)) {
          val t = f.getInteger(MediaFormat.KEY_COLOR_TRANSFER)
          hdr = hdr || t == MediaFormat.COLOR_TRANSFER_ST2084 || t == MediaFormat.COLOR_TRANSFER_HLG
        }
      }
    } finally {
      ex.release()
    }
    out.put("audio_channels", channels).put("hdr", hdr)
      .put("can_tone_map", android.os.Build.VERSION.SDK_INT >= 29).toString()
  } catch (e: Exception) {
    Log.w(TAG, "probe failed", e)
    JSONObject().put("error", e.message ?: e.javaClass.simpleName).toString()
  }

  /**
   * Start a transcode of `src` into the MP4 `out`: `width`×`height` (as
   * displayed), H.264 at `videoBps` (CBR or VBR), AAC at `audioBps`, 30 fps at most,
   * cut at `endMs` (0: whole clip). HDR is tone-mapped to SDR. Returns null when
   * started, or why it couldn't.
   */
  @JvmStatic
  fun transcodeVideo(src: String, out: String, width: Int, height: Int, videoBps: Int, audioBps: Int, endMs: Long, cbr: Boolean): String? {
    synchronized(lock) {
      if (state == "running") return "another video is being prepared"
      state = "running"
      progress = 0
      error = null
      outPath = out
      startedAt = System.nanoTime()
    }
    main.post {
      try {
        val ctx = context()
        val item = MediaItem.Builder().setUri(uri(src))
        if (endMs > 0) {
          item.setClippingConfiguration(MediaItem.ClippingConfiguration.Builder().setEndPositionMs(endMs).build())
        }
        val edited = EditedMediaItem.Builder(item.build())
          .setEffects(
            Effects(
              listOf(),
              listOf(
                FrameDropEffect.createDefaultFrameDropEffect(30f),
                Presentation.createForWidthAndHeight(width, height, Presentation.LAYOUT_SCALE_TO_FIT),
              ),
            ),
          )
          .build()
        val composition = Composition.Builder(EditedMediaItemSequence.Builder(edited).build())
          .setHdrMode(Composition.HDR_MODE_TONE_MAP_HDR_TO_SDR_USING_OPEN_GL)
          .build()
        val video = VideoEncoderSettings.Builder()
          .setBitrate(videoBps)
          .setBitrateMode(
            if (cbr) MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_CBR else MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_VBR,
          )
          .setEncodingProfileLevel(
            MediaCodecInfo.CodecProfileLevel.AVCProfileHigh,
            MediaCodecInfo.CodecProfileLevel.AVCLevel4,
          )
          .build()
        val audio = AudioEncoderSettings.Builder().setBitrate(audioBps).build()
        val encoders = DefaultEncoderFactory.Builder(ctx)
          .setRequestedVideoEncoderSettings(video)
          .setRequestedAudioEncoderSettings(audio)
          .setEnableFallback(true)
          .build()
        File(out).delete()
        val t = Transformer.Builder(ctx)
          .setVideoMimeType(MimeTypes.VIDEO_H264)
          .setAudioMimeType(MimeTypes.AUDIO_AAC)
          .setEncoderFactory(encoders)
          .setLooper(Looper.getMainLooper())
          .addListener(object : Transformer.Listener {
            override fun onCompleted(composition: Composition, result: ExportResult) =
              finish("done", null)

            override fun onError(composition: Composition, result: ExportResult, e: ExportException) {
              Log.w(TAG, "transcode failed", e)
              finish("error", "${e.errorCodeName}: ${e.message ?: ""}")
            }
          })
          .build()
        synchronized(lock) { transformer = t }
        t.start(composition, out)
        poll()
      } catch (e: Exception) {
        Log.w(TAG, "transcode didn't start", e)
        finish("error", e.message ?: e.javaClass.simpleName)
      }
    }
    return null
  }

  private val holder = ProgressHolder()

  /** Progress from the Transformer, on its looper, while it runs. */
  private fun poll() {
    val t = synchronized(lock) { if (state == "running") transformer else null } ?: return
    if (t.getProgress(holder) == Transformer.PROGRESS_STATE_AVAILABLE) {
      synchronized(lock) { progress = holder.progress }
    }
    main.postDelayed({ poll() }, 200)
  }

  private fun finish(s: String, err: String?) {
    synchronized(lock) {
      if (state != "running") return
      state = s
      error = err
      transformer = null
      finishedAt = System.nanoTime()
      if (s != "done") outPath?.let { File(it).delete() }
    }
  }

  /** {state, progress (0–100), error?, elapsed_ms} as JSON. */
  @JvmStatic
  fun transcodeState(): String = synchronized(lock) {
    val end = if (state == "running") System.nanoTime() else finishedAt
    JSONObject()
      .put("state", state)
      .put("progress", progress)
      .put("error", error ?: JSONObject.NULL)
      .put("elapsed_ms", if (startedAt == 0L) 0 else (end - startedAt) / 1_000_000)
      .toString()
  }

  /** Stop the running transcode (its half-made file is deleted). */
  @JvmStatic
  fun cancelTranscode() {
    main.post {
      val t = synchronized(lock) { transformer }
      t?.cancel()
      finish("cancelled", null)
    }
  }

  /** The frame at `atUs` (or the nearest sync frame) as a JPEG, or null. */
  @JvmStatic
  fun videoFrame(src: String, atUs: Long): ByteArray? {
    val r = MediaMetadataRetriever()
    return try {
      r.setDataSource(context(), uri(src))
      val bmp = r.getFrameAtTime(atUs, MediaMetadataRetriever.OPTION_CLOSEST_SYNC) ?: r.frameAtTime ?: return null
      val buf = ByteArrayOutputStream()
      bmp.compress(Bitmap.CompressFormat.JPEG, 90, buf)
      bmp.recycle()
      buf.toByteArray()
    } catch (e: Exception) {
      Log.w(TAG, "frame grab failed", e)
      null
    } finally {
      r.release()
    }
  }

}
