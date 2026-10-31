package org.sidetray.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.ColorSpace
import android.graphics.ImageDecoder
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Parcelable
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.lang.ref.WeakReference
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import kotlin.math.roundToInt

/**
 * Native helpers for Side Tray on Android. The Rust side calls the @JvmStatic
 * methods over JNI (src/android.rs):
 *
 * - content shared to Side Tray from another app ("Share → Side Tray"), copied
 *   into the app's cache so Rust can run it through the photo pipeline;
 * - moving the app to the background (the back button on the feed);
 * - deleting the camera's full-size originals once they're staged;
 * - decoding photo formats only Android can read (HEIC/HEIF, AVIF).
 */
object SideTrayAndroid {
  private const val MAX_FILES = 20
  private const val MAX_BYTES = 64L * 1024 * 1024
  private const val COPYING = "copying"

  private var activity: WeakReference<Activity>? = null
  private var appContext: Context? = null
  private val worker = Executors.newSingleThreadExecutor()
  private val lock = Any()

  /** null: nothing shared; COPYING: still reading it; otherwise the share as JSON. */
  private var share: String? = null
  private var shareSeq = 0

  private class TooLarge : IOException()

  fun attach(a: Activity, coldStart: Boolean) {
    activity = WeakReference(a)
    appContext = a.applicationContext
    if (coldStart) {
      // Leftovers from a share or a camera shot the app never finished with.
      worker.execute {
        File(a.cacheDir, "share").deleteRecursively()
        cleanCaptures()
      }
    }
  }

  /** An ACTION_SEND / ACTION_SEND_MULTIPLE intent: copy what came with it, off the main thread. */
  fun receive(a: Activity, intent: Intent?) {
    val action = intent?.action ?: return
    if (action != Intent.ACTION_SEND && action != Intent.ACTION_SEND_MULTIPLE) return
    val uris = LinkedHashSet<Uri>()
    if (action == Intent.ACTION_SEND) {
      streamExtra(intent)?.let { uris.add(it) }
    } else {
      streamListExtra(intent)?.let { uris.addAll(it) }
    }
    intent.clipData?.let { clip ->
      for (i in 0 until clip.itemCount) clip.getItemAt(i).uri?.let { uris.add(it) }
    }
    val text = intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString() ?: ""
    val subject = intent.getStringExtra(Intent.EXTRA_SUBJECT) ?: ""
    // Handled: if the activity is recreated it mustn't share the same thing again.
    a.intent = Intent(Intent.ACTION_MAIN)

    val seq: Int
    synchronized(lock) {
      seq = ++shareSeq
      share = COPYING
    }
    val resolver = a.applicationContext.contentResolver
    val dir = File(File(a.cacheDir, "share"), seq.toString())
    worker.execute {
      val files = JSONArray()
      val errors = JSONArray()
      var skipped = 0
      dir.deleteRecursively()
      dir.mkdirs()
      for ((i, uri) in uris.withIndex()) {
        if (i >= MAX_FILES) {
          skipped += uris.size - MAX_FILES
          break
        }
        val mime = try { resolver.getType(uri) } catch (e: Exception) { null }
        if (mime != null && !mime.startsWith("image/")) {
          skipped++
          continue
        }
        val out = File(dir, i.toString())
        try {
          val input = resolver.openInputStream(uri) ?: throw IOException("no data")
          input.use { src ->
            out.outputStream().use { dst ->
              val buf = ByteArray(64 * 1024)
              var total = 0L
              while (true) {
                val n = src.read(buf)
                if (n < 0) break
                total += n
                if (total > MAX_BYTES) throw TooLarge()
                dst.write(buf, 0, n)
              }
            }
          }
          files.put(JSONObject().put("path", out.absolutePath).put("mime", mime ?: ""))
        } catch (e: TooLarge) {
          out.delete()
          errors.put("A shared picture is over 64 MB, so it was left out.")
        } catch (e: Exception) {
          out.delete()
          errors.put("Couldn't read a shared picture (${e.javaClass.simpleName}).")
        }
      }
      val json = JSONObject()
        .put("text", text)
        .put("subject", subject)
        .put("dir", dir.absolutePath)
        .put("files", files)
        .put("skipped", skipped)
        .put("errors", errors)
      synchronized(lock) {
        if (seq == shareSeq) share = json.toString() else dir.deleteRecursively()
      }
    }
  }

  @Suppress("DEPRECATION")
  private fun streamExtra(intent: Intent): Uri? =
    if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
    else intent.getParcelableExtra<Parcelable>(Intent.EXTRA_STREAM) as? Uri

  @Suppress("DEPRECATION")
  private fun streamListExtra(intent: Intent): List<Uri>? =
    if (Build.VERSION.SDK_INT >= 33) intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
    else intent.getParcelableArrayListExtra<Parcelable>(Intent.EXTRA_STREAM)?.mapNotNull { it as? Uri }

  /** What was shared: null (nothing), "copying" (ask again shortly), or JSON (taken: asking again gives null). */
  @JvmStatic
  fun takeShare(): String? = synchronized(lock) {
    val s = share
    if (s != COPYING) share = null
    s
  }

  /**
   * The system bars and display cutouts the page has to keep clear of, in CSS
   * pixels: "top,right,bottom,left". Older WebViews report only some of these
   * as env(safe-area-inset-*), so the page asks here too.
   */
  @JvmStatic
  fun insets(): String? {
    val a = activity?.get() ?: return null
    val root = ViewCompat.getRootWindowInsets(a.window.decorView) ?: return null
    val i = root.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
    val d = a.resources.displayMetrics.density
    return "${i.top / d},${i.right / d},${i.bottom / d},${i.left / d}"
  }

  /** The back button with nothing left to close: leave the app running in the background, like Home. */
  @JvmStatic
  fun moveToBackground() {
    val a = activity?.get() ?: return
    a.runOnUiThread { a.moveTaskToBack(true) }
  }

  /**
   * The WebView's camera button saves each shot as a full-size JPEG (location
   * and all) in the app's external Pictures folder. Once it's been staged
   * (resized, stripped, re-encoded) the original isn't needed.
   */
  @JvmStatic
  fun cleanCaptures() {
    val ctx = appContext ?: return
    val dir = ctx.getExternalFilesDir(Environment.DIRECTORY_PICTURES) ?: return
    dir.listFiles()?.forEach { f ->
      if (f.isFile && f.name.startsWith("JPEG_") && f.name.endsWith(".jpg")) f.delete()
    }
  }

  /**
   * Decode a photo the Rust image library can't read (HEIC/HEIF from Android
   * 9, AVIF from Android 12) with the platform decoder, which also applies the
   * EXIF orientation. Scaled down so the longest side is at most `maxSide`.
   * Returns width (4 bytes, big endian), height (4 bytes), then RGBA pixels
   * (not premultiplied), or null if Android can't decode it either.
   */
  @JvmStatic
  fun decodeImage(bytes: ByteArray, maxSide: Int): ByteArray? {
    if (Build.VERSION.SDK_INT < 28) return null
    return try {
      val source = ImageDecoder.createSource(ByteBuffer.wrap(bytes))
      var bmp = ImageDecoder.decodeBitmap(source) { decoder, info, _ ->
        decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
        decoder.isUnpremultipliedRequired = true
        decoder.setTargetColorSpace(ColorSpace.get(ColorSpace.Named.SRGB))
        val w = info.size.width
        val h = info.size.height
        val longest = maxOf(w, h)
        if (longest > maxSide) {
          val s = maxSide.toDouble() / longest
          decoder.setTargetSize(maxOf(1, (w * s).roundToInt()), maxOf(1, (h * s).roundToInt()))
        }
      }
      if (bmp.config != Bitmap.Config.ARGB_8888) bmp = bmp.copy(Bitmap.Config.ARGB_8888, false)
      val out = ByteBuffer.allocate(8 + bmp.width * bmp.height * 4)
      out.putInt(bmp.width)
      out.putInt(bmp.height)
      bmp.copyPixelsToBuffer(out)
      bmp.recycle()
      out.array()
    } catch (e: Exception) {
      null
    } catch (e: OutOfMemoryError) {
      null
    }
  }
}
