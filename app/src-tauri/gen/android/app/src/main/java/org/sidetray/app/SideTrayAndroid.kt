package org.sidetray.app

import android.Manifest
import android.app.Activity
import android.app.ActivityManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.ColorSpace
import android.graphics.ImageDecoder
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Parcelable
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import org.unifiedpush.android.connector.UnifiedPush
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
 * - decoding photo formats only Android can read (HEIC/HEIF, AVIF);
 * - notifications (A3): showing them, the permission, what a tapped one was
 *   about, UnifiedPush registration and the periodic sync (SideTrayWorker);
 * - updates (A4): handing a downloaded APK to the installer, and the
 *   "install unknown apps" permission it needs.
 *
 * And the other way, the `native*` functions are Rust (src/android.rs). A push
 * wake-up or the periodic job can start this process without MainActivity, so
 * they load the library themselves (`ensureNative`).
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

  const val TAG = "SideTray"
  const val ACTION_OPEN = "org.sidetray.app.OPEN"
  const val EXTRA_TARGET = "target"
  private const val PUSH_INSTANCE = "default"
  private const val NTFY = "io.heckel.ntfy"

  @JvmStatic external fun nativeInit(context: Context)
  @JvmStatic external fun nativeForeground(visible: Boolean)
  @JvmStatic external fun nativeSync(dataDir: String): String
  @JvmStatic external fun nativePush(dataDir: String, kind: String, value: String): String

  private var nativeReady = false
  private var observing = false
  /** A tapped notification's target (JSON), until the page takes it. */
  private var openTarget: String? = null

  /** Load the Rust library and hand it the JavaVM and the app's context (once per process). */
  fun ensureNative(ctx: Context) {
    synchronized(lock) {
      if (nativeReady) return
      appContext = ctx.applicationContext
      System.loadLibrary("sidetray_app_lib")
      nativeInit(ctx.applicationContext)
      nativeReady = true
    }
  }

  fun attach(a: Activity, coldStart: Boolean) {
    activity = WeakReference(a)
    appContext = a.applicationContext
    ensureNative(a)
    if (!observing) {
      observing = true
      // Whether the app is on screen: notifications aren't shown then, and the
      // push socket is closed while it isn't (so the relay sends wake-ups).
      ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
        override fun onStart(owner: LifecycleOwner) {
          nativeForeground(true)
          // What they were about is on screen now.
          appContext?.let { NotificationManagerCompat.from(it).cancelAll() }
        }
        override fun onStop(owner: LifecycleOwner) = nativeForeground(false)
      })
    }
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
    if (action == ACTION_OPEN) {
      // A tapped notification: the page asks for it (takeOpen) on start and resume.
      synchronized(lock) { openTarget = intent.getStringExtra(EXTRA_TARGET) }
      a.intent = Intent(Intent.ACTION_MAIN)
      return
    }
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

  // --- notifications (A3) --------------------------------------------------------------

  /** What a tapped notification was about (JSON), once. */
  @JvmStatic
  fun takeOpen(): String? = synchronized(lock) {
    val t = openTarget
    openTarget = null
    t
  }

  private fun channels(ctx: Context) {
    if (Build.VERSION.SDK_INT < 26) return
    val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
    fun ch(id: String, name: String, importance: Int, desc: String) {
      nm.createNotificationChannel(NotificationChannel(id, name, importance).apply { description = desc })
    }
    ch("posts", "New posts", NotificationManager.IMPORTANCE_DEFAULT, "Someone in your group posted")
    ch("comments", "Comments on your posts", NotificationManager.IMPORTANCE_DEFAULT, "Someone commented on something you posted")
    ch("messages", "Direct messages", NotificationManager.IMPORTANCE_HIGH, "Messages sent to you")
    ch("joins", "Join requests", NotificationManager.IMPORTANCE_HIGH, "Key Masters: someone is waiting to be let in")
    ch("account", "Your membership", NotificationManager.IMPORTANCE_DEFAULT, "If this device is removed from the group")
    ch("sync", "Checking for new posts", NotificationManager.IMPORTANCE_MIN, "Shown briefly on older Android versions while Side Tray syncs")
  }

  /** Builds the low-key notification an expedited job shows on Android 11 and older. */
  fun syncNotification(ctx: Context): android.app.Notification {
    channels(ctx)
    return NotificationCompat.Builder(ctx, "sync")
      .setSmallIcon(R.drawable.ic_stat_sidetray)
      .setContentTitle("Checking for new posts")
      .setPriority(NotificationCompat.PRIORITY_MIN)
      .setSilent(true)
      .build()
  }

  /**
   * Show notifications: a JSON array of {id, channel, title, body, target}.
   * Tapping one opens MainActivity with the target, which the page then shows.
   */
  @JvmStatic
  fun showNotifications(json: String): String? {
    val ctx = appContext ?: return null
    channels(ctx)
    val nm = NotificationManagerCompat.from(ctx)
    if (!nm.areNotificationsEnabled()) return "off"
    val items = JSONArray(json)
    for (i in 0 until items.length()) {
      val o = items.getJSONObject(i)
      val id = o.getInt("id")
      val channel = o.getString("channel")
      val body = o.getString("body")
      val open = Intent(ctx, MainActivity::class.java)
        .setAction(ACTION_OPEN)
        .putExtra(EXTRA_TARGET, o.getString("target"))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
      val pi = PendingIntent.getActivity(ctx, id, open, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
      val n = NotificationCompat.Builder(ctx, channel)
        .setSmallIcon(R.drawable.ic_stat_sidetray)
        .setColor(0xFF2F6F62.toInt())
        .setContentTitle(o.getString("title"))
        .setContentText(body)
        .setStyle(NotificationCompat.BigTextStyle().bigText(body))
        .setContentIntent(pi)
        .setAutoCancel(true)
        .setCategory(if (channel == "messages") NotificationCompat.CATEGORY_MESSAGE else NotificationCompat.CATEGORY_SOCIAL)
        .setPriority(if (channel == "messages" || channel == "joins") NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
        .build()
      try {
        nm.notify(id, n)
      } catch (e: SecurityException) {
        return "off"
      }
    }
    return "shown"
  }

  /** "on", "needs_permission" (Android 13+, not granted yet), or "off" (switched off in settings). */
  @JvmStatic
  fun notificationState(): String {
    val ctx = appContext ?: return "off"
    if (Build.VERSION.SDK_INT >= 33 &&
      ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
      return "needs_permission"
    }
    return if (NotificationManagerCompat.from(ctx).areNotificationsEnabled()) "on" else "off"
  }

  /** Android's "Allow Side Tray to send you notifications?" prompt (Android 13+). */
  @JvmStatic
  fun requestNotificationPermission(): String {
    val a = activity?.get() ?: return "no_window"
    if (Build.VERSION.SDK_INT < 33) return "not_needed"
    a.runOnUiThread { a.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 41) }
    return "asked"
  }

  /** Android's notification settings for Side Tray (after the permission was refused). */
  @JvmStatic
  fun openNotificationSettings(): String? {
    val a = activity?.get() ?: return null
    val i = if (Build.VERSION.SDK_INT >= 26) {
      Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, a.packageName)
    } else {
      Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + a.packageName))
    }
    a.runOnUiThread { a.startActivity(i) }
    return null
  }

  // --- battery restrictions ------------------------------------------------------------

  /**
   * Whether Android holds back Side Tray or the push app (`distributor`, may be
   * "") to save battery. Held-back apps get wake-ups late or not at all: the
   * phone may freeze them, and dozing cuts their network. JSON:
   * {app_unrestricted, app_restricted, distributor_unrestricted (or null)}.
   */
  @JvmStatic
  fun batteryState(distributor: String): String {
    val ctx = appContext ?: return "{}"
    val pm = ctx.getSystemService(PowerManager::class.java)
    val restricted = Build.VERSION.SDK_INT >= 28 &&
      (ctx.getSystemService(ActivityManager::class.java)?.isBackgroundRestricted ?: false)
    val dist: Any = if (distributor.isEmpty()) JSONObject.NULL else pm.isIgnoringBatteryOptimizations(distributor)
    return JSONObject()
      .put("app_unrestricted", pm.isIgnoringBatteryOptimizations(ctx.packageName))
      .put("app_restricted", restricted)
      .put("distributor_unrestricted", dist)
      .toString()
  }

  /**
   * Take the person to the right place to make `pkg` Unrestricted. For Side
   * Tray itself that's Android's one-tap "Let app always run in background?"
   * dialog (unless it's set to Restricted, which only its App info screen can
   * undo). For another app (ntfy), its App info screen: Battery → Unrestricted.
   */
  @JvmStatic
  fun openBatterySettings(pkg: String): String? {
    val a = activity?.get() ?: return null
    val uri = Uri.parse("package:$pkg")
    val restricted = Build.VERSION.SDK_INT >= 28 &&
      (a.getSystemService(ActivityManager::class.java)?.isBackgroundRestricted ?: false)
    val pm = a.getSystemService(PowerManager::class.java)
    val intents = mutableListOf<Intent>()
    if (pkg == a.packageName && !restricted && !pm.isIgnoringBatteryOptimizations(pkg)) {
      @Suppress("BatteryLife")
      intents.add(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, uri))
    }
    intents.add(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, uri))
    intents.add(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
    a.runOnUiThread {
      for (i in intents) {
        try {
          a.startActivity(i)
          return@runOnUiThread
        } catch (e: Exception) {
          Log.w(TAG, "no screen for ${i.action}", e)
        }
      }
    }
    return null
  }

  // --- UnifiedPush and the periodic sync (A3) ---------------------------------------------

  /**
   * Register with the UnifiedPush distributor: the one already chosen, or else
   * ntfy, or else the first one installed. "fresh" unregisters first, so the
   * distributor makes a new endpoint (on its current default server). Returns
   * the distributor's package, or "" if the phone has none.
   */
  @JvmStatic
  fun pushRegister(mode: String): String {
    val ctx = appContext ?: return ""
    var d = UnifiedPush.getAckDistributor(ctx) ?: UnifiedPush.getSavedDistributor(ctx)
    if (d == null) {
      val all = UnifiedPush.getDistributors(ctx).filter { it != ctx.packageName }
      d = all.firstOrNull { it == NTFY } ?: all.firstOrNull()
      if (d != null) UnifiedPush.saveDistributor(ctx, d)
    }
    if (d == null) return ""
    if (mode == "fresh") {
      UnifiedPush.unregister(ctx, PUSH_INSTANCE)
      // Unregistering the last registration also forgets the distributor.
      UnifiedPush.saveDistributor(ctx, d)
    }
    UnifiedPush.register(ctx, PUSH_INSTANCE, "Side Tray", null)
    return d
  }

  @JvmStatic
  fun pushUnregister(): String? {
    appContext?.let { UnifiedPush.unregister(it, PUSH_INSTANCE) }
    return null
  }

  @JvmStatic
  fun periodicSync(mode: String): String? {
    appContext?.let { SideTrayWorker.periodic(it, mode == "on") }
    return null
  }

  // --- updates (A4) ------------------------------------------------------------------------

  /** Where Rust saves a downloaded APK (inside the FileProvider's cache-path). */
  @JvmStatic
  fun updateDir(): String? = appContext?.let { File(it.cacheDir, "updates").absolutePath }

  /** "yes" when Side Tray may hand APKs to the installer ("Install unknown apps", Android 8+). */
  @JvmStatic
  fun canInstallApks(): String {
    val ctx = appContext ?: return "no"
    return if (Build.VERSION.SDK_INT < 26 || ctx.packageManager.canRequestPackageInstalls()) "yes" else "no"
  }

  /**
   * Open Android's installer on a downloaded APK. Android checks that it's
   * signed with the same key as this app and asks the person to confirm.
   */
  @JvmStatic
  fun installApk(path: String): String {
    val a = activity?.get() ?: return "no_window"
    if (canInstallApks() != "yes") return "needs_permission"
    val uri = FileProvider.getUriForFile(a, a.packageName + ".fileprovider", File(path))
    // INSTALL_PACKAGE goes straight to the system's package installer; VIEW with
    // the APK type would also offer any app that opens APK files (Termux, office
    // apps...) in an "Open with" chooser. VIEW stays as the fallback.
    @Suppress("DEPRECATION")
    val intents = listOf(
      Intent(Intent.ACTION_INSTALL_PACKAGE).setData(uri),
      Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive"),
    ).map { it.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION) }
    a.runOnUiThread {
      for (i in intents) {
        try {
          a.startActivity(i)
          return@runOnUiThread
        } catch (e: Exception) {
          Log.w(TAG, "no installer for ${i.action}", e)
        }
      }
    }
    return "started"
  }

  /** Android's "Install unknown apps" switch for Side Tray ("Allow from this source"). */
  @JvmStatic
  fun openInstallSettings(): String? {
    val a = activity?.get() ?: return null
    val uri = Uri.parse("package:" + a.packageName)
    val intents = mutableListOf<Intent>()
    if (Build.VERSION.SDK_INT >= 26) intents.add(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, uri))
    intents.add(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, uri))
    a.runOnUiThread {
      for (i in intents) {
        try {
          a.startActivity(i)
          return@runOnUiThread
        } catch (e: Exception) {
          Log.w(TAG, "no screen for ${i.action}", e)
        }
      }
    }
    return null
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
