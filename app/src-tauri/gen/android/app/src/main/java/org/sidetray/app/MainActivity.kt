package org.sidetray.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.webkit.WebView
import androidx.activity.OnBackPressedCallback
import androidx.activity.enableEdgeToEdge

// A density change (a flip phone moving the app between its inner and outer
// screens) recreates this activity and so reloads the page: the WebView can't
// switch scale in place. The page keeps its drafts and view across that (app.js).
class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    SideTrayAndroid.attach(this, savedInstanceState == null)
    // Started by "Share → Side Tray" (a recreated activity has already handled it).
    if (savedInstanceState == null) SideTrayAndroid.receive(this, intent)
    // Back goes to the page (close the viewer, a dialog, a chat, ask about an
    // unsent post...), which leaves the app itself when there's nothing left.
    // Registered last, so it comes before Tauri's own handler, and again with
    // every new activity, so it keeps working after the window is rebuilt.
    onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
      override fun handleOnBackPressed() {
        val wv = findWebView(window.decorView)
        if (wv == null) {
          moveTaskToBack(true)
          return
        }
        wv.evaluateJavascript("window.__sidetrayBack ? window.__sidetrayBack() : false") { handled ->
          if (handled != "true") moveTaskToBack(true)
        }
      }
    })
  }

  private fun findWebView(v: View): WebView? {
    if (v is WebView) return v
    if (v is ViewGroup) for (i in 0 until v.childCount) findWebView(v.getChildAt(i))?.let { return it }
    return null
  }

  // Shared to while already running (launchMode singleTask).
  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    SideTrayAndroid.receive(this, intent)
  }
}
