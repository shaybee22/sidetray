package org.sidetray.app

import android.util.Log
import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage

/**
 * UnifiedPush events from the distributor (the ntfy app), A3. Called on the
 * main thread while the connector holds this service for a few seconds, so
 * everything real happens in SideTrayWorker.
 *
 * A message is only ever a wake-up: the relay sends an empty body (ntfy fills
 * in its own placeholder), and it's ignored. The sync fetches and decrypts
 * what's new over the relay's API.
 */
class SideTrayPushService : PushService() {
  // `instance` is the group (profile) the registration belongs to (SPEC.md Phase 8).
  override fun onMessage(message: PushMessage, instance: String) {
    SideTrayWorker.syncNow(this, instance)
  }

  override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
    SideTrayWorker.pushEvent(this, "endpoint", endpoint.url, instance)
  }

  override fun onRegistrationFailed(reason: FailedReason, instance: String) {
    Log.w(SideTrayAndroid.TAG, "UnifiedPush registration failed for $instance: $reason")
    SideTrayWorker.pushEvent(this, "failed", reason.name, instance)
  }

  override fun onUnregistered(instance: String) {
    SideTrayWorker.pushEvent(this, "unregistered", "", instance)
  }
}
