package com.bysonic.tglock

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat

class MainActivity : TauriActivity() {
  private val requestNotifications =
      registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        // The tunnel works either way: without the permission the system simply
        // hides the notification, while the foreground service still keeps the
        // process alive.
      }

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    askForNotificationPermission()
  }

  private fun askForNotificationPermission() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
    val granted =
        ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
    if (!granted) {
      requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
    }
  }
}
