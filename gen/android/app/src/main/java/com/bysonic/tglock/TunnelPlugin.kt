package com.bysonic.tglock

import android.app.Activity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.Plugin

@InvokeArg
class TunnelArgs {
    var enabled: Boolean = false
}

/** Called by Rust only; no WebView JavaScript interface or exported component. */
@TauriPlugin
class TunnelPlugin(private val activity: Activity) : Plugin(activity) {
    @Command
    fun setEnabled(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(TunnelArgs::class.java)
            if (args.enabled) TunnelService.start(activity) else TunnelService.stop(activity)
            invoke.resolve()
        } catch (error: Exception) {
            invoke.reject(error.message ?: "Cannot change tunnel foreground service")
        }
    }
}
