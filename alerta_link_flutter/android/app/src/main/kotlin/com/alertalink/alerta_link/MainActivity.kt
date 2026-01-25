package com.alertalink.alerta_link

import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.text.TextUtils
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * MainActivity - Punto de entrada de la app
 *
 * Responsabilidad: Solo configurar el Platform Channel
 * NO hace analisis, NO llama APIs, NO toma decisiones
 */
class MainActivity : FlutterActivity() {

    companion object {
        const val CHANNEL = "push_channel"
        var methodChannel: MethodChannel? = null
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        methodChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)

        methodChannel?.setMethodCallHandler { call, result ->
            when (call.method) {
                "check_permission" -> {
                    // Verificar si tiene permiso de NotificationListener
                    val hasPermission = isNotificationServiceEnabled()
                    result.success(hasPermission)
                }

                "open_settings" -> {
                    // Abrir configuracion de acceso a notificaciones
                    openNotificationSettings()
                    result.success(true)
                }

                "block_notification" -> {
                    // Kotlin recibe orden de Flutter para bloquear
                    val key = call.argument<String>("key")
                    if (key != null) {
                        PushListenerService.cancelNotification(key)
                        result.success(true)
                    } else {
                        result.error("INVALID_KEY", "Notification key is null", null)
                    }
                }

                "allow_notification" -> {
                    // No hacer nada, solo confirmar
                    result.success(true)
                }

                else -> {
                    result.notImplemented()
                }
            }
        }
    }

    /**
     * Verifica si el servicio de notificaciones esta habilitado
     */
    private fun isNotificationServiceEnabled(): Boolean {
        val pkgName = packageName
        val flat = Settings.Secure.getString(
            contentResolver,
            "enabled_notification_listeners"
        )
        if (!TextUtils.isEmpty(flat)) {
            val names = flat.split(":".toRegex())
            for (name in names) {
                val cn = ComponentName.unflattenFromString(name)
                if (cn != null && TextUtils.equals(pkgName, cn.packageName)) {
                    return true
                }
            }
        }
        return false
    }

    /**
     * Abre la configuracion de acceso a notificaciones
     */
    private fun openNotificationSettings() {
        val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
        startActivity(intent)
    }
}
