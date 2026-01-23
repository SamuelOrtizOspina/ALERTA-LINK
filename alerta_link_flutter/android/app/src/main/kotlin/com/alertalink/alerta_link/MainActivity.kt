package com.alertalink.alerta_link

import android.Manifest
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.TextUtils
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * MainActivity - Punto de entrada de la app ALERTA-LINK
 *
 * Responsabilidades:
 * - Configurar Platform Channels para comunicación Flutter <-> Android
 * - Manejar permisos de SMS y notificaciones
 * - Procesar intents de URLs compartidas
 * - Inicializar canales de notificación
 */
class MainActivity : FlutterActivity() {

    companion object {
        private const val TAG = "MainActivity"

        // Canales de comunicación
        const val CHANNEL = "push_channel"
        const val SMS_CHANNEL = "sms_channel"

        // Códigos de permisos
        private const val SMS_PERMISSION_CODE = 1001
        private const val NOTIFICATION_PERMISSION_CODE = 1002

        // Referencia al channel para que otros componentes puedan usarlo
        var methodChannel: MethodChannel? = null
        var smsChannel: MethodChannel? = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Inicializar canales de notificación
        NotificationHelper.createNotificationChannels(this)

        // Procesar intent si la app fue abierta desde una notificación
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    /**
     * Procesa el intent de entrada (notificación o URL compartida)
     */
    private fun handleIntent(intent: Intent?) {
        intent?.let {
            // Si viene de una notificación de phishing
            if (it.getBooleanExtra("from_notification", false)) {
                val url = it.getStringExtra("url") ?: return
                val score = it.getIntExtra("score", 0)
                val riskLevel = it.getStringExtra("risk_level") ?: "UNKNOWN"

                Log.d(TAG, "App abierta desde notificación: $url")

                // Enviar a Flutter cuando el engine esté listo
                flutterEngine?.dartExecutor?.let { executor ->
                    MethodChannel(executor.binaryMessenger, SMS_CHANNEL).invokeMethod(
                        "notification_opened",
                        mapOf(
                            "url" to url,
                            "score" to score,
                            "risk_level" to riskLevel
                        )
                    )
                }
            }

            // Si viene de compartir URL desde otra app
            if (it.action == Intent.ACTION_SEND && it.type == "text/plain") {
                val sharedText = it.getStringExtra(Intent.EXTRA_TEXT)
                if (!sharedText.isNullOrEmpty()) {
                    Log.d(TAG, "URL compartida recibida: $sharedText")
                    flutterEngine?.dartExecutor?.let { executor ->
                        MethodChannel(executor.binaryMessenger, CHANNEL).invokeMethod(
                            "shared_url",
                            sharedText
                        )
                    }
                }
            }
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        // Canal principal (push notifications)
        methodChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
        methodChannel?.setMethodCallHandler { call, result ->
            when (call.method) {
                "check_permission" -> {
                    val hasPermission = isNotificationServiceEnabled()
                    result.success(hasPermission)
                }
                "open_settings" -> {
                    openNotificationSettings()
                    result.success(true)
                }
                "block_notification" -> {
                    val key = call.argument<String>("key")
                    if (key != null) {
                        PushListenerService.cancelNotification(key)
                        result.success(true)
                    } else {
                        result.error("INVALID_KEY", "Notification key is null", null)
                    }
                }
                "allow_notification" -> {
                    result.success(true)
                }
                else -> result.notImplemented()
            }
        }

        // Canal de SMS
        smsChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, SMS_CHANNEL)
        smsChannel?.setMethodCallHandler { call, result ->
            when (call.method) {

                // Verificar si tiene permisos de SMS
                "check_sms_permission" -> {
                    val hasPermission = hasSmsPermissions()
                    result.success(hasPermission)
                }

                // Solicitar permisos de SMS
                "request_sms_permission" -> {
                    requestSmsPermissions()
                    result.success(true)
                }

                // Verificar si tiene permiso de notificaciones (Android 13+)
                "check_notification_permission" -> {
                    val hasPermission = hasNotificationPermission()
                    result.success(hasPermission)
                }

                // Solicitar permiso de notificaciones (Android 13+)
                "request_notification_permission" -> {
                    requestNotificationPermission()
                    result.success(true)
                }

                // Obtener estado completo de permisos
                "get_permissions_status" -> {
                    val status = mapOf(
                        "sms_read" to hasSmsPermissions(),
                        "sms_receive" to hasReceiveSmsPermission(),
                        "notification" to hasNotificationPermission(),
                        "all_granted" to (hasSmsPermissions() && hasNotificationPermission())
                    )
                    result.success(status)
                }

                // Abrir configuración de la app
                "open_app_settings" -> {
                    openAppSettings()
                    result.success(true)
                }

                else -> result.notImplemented()
            }
        }
    }

    // ==================== PERMISOS SMS ====================

    /**
     * Verifica si tiene permisos de lectura de SMS
     */
    private fun hasSmsPermissions(): Boolean {
        val readSms = ContextCompat.checkSelfPermission(this, Manifest.permission.READ_SMS)
        val receiveSms = ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS)
        return readSms == PackageManager.PERMISSION_GRANTED &&
                receiveSms == PackageManager.PERMISSION_GRANTED
    }

    /**
     * Verifica específicamente el permiso RECEIVE_SMS
     */
    private fun hasReceiveSmsPermission(): Boolean {
        return ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS) ==
                PackageManager.PERMISSION_GRANTED
    }

    /**
     * Solicita permisos de SMS al usuario
     */
    private fun requestSmsPermissions() {
        ActivityCompat.requestPermissions(
            this,
            arrayOf(
                Manifest.permission.READ_SMS,
                Manifest.permission.RECEIVE_SMS
            ),
            SMS_PERMISSION_CODE
        )
    }

    // ==================== PERMISOS NOTIFICACIONES ====================

    /**
     * Verifica si tiene permiso de notificaciones (Android 13+)
     */
    private fun hasNotificationPermission(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true // Antes de Android 13, no se necesita permiso explícito
        }
    }

    /**
     * Solicita permiso de notificaciones (Android 13+)
     */
    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                NOTIFICATION_PERMISSION_CODE
            )
        }
    }

    // ==================== NOTIFICATION LISTENER ====================

    /**
     * Verifica si el servicio de notificaciones está habilitado
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
     * Abre la configuración de acceso a notificaciones
     */
    private fun openNotificationSettings() {
        val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
        startActivity(intent)
    }

    /**
     * Abre la configuración de la app
     */
    private fun openAppSettings() {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.fromParts("package", packageName, null)
        }
        startActivity(intent)
    }

    // ==================== CALLBACK DE PERMISOS ====================

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)

        when (requestCode) {
            SMS_PERMISSION_CODE -> {
                val granted = grantResults.isNotEmpty() &&
                        grantResults.all { it == PackageManager.PERMISSION_GRANTED }
                Log.d(TAG, "Permisos SMS: ${if (granted) "CONCEDIDOS" else "DENEGADOS"}")

                smsChannel?.invokeMethod(
                    "sms_permission_result",
                    mapOf("granted" to granted)
                )
            }

            NOTIFICATION_PERMISSION_CODE -> {
                val granted = grantResults.isNotEmpty() &&
                        grantResults[0] == PackageManager.PERMISSION_GRANTED
                Log.d(TAG, "Permiso notificaciones: ${if (granted) "CONCEDIDO" else "DENEGADO"}")

                smsChannel?.invokeMethod(
                    "notification_permission_result",
                    mapOf("granted" to granted)
                )
            }
        }
    }
}
