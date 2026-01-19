package com.alertalink.alerta_link

import android.app.Notification
import android.os.Handler
import android.os.Looper
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import io.flutter.plugin.common.MethodChannel
import java.util.regex.Pattern

/**
 * PushListenerService - Escucha notificaciones del sistema
 *
 * RESPONSABILIDAD UNICA:
 * - Escuchar notificaciones
 * - Extraer URLs del texto
 * - Enviar a Flutter via Platform Channel
 *
 * NO HACE:
 * - Analisis de URLs
 * - Llamadas a APIs
 * - Decisiones de seguridad
 *
 * Flutter decide, Kotlin obedece.
 */
class PushListenerService : NotificationListenerService() {

    companion object {
        private const val TAG = "PushListenerService"

        // Patron para detectar URLs
        private val URL_PATTERN = Pattern.compile(
            "(https?://[\\w\\-._~:/?#\\[\\]@!\$&'()*+,;=%]+)",
            Pattern.CASE_INSENSITIVE
        )

        // Referencia para cancelar notificaciones
        private var instance: PushListenerService? = null

        /**
         * Cancela una notificacion por su key
         * Llamado por Flutter via Platform Channel
         */
        fun cancelNotification(key: String) {
            try {
                instance?.cancelNotification(key)
                Log.d(TAG, "Notificacion cancelada: $key")
            } catch (e: Exception) {
                Log.e(TAG, "Error cancelando notificacion: ${e.message}")
            }
        }
    }

    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onCreate() {
        super.onCreate()
        instance = this
        Log.d(TAG, "PushListenerService creado")
    }

    override fun onDestroy() {
        super.onDestroy()
        instance = null
        Log.d(TAG, "PushListenerService destruido")
    }

    /**
     * Llamado cuando llega una nueva notificacion
     */
    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        sbn ?: return

        // Ignorar notificaciones propias
        if (sbn.packageName == packageName) return

        try {
            val notification = sbn.notification
            val extras = notification.extras

            // Extraer texto de la notificacion
            val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
            val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
            val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: ""

            // Combinar todo el texto
            val fullText = "$title $text $bigText"

            // Buscar URLs en el texto
            val urls = extractUrls(fullText)

            if (urls.isNotEmpty()) {
                Log.d(TAG, "URLs detectadas en notificacion de ${sbn.packageName}: $urls")

                // Enviar cada URL a Flutter
                for (url in urls) {
                    sendUrlToFlutter(
                        url = url,
                        packageName = sbn.packageName,
                        title = title,
                        body = text,
                        notificationKey = sbn.key
                    )
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error procesando notificacion: ${e.message}")
        }
    }

    /**
     * Extrae URLs del texto usando regex
     */
    private fun extractUrls(text: String): List<String> {
        val urls = mutableListOf<String>()
        val matcher = URL_PATTERN.matcher(text)

        while (matcher.find()) {
            val url = matcher.group(1)
            if (url != null && isValidUrl(url)) {
                urls.add(url)
            }
        }

        return urls.distinct()
    }

    /**
     * Valida que la URL sea valida y no sea de dominios conocidos seguros
     */
    private fun isValidUrl(url: String): Boolean {
        // Filtrar URLs muy cortas
        if (url.length < 10) return false

        // Filtrar URLs de Google Play (spam comun)
        if (url.contains("play.google.com")) return false

        // Filtrar URLs de actualizaciones del sistema
        if (url.contains("android.com/update")) return false

        return true
    }

    /**
     * Envia la URL detectada a Flutter via Platform Channel
     *
     * Solo envia datos, NO toma decisiones.
     * Flutter decidira si es phishing o no.
     */
    private fun sendUrlToFlutter(
        url: String,
        packageName: String,
        title: String,
        body: String,
        notificationKey: String
    ) {
        mainHandler.post {
            try {
                MainActivity.methodChannel?.invokeMethod(
                    "onUrlDetected",
                    mapOf(
                        "url" to url,
                        "package" to packageName,
                        "title" to title,
                        "body" to body,
                        "key" to notificationKey
                    )
                )
                Log.d(TAG, "URL enviada a Flutter: $url")
            } catch (e: Exception) {
                Log.e(TAG, "Error enviando a Flutter: ${e.message}")
            }
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        // No hacemos nada cuando se elimina una notificacion
    }
}
