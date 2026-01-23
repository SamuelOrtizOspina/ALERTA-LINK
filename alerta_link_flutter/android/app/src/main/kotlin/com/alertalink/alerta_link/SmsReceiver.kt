package com.alertalink.alerta_link

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log

/**
 * SmsReceiver - BroadcastReceiver para detectar SMS entrantes
 *
 * Funciona incluso cuando la app está cerrada o el teléfono bloqueado.
 * NO es un servicio en background permanente - solo se activa al recibir SMS.
 *
 * Android permite esto porque:
 * 1. BroadcastReceiver se ejecuta brevemente (~10 segundos máximo)
 * 2. No consume batería cuando no hay SMS
 * 3. Es el método estándar para interceptar SMS
 */
class SmsReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "SmsReceiver"

        // Regex para detectar URLs en el mensaje
        private val URL_REGEX = Regex(
            """(https?://[^\s<>"{}|\\^`\[\]]+)|(www\.[^\s<>"{}|\\^`\[\]]+)|([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(/[^\s]*)?)""",
            RegexOption.IGNORE_CASE
        )
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) {
            return
        }

        Log.d(TAG, "SMS recibido - iniciando análisis")

        try {
            // Extraer mensajes SMS del intent
            val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)

            if (messages.isNullOrEmpty()) {
                Log.w(TAG, "No se pudieron extraer mensajes del intent")
                return
            }

            // Concatenar el cuerpo del mensaje (puede venir en partes)
            val fullMessage = StringBuilder()
            var sender: String? = null

            for (sms in messages) {
                fullMessage.append(sms.messageBody ?: "")
                if (sender == null) {
                    sender = sms.originatingAddress
                }
            }

            val messageText = fullMessage.toString()
            Log.d(TAG, "Mensaje de: $sender")
            Log.d(TAG, "Contenido: ${messageText.take(100)}...") // Solo log primeros 100 chars

            // Buscar URLs en el mensaje
            val urls = extractUrls(messageText)

            if (urls.isEmpty()) {
                Log.d(TAG, "No se encontraron URLs en el mensaje")
                return
            }

            Log.d(TAG, "URLs encontradas: ${urls.size}")

            // Analizar cada URL encontrada
            for (url in urls) {
                Log.d(TAG, "Analizando URL: $url")
                SmsAnalyzer.analyzeUrl(context, url, sender ?: "Desconocido", messageText)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error procesando SMS: ${e.message}", e)
        }
    }

    /**
     * Extrae todas las URLs del texto del mensaje
     */
    private fun extractUrls(text: String): List<String> {
        val urls = mutableListOf<String>()

        URL_REGEX.findAll(text).forEach { match ->
            var url = match.value.trim()

            // Normalizar URL
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                url = "https://$url"
            }

            // Remover caracteres finales no válidos
            url = url.trimEnd('.', ',', '!', '?', ')', ']', '}', '>', '"', '\'')

            if (url.isNotEmpty() && isValidUrl(url)) {
                urls.add(url)
            }
        }

        return urls.distinct() // Eliminar duplicados
    }

    /**
     * Valida que la URL tenga un formato básico correcto
     */
    private fun isValidUrl(url: String): Boolean {
        return try {
            val uri = java.net.URI(url)
            val host = uri.host
            host != null && host.contains(".") && host.length > 3
        } catch (e: Exception) {
            false
        }
    }
}
