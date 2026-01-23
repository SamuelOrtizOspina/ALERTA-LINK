package com.alertalink.alerta_link

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

/**
 * SmsAnalyzer - Analiza URLs enviándolas al backend de ALERTA-LINK
 *
 * Ejecuta el análisis en un thread separado para no bloquear el BroadcastReceiver.
 * Muestra notificaciones si el riesgo es MEDIUM o HIGH.
 */
object SmsAnalyzer {

    private const val TAG = "SmsAnalyzer"

    // URL del backend de ALERTA-LINK
    private const val API_URL = "https://api.samuelortizospina.me/analyze"

    // Timeout para la conexión (en milisegundos)
    private const val CONNECT_TIMEOUT = 10000
    private const val READ_TIMEOUT = 15000

    // Executor para operaciones en background
    private val executor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    /**
     * Analiza una URL enviándola al backend
     *
     * @param context Contexto de Android
     * @param urlToAnalyze URL a analizar
     * @param sender Remitente del SMS
     * @param originalMessage Mensaje original (para contexto)
     */
    fun analyzeUrl(context: Context, urlToAnalyze: String, sender: String, originalMessage: String) {
        executor.execute {
            try {
                Log.d(TAG, "Iniciando análisis de: $urlToAnalyze")

                val result = callBackendApi(urlToAnalyze)

                if (result != null) {
                    val score = result.optInt("score", -1)
                    val riskLevel = result.optString("risk_level", "UNKNOWN")
                    val signals = result.optJSONArray("signals")

                    Log.d(TAG, "Resultado: score=$score, risk=$riskLevel")

                    // Notificar a Flutter (si está activo)
                    notifyFlutter(urlToAnalyze, score, riskLevel, sender)

                    // Mostrar notificación si es MEDIUM o HIGH
                    if (riskLevel == "MEDIUM" || riskLevel == "HIGH") {
                        mainHandler.post {
                            NotificationHelper.showPhishingAlert(
                                context = context,
                                url = urlToAnalyze,
                                score = score,
                                riskLevel = riskLevel,
                                sender = sender,
                                signalCount = signals?.length() ?: 0
                            )
                        }
                    }
                } else {
                    Log.e(TAG, "No se pudo obtener resultado del backend")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error analizando URL: ${e.message}", e)
            }
        }
    }

    /**
     * Llama al API del backend para analizar la URL
     */
    private fun callBackendApi(urlToAnalyze: String): JSONObject? {
        var connection: HttpURLConnection? = null

        try {
            val url = URL(API_URL)
            connection = url.openConnection() as HttpURLConnection

            connection.apply {
                requestMethod = "POST"
                connectTimeout = CONNECT_TIMEOUT
                readTimeout = READ_TIMEOUT
                doOutput = true
                doInput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/json")
                setRequestProperty("User-Agent", "ALERTA-LINK-Android/1.2.0")
            }

            // Crear JSON body
            val jsonBody = JSONObject().apply {
                put("url", urlToAnalyze)
                put("source", "sms_auto")
            }

            // Enviar request
            OutputStreamWriter(connection.outputStream, "UTF-8").use { writer ->
                writer.write(jsonBody.toString())
                writer.flush()
            }

            // Leer response
            val responseCode = connection.responseCode
            Log.d(TAG, "Response code: $responseCode")

            if (responseCode == HttpURLConnection.HTTP_OK) {
                val response = BufferedReader(InputStreamReader(connection.inputStream)).use { reader ->
                    reader.readText()
                }
                return JSONObject(response)
            } else {
                // Leer error
                val errorStream = connection.errorStream
                if (errorStream != null) {
                    val error = BufferedReader(InputStreamReader(errorStream)).use { it.readText() }
                    Log.e(TAG, "Error response: $error")
                }
                return null
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error llamando API: ${e.message}", e)
            return null
        } finally {
            connection?.disconnect()
        }
    }

    /**
     * Notifica a Flutter sobre el resultado del análisis
     * (Solo funciona si la app está abierta)
     */
    private fun notifyFlutter(url: String, score: Int, riskLevel: String, sender: String) {
        mainHandler.post {
            try {
                MainActivity.smsChannel?.invokeMethod(
                    "sms_url_analyzed",
                    mapOf(
                        "url" to url,
                        "score" to score,
                        "risk_level" to riskLevel,
                        "sender" to sender,
                        "source" to "sms_auto"
                    )
                )
            } catch (e: Exception) {
                Log.w(TAG, "No se pudo notificar a Flutter (app posiblemente cerrada): ${e.message}")
            }
        }
    }
}
