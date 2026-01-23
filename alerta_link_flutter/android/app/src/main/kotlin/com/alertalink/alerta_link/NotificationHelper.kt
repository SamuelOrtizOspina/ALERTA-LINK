package com.alertalink.alerta_link

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import android.util.Log

/**
 * NotificationHelper - Muestra notificaciones de alerta de phishing
 *
 * Crea notificaciones de alta prioridad para alertar al usuario
 * cuando se detecta una URL sospechosa en un SMS.
 */
object NotificationHelper {

    private const val TAG = "NotificationHelper"

    // Canales de notificación
    private const val CHANNEL_ID_HIGH = "alerta_link_high"
    private const val CHANNEL_ID_MEDIUM = "alerta_link_medium"

    // IDs de notificación
    private var notificationId = 1000

    /**
     * Inicializa los canales de notificación (requerido para Android 8+)
     */
    fun createNotificationChannels(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

            // Canal para alertas de alto riesgo
            val highChannel = NotificationChannel(
                CHANNEL_ID_HIGH,
                "Alertas de Alto Riesgo",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notificaciones de URLs con alto riesgo de phishing"
                enableLights(true)
                lightColor = Color.RED
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 500, 200, 500)
                setShowBadge(true)
            }

            // Canal para alertas de riesgo medio
            val mediumChannel = NotificationChannel(
                CHANNEL_ID_MEDIUM,
                "Alertas de Riesgo Medio",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Notificaciones de URLs con riesgo moderado"
                enableLights(true)
                lightColor = Color.YELLOW
                setShowBadge(true)
            }

            notificationManager.createNotificationChannel(highChannel)
            notificationManager.createNotificationChannel(mediumChannel)

            Log.d(TAG, "Canales de notificación creados")
        }
    }

    /**
     * Muestra una notificación de alerta de phishing
     *
     * @param context Contexto de Android
     * @param url URL detectada
     * @param score Puntuación de riesgo (0-100)
     * @param riskLevel Nivel de riesgo (LOW, MEDIUM, HIGH)
     * @param sender Remitente del SMS
     * @param signalCount Número de señales detectadas
     */
    fun showPhishingAlert(
        context: Context,
        url: String,
        score: Int,
        riskLevel: String,
        sender: String,
        signalCount: Int
    ) {
        try {
            // Asegurar que los canales existen
            createNotificationChannels(context)

            // Seleccionar canal y configuración según el nivel de riesgo
            val (channelId, icon, color, title) = when (riskLevel) {
                "HIGH" -> Quadruple(
                    CHANNEL_ID_HIGH,
                    android.R.drawable.ic_dialog_alert,
                    Color.RED,
                    "⚠️ ALERTA: URL Peligrosa Detectada"
                )
                else -> Quadruple(
                    CHANNEL_ID_MEDIUM,
                    android.R.drawable.ic_dialog_info,
                    Color.rgb(255, 152, 0), // Naranja
                    "⚡ Advertencia: URL Sospechosa"
                )
            }

            // Crear intent para abrir la app al tocar la notificación
            val intent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                putExtra("url", url)
                putExtra("score", score)
                putExtra("risk_level", riskLevel)
                putExtra("from_notification", true)
            }

            val pendingIntent = PendingIntent.getActivity(
                context,
                notificationId,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            // Truncar URL si es muy larga
            val displayUrl = if (url.length > 50) {
                url.take(47) + "..."
            } else {
                url
            }

            // Crear el contenido de la notificación
            val contentText = buildString {
                append("De: $sender\n")
                append("URL: $displayUrl\n")
                append("Riesgo: $score/100")
                if (signalCount > 0) {
                    append(" ($signalCount señales)")
                }
            }

            // Construir la notificación
            val builder = NotificationCompat.Builder(context, channelId)
                .setSmallIcon(icon)
                .setContentTitle(title)
                .setContentText("Riesgo: $score/100 - Toca para más detalles")
                .setStyle(NotificationCompat.BigTextStyle().bigText(contentText))
                .setPriority(if (riskLevel == "HIGH") NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
                .setColor(color)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)

            // Agregar vibración para alto riesgo
            if (riskLevel == "HIGH") {
                builder.setVibrate(longArrayOf(0, 500, 200, 500))
            }

            // Mostrar la notificación
            with(NotificationManagerCompat.from(context)) {
                try {
                    notify(notificationId++, builder.build())
                    Log.d(TAG, "Notificación mostrada: $riskLevel, score=$score")
                } catch (e: SecurityException) {
                    Log.e(TAG, "Sin permiso para mostrar notificaciones: ${e.message}")
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error mostrando notificación: ${e.message}", e)
        }
    }

    /**
     * Helper data class para agrupar configuración de notificación
     */
    private data class Quadruple<A, B, C, D>(
        val first: A,
        val second: B,
        val third: C,
        val fourth: D
    )
}
