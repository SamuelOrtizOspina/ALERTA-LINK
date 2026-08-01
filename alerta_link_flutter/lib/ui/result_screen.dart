import 'package:flutter/material.dart';
import '../models/url_analysis.dart';

/// Pantalla de resultado del analisis (semaforo)
class ResultScreen extends StatelessWidget {
  final UrlAnalysis analysis;

  const ResultScreen({super.key, required this.analysis});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Resultado'),
        centerTitle: true,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Semaforo
            _buildTrafficLight(),
            const SizedBox(height: 24),

            // URL analizada
            _buildUrlCard(),
            const SizedBox(height: 16),

            // Score y nivel
            _buildScoreCard(),
            const SizedBox(height: 16),

            // Senales detectadas
            _buildSignalsCard(),
            const SizedBox(height: 16),

            // Recomendaciones
            _buildRecommendationsCard(),
            const SizedBox(height: 16),

            // Info del analisis
            _buildInfoCard(),
          ],
        ),
      ),
    );
  }

  Widget _buildTrafficLight() {
    final color = _getRiskColor(analysis.riskLevel);
    final icon = _getRiskIcon(analysis.riskLevel);

    return Card(
      elevation: 4,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: Container(
        padding: const EdgeInsets.all(32),
        decoration: BoxDecoration(
          color: color.withOpacity(0.1),
          borderRadius: BorderRadius.circular(16),
        ),
        child: Column(
          children: [
            // Icono grande
            Container(
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                color: color,
                shape: BoxShape.circle,
                boxShadow: [
                  BoxShadow(
                    color: color.withOpacity(0.4),
                    blurRadius: 20,
                    spreadRadius: 5,
                  ),
                ],
              ),
              child: Icon(icon, color: Colors.white, size: 48),
            ),
            const SizedBox(height: 16),

            // Nivel de riesgo
            Text(
              analysis.riskLevel == RiskLevel.safe
                  ? 'Seguro'
                  : 'Riesgo ${analysis.riskLevel.displayName}',
              style: TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.bold,
                color: color,
              ),
            ),
            const SizedBox(height: 8),

            // Score
            Text(
              'Puntuacion: ${analysis.score}/100',
              style: const TextStyle(fontSize: 16, color: Colors.grey),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildUrlCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'URL Analizada',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              analysis.url,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 14,
              ),
            ),
            if (analysis.sourcePackage != null) ...[
              const SizedBox(height: 8),
              Text(
                'Fuente: ${analysis.sourcePackage}',
                style: TextStyle(
                  fontSize: 12,
                  color: Colors.grey.shade600,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildScoreCard() {
    final color = _getRiskColor(analysis.riskLevel);

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            // Indicador circular
            SizedBox(
              width: 60,
              height: 60,
              child: Stack(
                fit: StackFit.expand,
                children: [
                  CircularProgressIndicator(
                    value: analysis.score / 100,
                    backgroundColor: Colors.grey.shade200,
                    color: color,
                    strokeWidth: 6,
                  ),
                  Center(
                    child: Text(
                      '${analysis.score}',
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        color: color,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 16),

            // Detalles
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Modo: ${analysis.modeUsed}',
                    style: const TextStyle(fontWeight: FontWeight.w500),
                  ),
                  Text(
                    '${analysis.signals.length} senales detectadas',
                    style: TextStyle(color: Colors.grey.shade600),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSignalsCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.radar, size: 20),
                const SizedBox(width: 8),
                Text(
                  'Senales Detectadas (${analysis.signals.length})',
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 16,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            if (analysis.signals.isEmpty)
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 8),
                child: Text(
                  'No se detectaron senales de riesgo',
                  style: TextStyle(color: Colors.green, fontStyle: FontStyle.italic),
                ),
              )
            else
              ...analysis.signals.map((signal) => _buildSignalItem(signal)),
          ],
        ),
      ),
    );
  }

  Widget _buildSignalItem(Signal signal) {
    // Tres tipos de senal:
    // - Positiva (peso < 0): bonificacion de confianza (verde)
    // - Informativa (peso == 0): solo contexto, no suma al score (gris)
    // - De riesgo (peso > 0): usa el color segun su severidad
    final bool isPositive = signal.weight < 0;
    final bool isInformational = signal.weight == 0;

    final Color color;
    final IconData icon;
    final String badgeText;
    if (isPositive) {
      color = Colors.green;
      icon = Icons.check_circle;
      badgeText = 'CONFIANZA';
    } else if (isInformational) {
      color = Colors.blueGrey;
      icon = Icons.info_outline;
      badgeText = 'INFORMATIVA';
    } else {
      color = _getSeverityColor(signal.severity);
      icon = _getSeverityIcon(signal.severity);
      badgeText = signal.severity.toUpperCase();
    }

    return Container(
      margin: const EdgeInsets.symmetric(vertical: 4),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border(left: BorderSide(color: color, width: 3)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: color, size: 20),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Nombre de la senal detectada (ej: NO_HTTPS, BRAND_IMPERSONATION)
                if (signal.id.isNotEmpty)
                  Text(
                    signal.id,
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.bold,
                      color: color,
                      letterSpacing: 0.3,
                    ),
                  ),
                // Explicacion en lenguaje sencillo
                if (signal.message.isNotEmpty) ...[
                  const SizedBox(height: 2),
                  Text(
                    signal.message,
                    style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w400),
                  ),
                ],
                const SizedBox(height: 6),
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                      decoration: BoxDecoration(
                        color: color.withOpacity(0.2),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Text(
                        badgeText,
                        style: TextStyle(fontSize: 10, color: color, fontWeight: FontWeight.bold),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Text(
                      isInformational
                          ? 'No suma al puntaje'
                          : 'Peso: ${signal.weight > 0 ? '+' : ''}${signal.weight}',
                      style: TextStyle(fontSize: 12, color: Colors.grey.shade600),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Color _getSeverityColor(String severity) {
    switch (severity.toUpperCase()) {
      case 'HIGH':
      case 'CRITICAL':
        return Colors.red;
      case 'MEDIUM':
        return Colors.orange;
      case 'LOW':
        return Colors.yellow.shade700;
      default:
        return Colors.blue;
    }
  }

  IconData _getSeverityIcon(String severity) {
    switch (severity.toUpperCase()) {
      case 'HIGH':
      case 'CRITICAL':
        return Icons.error;
      case 'MEDIUM':
        return Icons.warning;
      case 'LOW':
        return Icons.info;
      default:
        return Icons.help_outline;
    }
  }

  Widget _buildRecommendationsCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Recomendaciones',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
            const SizedBox(height: 12),
            ...analysis.recommendations.map(
              (rec) => Padding(
                padding: const EdgeInsets.symmetric(vertical: 4),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(Icons.arrow_right, size: 20),
                    const SizedBox(width: 4),
                    Expanded(child: Text(rec)),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoCard() {
    return Card(
      color: Colors.grey.shade100,
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Row(
          children: [
            Icon(Icons.access_time, size: 16, color: Colors.grey.shade600),
            const SizedBox(width: 8),
            Text(
              'Analizado: ${_formatDateTime(analysis.analyzedAt)}',
              style: TextStyle(
                fontSize: 12,
                color: Colors.grey.shade600,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Color _getRiskColor(RiskLevel level) {
    switch (level) {
      case RiskLevel.safe:
        return Colors.green;
      case RiskLevel.low:
        return Colors.yellow.shade700;
      case RiskLevel.medium:
        return Colors.orange;
      case RiskLevel.high:
        return Colors.red;
      default:
        return Colors.grey;
    }
  }

  IconData _getRiskIcon(RiskLevel level) {
    switch (level) {
      case RiskLevel.safe:
        return Icons.check_circle;
      case RiskLevel.low:
        return Icons.info;
      case RiskLevel.medium:
        return Icons.warning;
      case RiskLevel.high:
        return Icons.dangerous;
      default:
        return Icons.help;
    }
  }

  String _formatDateTime(DateTime dt) {
    return '${dt.day}/${dt.month}/${dt.year} ${dt.hour}:${dt.minute.toString().padLeft(2, '0')}';
  }
}
