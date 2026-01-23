/// Modelos de datos para el analisis de URLs

/// Resultado del analisis de una URL
class UrlAnalysis {
  final String url;
  final String normalizedUrl;
  final int score;
  final RiskLevel riskLevel;
  final String modelUsed;
  final String modeUsed;
  final List<Signal> signals;
  final List<String> recommendations;
  final DateTime analyzedAt;
  final String? sourcePackage;

  UrlAnalysis({
    required this.url,
    required this.normalizedUrl,
    required this.score,
    required this.riskLevel,
    required this.modelUsed,
    required this.modeUsed,
    required this.signals,
    required this.recommendations,
    required this.analyzedAt,
    this.sourcePackage,
  });

  factory UrlAnalysis.fromJson(Map<String, dynamic> json) {
    return UrlAnalysis(
      url: json['url'] ?? '',
      normalizedUrl: json['normalized_url'] ?? json['url'] ?? '',
      score: json['score'] ?? 0,
      riskLevel: RiskLevel.fromString(json['risk_level'] ?? 'UNKNOWN'),
      modelUsed: json['model_used'] ?? 'ml',
      modeUsed: json['mode_used'] ?? 'online',
      signals: (json['signals'] as List<dynamic>?)
              ?.map((s) => Signal.fromJson(s))
              .toList() ??
          [],
      recommendations:
          List<String>.from(json['recommendations'] ?? []),
      analyzedAt: DateTime.tryParse(json['timestamps']?['completed_at'] ?? '') ??
          DateTime.now(),
      sourcePackage: json['source_package'],
    );
  }

  Map<String, dynamic> toJson() => {
        'url': url,
        'normalized_url': normalizedUrl,
        'score': score,
        'risk_level': riskLevel.name,
        'model_used': modelUsed,
        'mode_used': modeUsed,
        'signals': signals.map((s) => s.toJson()).toList(),
        'recommendations': recommendations,
        'analyzed_at': analyzedAt.toIso8601String(),
        'source_package': sourcePackage,
      };

  /// Nombre del modelo para mostrar
  String get modelDisplayName {
    switch (modelUsed) {
      case 'ml':
        return 'Machine Learning';
      case 'heuristic':
        return 'Heuristico';
      default:
        return modelUsed;
    }
  }

  /// Determina el color del semaforo segun el nivel de riesgo
  String get trafficLightColor {
    switch (riskLevel) {
      case RiskLevel.safe:
        return 'green';
      case RiskLevel.low:
        return 'yellow';
      case RiskLevel.medium:
        return 'orange';
      case RiskLevel.high:
        return 'red';
      default:
        return 'grey';
    }
  }
}

/// Nivel de riesgo de una URL
enum RiskLevel {
  safe,
  low,
  medium,
  high,
  unknown;

  static RiskLevel fromString(String value) {
    switch (value.toUpperCase()) {
      case 'SAFE':
        return RiskLevel.safe;
      case 'LOW':
        return RiskLevel.low;
      case 'MEDIUM':
        return RiskLevel.medium;
      case 'HIGH':
        return RiskLevel.high;
      default:
        return RiskLevel.unknown;
    }
  }

  String get displayName {
    switch (this) {
      case RiskLevel.safe:
        return 'Seguro';
      case RiskLevel.low:
        return 'Bajo';
      case RiskLevel.medium:
        return 'Medio';
      case RiskLevel.high:
        return 'Alto';
      default:
        return 'Desconocido';
    }
  }
}

/// Senal detectada durante el analisis
class Signal {
  final String id;
  final String message;
  final String severity;
  final int weight;
  final String category;

  Signal({
    required this.id,
    required this.message,
    required this.severity,
    required this.weight,
    required this.category,
  });

  factory Signal.fromJson(Map<String, dynamic> json) {
    return Signal(
      id: json['id'] ?? '',
      message: json['message'] ?? '',
      severity: json['severity'] ?? 'info',
      weight: json['weight'] ?? 0,
      category: json['category'] ?? 'other',
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'message': message,
        'severity': severity,
        'weight': weight,
        'category': category,
      };

  bool get isPositive => weight < 0;
  bool get isNegative => weight > 0;
}

/// Notificacion recibida desde Kotlin
class NotificationData {
  final String url;
  final String packageName;
  final String? title;
  final String? body;
  final DateTime receivedAt;

  NotificationData({
    required this.url,
    required this.packageName,
    this.title,
    this.body,
    required this.receivedAt,
  });

  factory NotificationData.fromMap(Map<dynamic, dynamic> map) {
    return NotificationData(
      url: map['url'] ?? '',
      packageName: map['package'] ?? '',
      title: map['title'],
      body: map['body'],
      receivedAt: DateTime.now(),
    );
  }
}
