import 'package:flutter/services.dart';
import 'package:flutter/foundation.dart';

/// SmsService - Maneja la comunicación con Android para detección de SMS
///
/// Funcionalidades:
/// - Verificar y solicitar permisos de SMS
/// - Recibir notificaciones cuando se detecta phishing en SMS
/// - Manejar eventos de Android
class SmsService {
  static const MethodChannel _channel = MethodChannel('sms_channel');

  // Callbacks para eventos de SMS
  static Function(String url, int score, String riskLevel, String sender)?
      onSmsUrlAnalyzed;
  static Function(String url, int score, String riskLevel)? onNotificationOpened;
  static Function(bool granted)? onSmsPermissionResult;
  static Function(bool granted)? onNotificationPermissionResult;

  /// Inicializa el servicio y configura los listeners
  static void initialize() {
    _channel.setMethodCallHandler(_handleMethodCall);
    debugPrint('SmsService: Inicializado');
  }

  /// Maneja las llamadas desde Android
  static Future<dynamic> _handleMethodCall(MethodCall call) async {
    debugPrint('SmsService: Método recibido: ${call.method}');

    switch (call.method) {
      case 'sms_url_analyzed':
        // URL detectada y analizada automáticamente desde SMS
        final args = call.arguments as Map<dynamic, dynamic>;
        final url = args['url'] as String;
        final score = args['score'] as int;
        final riskLevel = args['risk_level'] as String;
        final sender = args['sender'] as String;

        debugPrint('SmsService: URL analizada - $url (score: $score, risk: $riskLevel)');

        onSmsUrlAnalyzed?.call(url, score, riskLevel, sender);
        break;

      case 'notification_opened':
        // Usuario tocó la notificación de alerta
        final args = call.arguments as Map<dynamic, dynamic>;
        final url = args['url'] as String;
        final score = args['score'] as int;
        final riskLevel = args['risk_level'] as String;

        debugPrint('SmsService: Notificación abierta - $url');

        onNotificationOpened?.call(url, score, riskLevel);
        break;

      case 'sms_permission_result':
        // Resultado de solicitud de permisos SMS
        final args = call.arguments as Map<dynamic, dynamic>;
        final granted = args['granted'] as bool;

        debugPrint('SmsService: Permiso SMS ${granted ? "concedido" : "denegado"}');

        onSmsPermissionResult?.call(granted);
        break;

      case 'notification_permission_result':
        // Resultado de solicitud de permiso de notificaciones
        final args = call.arguments as Map<dynamic, dynamic>;
        final granted = args['granted'] as bool;

        debugPrint('SmsService: Permiso notificaciones ${granted ? "concedido" : "denegado"}');

        onNotificationPermissionResult?.call(granted);
        break;

      default:
        debugPrint('SmsService: Método no manejado: ${call.method}');
    }
  }

  // ==================== PERMISOS ====================

  /// Verifica si tiene permisos de SMS
  static Future<bool> hasSmsPermission() async {
    try {
      final result = await _channel.invokeMethod<bool>('check_sms_permission');
      return result ?? false;
    } catch (e) {
      debugPrint('SmsService: Error verificando permiso SMS: $e');
      return false;
    }
  }

  /// Solicita permisos de SMS al usuario
  static Future<void> requestSmsPermission() async {
    try {
      await _channel.invokeMethod('request_sms_permission');
    } catch (e) {
      debugPrint('SmsService: Error solicitando permiso SMS: $e');
    }
  }

  /// Verifica si tiene permiso de notificaciones (Android 13+)
  static Future<bool> hasNotificationPermission() async {
    try {
      final result =
          await _channel.invokeMethod<bool>('check_notification_permission');
      return result ?? true; // true por defecto para Android < 13
    } catch (e) {
      debugPrint('SmsService: Error verificando permiso notificaciones: $e');
      return true;
    }
  }

  /// Solicita permiso de notificaciones (Android 13+)
  static Future<void> requestNotificationPermission() async {
    try {
      await _channel.invokeMethod('request_notification_permission');
    } catch (e) {
      debugPrint('SmsService: Error solicitando permiso notificaciones: $e');
    }
  }

  /// Obtiene el estado de todos los permisos
  static Future<Map<String, bool>> getPermissionsStatus() async {
    try {
      final result =
          await _channel.invokeMethod<Map<dynamic, dynamic>>('get_permissions_status');
      if (result != null) {
        return {
          'sms_read': result['sms_read'] as bool? ?? false,
          'sms_receive': result['sms_receive'] as bool? ?? false,
          'notification': result['notification'] as bool? ?? true,
          'all_granted': result['all_granted'] as bool? ?? false,
        };
      }
    } catch (e) {
      debugPrint('SmsService: Error obteniendo estado de permisos: $e');
    }
    return {
      'sms_read': false,
      'sms_receive': false,
      'notification': true,
      'all_granted': false,
    };
  }

  /// Abre la configuración de la app
  static Future<void> openAppSettings() async {
    try {
      await _channel.invokeMethod('open_app_settings');
    } catch (e) {
      debugPrint('SmsService: Error abriendo configuración: $e');
    }
  }

  /// Solicita todos los permisos necesarios
  static Future<void> requestAllPermissions() async {
    final status = await getPermissionsStatus();

    // Primero solicitar permisos de SMS
    if (!status['sms_read']! || !status['sms_receive']!) {
      await requestSmsPermission();
      // Esperar un poco antes de solicitar el siguiente permiso
      await Future.delayed(const Duration(milliseconds: 500));
    }

    // Luego solicitar permiso de notificaciones (Android 13+)
    if (!status['notification']!) {
      await requestNotificationPermission();
    }
  }
}

/// Modelo para representar un análisis de SMS
class SmsAnalysisResult {
  final String url;
  final int score;
  final String riskLevel;
  final String sender;
  final DateTime timestamp;

  SmsAnalysisResult({
    required this.url,
    required this.score,
    required this.riskLevel,
    required this.sender,
    DateTime? timestamp,
  }) : timestamp = timestamp ?? DateTime.now();

  bool get isHighRisk => riskLevel == 'HIGH';
  bool get isMediumRisk => riskLevel == 'MEDIUM';
  bool get isLowRisk => riskLevel == 'LOW';
  bool get isDangerous => isHighRisk || isMediumRisk;

  @override
  String toString() {
    return 'SmsAnalysisResult(url: $url, score: $score, risk: $riskLevel, sender: $sender)';
  }
}
