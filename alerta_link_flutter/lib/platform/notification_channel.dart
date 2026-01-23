import 'dart:async';
import 'package:flutter/services.dart';
import '../models/url_analysis.dart';

/// Canal de comunicacion con la capa nativa de Kotlin
///
/// Kotlin -> Flutter: Envia URLs detectadas en notificaciones
/// Flutter -> Kotlin: Ordenes para bloquear/permitir notificaciones
class NotificationChannel {
  static const String _channelName = 'push_channel';
  static const MethodChannel _channel = MethodChannel(_channelName);

  /// Stream de notificaciones recibidas
  static final StreamController<NotificationData> _notificationController =
      StreamController<NotificationData>.broadcast();

  /// Stream publico para escuchar notificaciones
  static Stream<NotificationData> get onNotificationReceived =>
      _notificationController.stream;

  /// Inicializa el canal y configura el handler
  static void initialize() {
    _channel.setMethodCallHandler(_handleMethodCall);
  }

  /// Maneja las llamadas desde Kotlin
  static Future<dynamic> _handleMethodCall(MethodCall call) async {
    switch (call.method) {
      case 'onUrlDetected':
        // Kotlin encontro una URL en una notificacion
        final Map<dynamic, dynamic> data = call.arguments;
        final notification = NotificationData.fromMap(data);
        _notificationController.add(notification);
        return true;

      case 'onNotificationPosted':
        // Notificacion genérica recibida (sin URL)
        return true;

      default:
        throw PlatformException(
          code: 'NOT_IMPLEMENTED',
          message: 'Method ${call.method} not implemented',
        );
    }
  }

  /// Ordena a Kotlin bloquear/cancelar una notificacion
  static Future<bool> blockNotification(String notificationKey) async {
    try {
      final result = await _channel.invokeMethod('block_notification', {
        'key': notificationKey,
      });
      return result == true;
    } on PlatformException catch (e) {
      print('Error blocking notification: ${e.message}');
      return false;
    }
  }

  /// Ordena a Kotlin permitir una notificacion
  static Future<bool> allowNotification(String notificationKey) async {
    try {
      final result = await _channel.invokeMethod('allow_notification', {
        'key': notificationKey,
      });
      return result == true;
    } on PlatformException catch (e) {
      print('Error allowing notification: ${e.message}');
      return false;
    }
  }

  /// Verifica si el permiso de notificaciones esta habilitado
  static Future<bool> hasNotificationPermission() async {
    try {
      final result = await _channel.invokeMethod('check_permission');
      return result == true;
    } on PlatformException {
      return false;
    }
  }

  /// Abre la configuracion para habilitar el permiso de notificaciones
  static Future<void> openNotificationSettings() async {
    try {
      await _channel.invokeMethod('open_settings');
    } on PlatformException catch (e) {
      print('Error opening settings: ${e.message}');
    }
  }

  /// Libera recursos
  static void dispose() {
    _notificationController.close();
  }
}
