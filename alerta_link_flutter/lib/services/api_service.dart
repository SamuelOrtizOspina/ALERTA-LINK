import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/url_analysis.dart';

/// Configuracion de la API segun ambiente
class ApiConfig {
  // URL permanente del servidor (tu dominio)
  static const String productionUrl = 'https://alerta.mirrorhub.tech';

  // URL para desarrollo local (emulador Android)
  static const String developmentUrl = 'http://10.0.2.2:8000';

  // Determinar si estamos en modo produccion
  static bool get isProduction =>
      const bool.fromEnvironment('dart.vm.product', defaultValue: false);

  // URL base segun el ambiente
  static String get baseUrl {
    // Permitir override via variable de entorno
    const envUrl = String.fromEnvironment('API_URL', defaultValue: '');
    if (envUrl.isNotEmpty) return envUrl;

    return isProduction ? productionUrl : developmentUrl;
  }
}

/// Servicio para comunicarse con el backend ALERTA-LINK
class ApiService {
  // URL base configurable
  static String _customBaseUrl = '';

  /// Obtiene la URL base actual
  static String get baseUrl =>
      _customBaseUrl.isNotEmpty ? _customBaseUrl : ApiConfig.baseUrl;

  /// Configura la URL base del servidor (para testing o configuracion manual)
  static void setBaseUrl(String url) {
    _customBaseUrl = url;
  }

  /// Resetea a la URL por defecto
  static void resetBaseUrl() {
    _customBaseUrl = '';
  }

  /// Analiza una URL y retorna el resultado
  static Future<UrlAnalysis> analyzeUrl(
    String url, {
    String mode = 'online',
    String model = 'ml',
  }) async {
    try {
      final response = await http
          .post(
            Uri.parse('$baseUrl/analyze'),
            headers: {
              'Content-Type': 'application/json',
              'X-Requested-With': 'ALERTA-LINK-App',
            },
            body: jsonEncode({
              'url': url,
              'mode': mode,
              'model': model,
            }),
          )
          .timeout(const Duration(seconds: 15)); // Reducido de 30s

      if (response.statusCode == 200) {
        final json = jsonDecode(response.body);
        return UrlAnalysis.fromJson(json);
      } else {
        throw ApiException(
          'Error del servidor: ${response.statusCode}',
          response.statusCode,
        );
      }
    } on http.ClientException catch (e) {
      throw ApiException('Error de conexion: ${e.message}', 0);
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException('Error inesperado: $e', 0);
    }
  }

  /// Verifica si el servidor esta disponible
  static Future<bool> checkHealth() async {
    try {
      final response = await http
          .get(
            Uri.parse('$baseUrl/health'),
            headers: {'X-Requested-With': 'ALERTA-LINK-App'},
          )
          .timeout(const Duration(seconds: 5));
      return response.statusCode == 200;
    } catch (e) {
      return false;
    }
  }

  /// Obtiene la configuracion actual del servidor
  static Future<Map<String, dynamic>> getSettings() async {
    try {
      final response = await http
          .get(
            Uri.parse('$baseUrl/settings'),
            headers: {'X-Requested-With': 'ALERTA-LINK-App'},
          )
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      }
      throw ApiException('Error obteniendo settings', response.statusCode);
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException('Error de conexion', 0);
    }
  }

  /// Cambia el modo de conexion
  static Future<Map<String, dynamic>> setMode(String mode) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/settings/mode'),
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'ALERTA-LINK-App',
        },
        body: jsonEncode({
          'mode': mode,
          'sync_on_connect': true,
        }),
      );

      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      }
      throw ApiException('Error cambiando modo', response.statusCode);
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException('Error de conexion', 0);
    }
  }

  /// Reporta una URL sospechosa
  static Future<bool> reportUrl({
    required String url,
    required String label,
    String? comment,
    String? contact,
  }) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/report'),
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'ALERTA-LINK-App',
        },
        body: jsonEncode({
          'url': url,
          'label': label,
          'comment': comment,
          'contact': contact,
        }),
      );
      return response.statusCode == 200;
    } catch (e) {
      return false;
    }
  }

  /// Obtiene informacion del ambiente actual
  static Map<String, dynamic> getEnvironmentInfo() {
    return {
      'baseUrl': baseUrl,
      'isProduction': ApiConfig.isProduction,
      'isCustomUrl': _customBaseUrl.isNotEmpty,
    };
  }
}

/// Excepcion personalizada para errores de API
class ApiException implements Exception {
  final String message;
  final int statusCode;

  ApiException(this.message, this.statusCode);

  @override
  String toString() => 'ApiException: $message (code: $statusCode)';
}
