import '../models/url_analysis.dart';
import '../services/api_service.dart';

/// Analizador principal de URLs
///
/// Toda la logica de decision esta aqui en Flutter.
/// Kotlin solo envia URLs, Flutter decide.
class UrlAnalyzer {
  /// Modo de conexion actual (siempre online)
  static String _currentMode = 'online';

  /// Modelo de analisis actual: 'ml' o 'heuristic'
  ///
  /// Por defecto se usa el heuristico: es el motor con pesos calibrados
  /// y el que corresponde a los resultados reportados en la evaluacion.
  static String _currentModel = 'heuristic';

  /// Historial de analisis (en memoria, podria ser SQLite)
  static final List<UrlAnalysis> _history = [];

  /// Obtiene el modo actual
  static String get currentMode => _currentMode;

  /// Obtiene el modelo actual
  static String get currentModel => _currentModel;

  /// Obtiene el historial
  static List<UrlAnalysis> get history => List.unmodifiable(_history);

  /// Cambia el modo de conexion (deprecado, siempre online)
  static Future<void> setMode(String mode) async {
    // Siempre usar online
    _currentMode = 'online';
  }

  /// Cambia el modelo de analisis
  static Future<void> setModel(String model) async {
    if (!['ml', 'heuristic'].contains(model)) {
      throw ArgumentError('Modelo invalido: $model');
    }
    _currentModel = model;
  }

  /// Analiza una URL
  ///
  /// [url] - URL a analizar
  /// [sourcePackage] - App de donde vino la URL (opcional)
  /// [saveToHistory] - Si guardar en historial (default: true)
  static Future<UrlAnalysis> analyze(
    String url, {
    String? sourcePackage,
    bool saveToHistory = true,
  }) async {
    // Normalizar URL - agregar https:// si no tiene esquema
    String normalizedUrl = url.trim();
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
      normalizedUrl = 'https://$normalizedUrl';
    }

    // Validar URL basica
    if (!_isValidUrl(normalizedUrl)) {
      throw ArgumentError('URL invalida: $url');
    }

    // Llamar al backend con modelo seleccionado
    final result = await ApiService.analyzeUrl(
      normalizedUrl,
      mode: _currentMode,
      model: _currentModel,
    );

    // Guardar en historial
    if (saveToHistory) {
      _addToHistory(result);
    }

    return result;
  }

  /// Verifica si una URL es valida
  static bool _isValidUrl(String url) {
    if (url.isEmpty) return false;
    final uri = Uri.tryParse(url);
    if (uri == null) return false;
    return uri.hasScheme && (uri.scheme == 'http' || uri.scheme == 'https');
  }

  /// Agrega un resultado al historial
  static void _addToHistory(UrlAnalysis analysis) {
    _history.insert(0, analysis);
    // Mantener solo los ultimos 100
    if (_history.length > 100) {
      _history.removeLast();
    }
  }

  /// Limpia el historial
  static void clearHistory() {
    _history.clear();
  }
}
