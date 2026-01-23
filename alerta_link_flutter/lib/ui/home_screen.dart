import 'package:flutter/material.dart';
import '../logic/url_analyzer.dart';
import '../models/url_analysis.dart';
import '../platform/notification_channel.dart';
import '../services/sms_service.dart';
import 'result_screen.dart';
import 'settings_screen.dart';
import 'history_screen.dart';
import 'sms_protection_screen.dart';

/// Pantalla principal de la app
class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final TextEditingController _urlController = TextEditingController();
  bool _isAnalyzing = false;
  bool _hasNotificationPermission = false;
  bool _hasSmsProtection = false;

  @override
  void initState() {
    super.initState();
    _initializeApp();
  }

  Future<void> _initializeApp() async {
    // Inicializar canal de notificaciones
    NotificationChannel.initialize();

    // Verificar permiso de notificaciones
    _hasNotificationPermission =
        await NotificationChannel.hasNotificationPermission();

    // Verificar estado de protección SMS
    final smsStatus = await SmsService.getPermissionsStatus();
    _hasSmsProtection = smsStatus['all_granted'] ?? false;

    setState(() {});

    // Escuchar URLs detectadas en notificaciones
    NotificationChannel.onNotificationReceived.listen((notification) {
      _analyzeUrl(notification.url, sourcePackage: notification.packageName);
    });

    // Escuchar URLs analizadas desde SMS
    SmsService.onSmsUrlAnalyzed = (url, score, riskLevel, sender) {
      _showSmsAlert(url, score, riskLevel, sender);
    };

    // Escuchar cuando el usuario abre una notificación de SMS
    SmsService.onNotificationOpened = (url, score, riskLevel) {
      _analyzeUrl(url, sourcePackage: 'SMS');
    };
  }

  void _showSmsAlert(String url, int score, String riskLevel, String sender) {
    final color = riskLevel == 'HIGH' ? Colors.red : Colors.orange;
    final icon = riskLevel == 'HIGH' ? Icons.dangerous : Icons.warning;

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Row(
          children: [
            Icon(icon, color: Colors.white),
            const SizedBox(width: 8),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    'SMS sospechoso de $sender',
                    style: const TextStyle(fontWeight: FontWeight.bold),
                  ),
                  Text('Riesgo: $score/100'),
                ],
              ),
            ),
          ],
        ),
        backgroundColor: color,
        behavior: SnackBarBehavior.floating,
        duration: const Duration(seconds: 5),
        action: SnackBarAction(
          label: 'Ver',
          textColor: Colors.white,
          onPressed: () => _analyzeUrl(url, sourcePackage: 'SMS'),
        ),
      ),
    );
  }

  Future<void> _analyzeUrl(String url, {String? sourcePackage}) async {
    if (url.isEmpty) {
      _showSnackBar('Ingresa una URL para analizar');
      return;
    }

    setState(() => _isAnalyzing = true);

    try {
      final result = await UrlAnalyzer.analyze(
        url,
        sourcePackage: sourcePackage,
      );
      _navigateToResult(result);
    } catch (e) {
      _showSnackBar('Error: $e');
    } finally {
      setState(() => _isAnalyzing = false);
    }
  }

  void _navigateToResult(UrlAnalysis result) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => ResultScreen(analysis: result),
      ),
    );
  }

  void _showSnackBar(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message)),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('ALERTA-LINK'),
        centerTitle: true,
        actions: [
          IconButton(
            icon: const Icon(Icons.history),
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (context) => const HistoryScreen()),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (context) => const SettingsScreen()),
            ),
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Banner de estado de notificaciones
            _buildStatusBanner(),

            // Banner de protección SMS
            _buildSmsProtectionBanner(),
            const SizedBox(height: 24),

            // Logo/Icono
            const Icon(
              Icons.security,
              size: 80,
              color: Colors.blue,
            ),
            const SizedBox(height: 16),

            // Titulo
            const Text(
              'Detector de Phishing',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 8),
            const Text(
              'Analiza URLs para detectar intentos de phishing',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 14,
                color: Colors.grey,
              ),
            ),
            const SizedBox(height: 32),

            // Campo de URL
            TextField(
              controller: _urlController,
              decoration: InputDecoration(
                labelText: 'URL a analizar',
                hintText: 'https://ejemplo.com',
                prefixIcon: const Icon(Icons.link),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
                suffixIcon: _urlController.text.isNotEmpty
                    ? IconButton(
                        icon: const Icon(Icons.clear),
                        onPressed: () {
                          _urlController.clear();
                          setState(() {});
                        },
                      )
                    : null,
              ),
              keyboardType: TextInputType.url,
              textInputAction: TextInputAction.go,
              onSubmitted: (url) => _analyzeUrl(url),
              onChanged: (value) => setState(() {}),
            ),
            const SizedBox(height: 16),

            // Boton de analizar
            ElevatedButton.icon(
              onPressed: _isAnalyzing
                  ? null
                  : () => _analyzeUrl(_urlController.text),
              icon: _isAnalyzing
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.search),
              label: Text(_isAnalyzing ? 'Analizando...' : 'Analizar URL'),
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 16),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
              ),
            ),
            const SizedBox(height: 24),

            // Info de modo
            _buildModeInfo(),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusBanner() {
    if (!_hasNotificationPermission) {
      return Card(
        color: Colors.orange.shade50,
        child: ListTile(
          leading: const Icon(Icons.warning, color: Colors.orange),
          title: const Text('Permiso requerido'),
          subtitle: const Text(
            'Habilita el acceso a notificaciones para detectar URLs automaticamente',
          ),
          trailing: TextButton(
            onPressed: () => NotificationChannel.openNotificationSettings(),
            child: const Text('Habilitar'),
          ),
        ),
      );
    }
    return const SizedBox.shrink();
  }

  Widget _buildSmsProtectionBanner() {
    return Card(
      color: _hasSmsProtection ? Colors.green.shade50 : Colors.blue.shade50,
      child: ListTile(
        leading: Icon(
          _hasSmsProtection ? Icons.shield : Icons.sms,
          color: _hasSmsProtection ? Colors.green : Colors.blue,
        ),
        title: Text(
          _hasSmsProtection ? 'Proteccion SMS Activa' : 'Proteccion SMS',
        ),
        subtitle: Text(
          _hasSmsProtection
              ? 'Los SMS con enlaces sospechosos seran analizados'
              : 'Detecta phishing en mensajes de texto automaticamente',
        ),
        trailing: TextButton(
          onPressed: () async {
            await Navigator.push(
              context,
              MaterialPageRoute(
                builder: (context) => const SmsProtectionScreen(),
              ),
            );
            // Actualizar estado al volver
            final smsStatus = await SmsService.getPermissionsStatus();
            setState(() {
              _hasSmsProtection = smsStatus['all_granted'] ?? false;
            });
          },
          child: Text(_hasSmsProtection ? 'Configurar' : 'Activar'),
        ),
      ),
    );
  }

  Widget _buildModeInfo() {
    final mode = UrlAnalyzer.currentMode;
    final (icon, color, text) = switch (mode) {
      'online' => (Icons.verified_user, Colors.green, 'Analisis Completo'),
      _ => (Icons.auto_awesome, Colors.blue, 'Analisis Automatico'),
    };

    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Icon(icon, color: color, size: 20),
        const SizedBox(width: 8),
        Text(
          text,
          style: TextStyle(color: color, fontWeight: FontWeight.w500),
        ),
      ],
    );
  }

  @override
  void dispose() {
    _urlController.dispose();
    NotificationChannel.dispose();
    // Limpiar callbacks de SMS
    SmsService.onSmsUrlAnalyzed = null;
    SmsService.onNotificationOpened = null;
    super.dispose();
  }
}
