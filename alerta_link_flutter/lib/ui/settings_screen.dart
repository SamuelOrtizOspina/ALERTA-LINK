import 'package:flutter/material.dart';
import '../logic/url_analyzer.dart';
import '../services/api_service.dart';

/// Pantalla de configuracion
class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  String _currentModel = UrlAnalyzer.currentModel;
  bool _isLoading = false;
  bool _isServerOnline = false;
  Map<String, dynamic>? _serverSettings;

  @override
  void initState() {
    super.initState();
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    setState(() => _isLoading = true);

    try {
      _isServerOnline = await ApiService.checkHealth();
      if (_isServerOnline) {
        _serverSettings = await ApiService.getSettings();
      }
    } catch (e) {
      _isServerOnline = false;
    }

    setState(() => _isLoading = false);
  }

  Future<void> _changeModel(String model) async {
    setState(() => _isLoading = true);

    try {
      await UrlAnalyzer.setModel(model);
      _currentModel = model;
      final modelName = model == 'ml' ? 'Machine Learning' : 'Heuristico';
      _showSnackBar('Modelo cambiado a: $modelName');
    } catch (e) {
      _showSnackBar('Error al cambiar modelo');
    }

    setState(() => _isLoading = false);
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
        title: const Text('Configuracion'),
        centerTitle: true,
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                // Estado del servidor
                _buildServerStatus(),
                const SizedBox(height: 24),

                // Modo de conexion
                _buildModeSection(),
                const SizedBox(height: 24),

                // Servicios
                if (_serverSettings != null) _buildServicesSection(),
                const SizedBox(height: 24),

                // Info de la app
                _buildAppInfo(),
              ],
            ),
    );
  }

  Widget _buildServerStatus() {
    return Card(
      child: ListTile(
        leading: Icon(
          _isServerOnline ? Icons.cloud_done : Icons.cloud_off,
          color: _isServerOnline ? Colors.green : Colors.red,
        ),
        title: Text(
          _isServerOnline ? 'Servidor conectado' : 'Servidor desconectado',
        ),
        subtitle: Text(ApiService.baseUrl),
        trailing: IconButton(
          icon: const Icon(Icons.refresh),
          onPressed: _loadSettings,
        ),
      ),
    );
  }

  Widget _buildModeSection() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Modelo de Analisis',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 18,
              ),
            ),
            const SizedBox(height: 8),
            const Text(
              'Selecciona el tipo de modelo para detectar phishing:',
              style: TextStyle(color: Colors.grey, fontSize: 12),
            ),
            const SizedBox(height: 16),
            _buildModelOption(
              'ml',
              'Machine Learning',
              'GradientBoosting (98.75% accuracy) + APIs',
              Icons.psychology,
            ),
            _buildModelOption(
              'heuristic',
              'Heuristico',
              'Reglas calibradas (75.88% accuracy) + APIs',
              Icons.rule,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildModelOption(
    String model,
    String title,
    String subtitle,
    IconData icon,
  ) {
    final isSelected = _currentModel == model;

    return RadioListTile<String>(
      value: model,
      groupValue: _currentModel,
      onChanged: (value) {
        if (value != null) _changeModel(value);
      },
      title: Row(
        children: [
          Icon(icon, size: 20, color: isSelected ? Colors.blue : Colors.grey),
          const SizedBox(width: 8),
          Text(title, style: TextStyle(fontWeight: isSelected ? FontWeight.bold : FontWeight.normal)),
        ],
      ),
      subtitle: Text(subtitle),
      selected: isSelected,
      activeColor: Colors.blue,
    );
  }

  Widget _buildServicesSection() {
    final services =
        _serverSettings?['services'] as Map<String, dynamic>? ?? {};

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Estado de Servicios',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 18,
              ),
            ),
            const SizedBox(height: 12),
            _buildServiceItem(
              'Tranco API',
              services['tranco']?['enabled'] ?? false,
              services['tranco']?['message'] ?? 'Desconocido',
            ),
            _buildServiceItem(
              'VirusTotal API',
              services['virustotal']?['enabled'] ?? false,
              services['virustotal']?['message'] ?? 'Desconocido',
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildServiceItem(String name, bool enabled, String message) {
    return ListTile(
      leading: Icon(
        enabled ? Icons.check_circle : Icons.cancel,
        color: enabled ? Colors.green : Colors.red,
      ),
      title: Text(name),
      subtitle: Text(message),
      dense: true,
    );
  }

  Widget _buildAppInfo() {
    final version = _serverSettings?['app_version'] ?? '0.1.0';

    return Card(
      color: Colors.grey.shade100,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            const Icon(Icons.security, size: 48, color: Colors.blue),
            const SizedBox(height: 8),
            const Text(
              'ALERTA-LINK',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 18,
              ),
            ),
            Text(
              'Version: $version',
              style: const TextStyle(color: Colors.grey),
            ),
            const SizedBox(height: 8),
            const Text(
              'Sistema Forense de Deteccion de Phishing',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 12),
            ),
          ],
        ),
      ),
    );
  }
}
