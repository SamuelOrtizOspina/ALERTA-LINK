import 'package:flutter/material.dart';
import '../services/sms_service.dart';

/// SmsProtectionScreen - Pantalla para configurar la protección SMS
///
/// Permite al usuario:
/// - Ver el estado de los permisos
/// - Activar/desactivar la protección
/// - Solicitar permisos necesarios
class SmsProtectionScreen extends StatefulWidget {
  const SmsProtectionScreen({super.key});

  @override
  State<SmsProtectionScreen> createState() => _SmsProtectionScreenState();
}

class _SmsProtectionScreenState extends State<SmsProtectionScreen> {
  bool _isLoading = true;
  Map<String, bool> _permissions = {};

  @override
  void initState() {
    super.initState();
    _loadPermissions();
    _setupListeners();
  }

  void _setupListeners() {
    SmsService.onSmsPermissionResult = (granted) {
      _loadPermissions();
      _showSnackBar(
        granted
            ? '✅ Permisos de SMS concedidos'
            : '❌ Permisos de SMS denegados',
        granted ? Colors.green : Colors.red,
      );
    };

    SmsService.onNotificationPermissionResult = (granted) {
      _loadPermissions();
      _showSnackBar(
        granted
            ? '✅ Permiso de notificaciones concedido'
            : '❌ Permiso de notificaciones denegado',
        granted ? Colors.green : Colors.red,
      );
    };
  }

  Future<void> _loadPermissions() async {
    setState(() => _isLoading = true);
    final permissions = await SmsService.getPermissionsStatus();
    setState(() {
      _permissions = permissions;
      _isLoading = false;
    });
  }

  void _showSnackBar(String message, Color color) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: color,
        behavior: SnackBarBehavior.floating,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final isProtectionActive = _permissions['all_granted'] ?? false;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Protección SMS'),
        backgroundColor: isProtectionActive ? Colors.green : Colors.orange,
        foregroundColor: Colors.white,
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Header con estado
                  _buildStatusCard(isProtectionActive),
                  const SizedBox(height: 24),

                  // Explicación
                  _buildExplanationCard(),
                  const SizedBox(height: 24),

                  // Lista de permisos
                  _buildPermissionsList(),
                  const SizedBox(height: 24),

                  // Botón de acción
                  if (!isProtectionActive) _buildRequestButton(),

                  const SizedBox(height: 16),

                  // Info adicional
                  _buildInfoCard(),
                ],
              ),
            ),
    );
  }

  Widget _buildStatusCard(bool isActive) {
    return Card(
      elevation: 4,
      color: isActive ? Colors.green.shade50 : Colors.orange.shade50,
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: isActive ? Colors.green : Colors.orange,
                shape: BoxShape.circle,
              ),
              child: Icon(
                isActive ? Icons.shield : Icons.shield_outlined,
                color: Colors.white,
                size: 32,
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    isActive ? 'Protección Activa' : 'Protección Inactiva',
                    style: TextStyle(
                      fontSize: 20,
                      fontWeight: FontWeight.bold,
                      color: isActive ? Colors.green.shade700 : Colors.orange.shade700,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    isActive
                        ? 'Los SMS con URLs sospechosas serán analizados automáticamente'
                        : 'Activa la protección para detectar phishing en SMS',
                    style: TextStyle(
                      color: isActive ? Colors.green.shade600 : Colors.orange.shade600,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildExplanationCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.info_outline, color: Colors.blue.shade600),
                const SizedBox(width: 8),
                const Text(
                  '¿Cómo funciona?',
                  style: TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            _buildStep('1', 'Recibes un SMS con un enlace sospechoso'),
            _buildStep('2', 'ALERTA-LINK detecta el enlace automáticamente'),
            _buildStep('3', 'El enlace es analizado por nuestro sistema'),
            _buildStep('4', 'Si es peligroso, recibes una alerta inmediata'),
          ],
        ),
      ),
    );
  }

  Widget _buildStep(String number, String text) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 24,
            height: 24,
            decoration: BoxDecoration(
              color: Colors.blue.shade100,
              shape: BoxShape.circle,
            ),
            child: Center(
              child: Text(
                number,
                style: TextStyle(
                  color: Colors.blue.shade700,
                  fontWeight: FontWeight.bold,
                  fontSize: 12,
                ),
              ),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(text, style: const TextStyle(fontSize: 14)),
          ),
        ],
      ),
    );
  }

  Widget _buildPermissionsList() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Permisos necesarios',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 16),
            _buildPermissionItem(
              'Recibir SMS',
              'Para detectar mensajes entrantes',
              _permissions['sms_receive'] ?? false,
              Icons.sms,
            ),
            const Divider(),
            _buildPermissionItem(
              'Leer SMS',
              'Para analizar el contenido',
              _permissions['sms_read'] ?? false,
              Icons.message,
            ),
            const Divider(),
            _buildPermissionItem(
              'Notificaciones',
              'Para alertarte de peligros',
              _permissions['notification'] ?? true,
              Icons.notifications,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPermissionItem(
    String title,
    String description,
    bool granted,
    IconData icon,
  ) {
    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: Container(
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: granted ? Colors.green.shade50 : Colors.grey.shade100,
          borderRadius: BorderRadius.circular(8),
        ),
        child: Icon(
          icon,
          color: granted ? Colors.green : Colors.grey,
        ),
      ),
      title: Text(title),
      subtitle: Text(description, style: const TextStyle(fontSize: 12)),
      trailing: Icon(
        granted ? Icons.check_circle : Icons.cancel,
        color: granted ? Colors.green : Colors.red.shade300,
      ),
    );
  }

  Widget _buildRequestButton() {
    return SizedBox(
      width: double.infinity,
      child: ElevatedButton.icon(
        onPressed: () async {
          await SmsService.requestAllPermissions();
        },
        icon: const Icon(Icons.security),
        label: const Text('Activar Protección SMS'),
        style: ElevatedButton.styleFrom(
          backgroundColor: Colors.green,
          foregroundColor: Colors.white,
          padding: const EdgeInsets.symmetric(vertical: 16),
          textStyle: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
        ),
      ),
    );
  }

  Widget _buildInfoCard() {
    return Card(
      color: Colors.blue.shade50,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.privacy_tip, color: Colors.blue.shade600),
                const SizedBox(width: 8),
                Text(
                  'Privacidad',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Colors.blue.shade700,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              '• Solo analizamos URLs, no el contenido completo de tus SMS\n'
              '• No guardamos tus mensajes\n'
              '• No compartimos tu información\n'
              '• Puedes desactivar esta función en cualquier momento',
              style: TextStyle(
                color: Colors.blue.shade600,
                fontSize: 13,
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  void dispose() {
    SmsService.onSmsPermissionResult = null;
    SmsService.onNotificationPermissionResult = null;
    super.dispose();
  }
}
