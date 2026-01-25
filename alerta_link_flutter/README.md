# ALERTA-LINK Flutter + Kotlin

App movil hibrida para deteccion de phishing en tiempo real.

## Arquitectura

```
+---------------------------+
|      Flutter (Dart)       |  <- TODA la logica aqui
|  - UI / Pantallas         |
|  - Analisis de URLs       |
|  - Llamadas a API         |
|  - Historial              |
|  - Configuracion          |
+-------------+-------------+
              |
      Platform Channel
         "push_channel"
              |
+-------------+-------------+
|      Kotlin (Android)     |  <- Solo notificaciones
|  - NotificationListener   |
|  - Extraer URLs           |
|  - Cancelar notificacion  |
+---------------------------+
```

## Regla Principal

| Componente | Responsabilidad |
|------------|-----------------|
| **Flutter** | Decide (analiza, llama APIs, guarda historial) |
| **Kotlin** | Obedece (escucha notificaciones, envia URLs) |

## Estructura del Proyecto

```
lib/
├── main.dart                    # Punto de entrada
├── ui/
│   ├── home_screen.dart         # Pantalla principal
│   ├── result_screen.dart       # Semaforo de riesgo
│   ├── settings_screen.dart     # Configuracion de modo
│   └── history_screen.dart      # Historial de analisis
├── logic/
│   └── url_analyzer.dart        # Logica de analisis
├── models/
│   └── url_analysis.dart        # Modelos de datos
├── services/
│   └── api_service.dart         # Cliente HTTP
└── platform/
    └── notification_channel.dart # Platform Channel

android/app/src/main/kotlin/.../
├── MainActivity.kt              # Configura Platform Channel
└── PushListenerService.kt       # NotificationListenerService
```

## Comunicacion Flutter <-> Kotlin

### Canal: `push_channel`

**Kotlin -> Flutter:**
```dart
// Cuando detecta URL en notificacion
{
  "url": "https://ejemplo.com",
  "package": "com.whatsapp",
  "title": "Nuevo mensaje",
  "body": "Mira este link...",
  "key": "notification_key"
}
```

**Flutter -> Kotlin:**
```dart
// Bloquear notificacion
"block_notification" -> {key: "..."}

// Permitir notificacion
"allow_notification" -> {key: "..."}

// Verificar permiso
"check_permission" -> bool

// Abrir configuracion
"open_settings" -> void
```

## Modos de Conexion

| Modo | Descripcion | APIs |
|------|-------------|------|
| **Auto** | Detecta conexion | Si hay internet: online |
| **Online** | Forzar APIs | Tranco + VirusTotal |
| **Offline** | Solo local | ML + Heuristicas |

## Compilar

```bash
# Debug
flutter build apk --debug

# Release
flutter build apk --release
```

El APK se genera en: `build/app/outputs/flutter-apk/`

## Configuracion

1. **Backend URL**: Editar `lib/services/api_service.dart`
   ```dart
   static String baseUrl = 'http://TU_IP:8000';
   ```

2. **Emulador**: Usar `10.0.2.2` como IP del host

3. **Dispositivo fisico**: Usar IP local de la maquina

## Permisos Requeridos

- `INTERNET`: Conexion al backend
- `ACCESS_NETWORK_STATE`: Detectar conectividad
- `BIND_NOTIFICATION_LISTENER_SERVICE`: Escuchar notificaciones

## Flujo de la App

```
1. Usuario ingresa URL manualmente
   └─> Flutter analiza -> Muestra semaforo

2. Usuario comparte URL desde otra app
   └─> Flutter recibe -> Analiza -> Muestra semaforo

3. Notificacion con URL llega
   └─> Kotlin detecta -> Envia a Flutter -> Flutter analiza
   └─> Si es peligrosa: Flutter ordena bloquear
```

## Autores

- Cristia Salazar
- Samuel Ortiz Ospina
- Juan Stiven Castro

**Universidad Manuela Beltran - Ingenieria de Software 2025**
