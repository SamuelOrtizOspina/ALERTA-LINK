# App Movil - ALERTA-LINK

> Aplicacion movil Flutter para deteccion de phishing/smishing - 100% OFFLINE

---

## Descripcion

Aplicacion movil para Android que permite:
1. **Deteccion automatica de SMS** - Analiza URLs en SMS entrantes automaticamente
2. Analizar URLs sospechosas recibidas por SMS/WhatsApp/email
3. Ver score de riesgo con semaforo visual (0-100)
4. Entender por que una URL es peligrosa (senales explicadas)
5. Reportar URLs maliciosas (opt-in)
6. Funciona 100% OFFLINE con motor heuristico local
7. Modo cloud-assisted opcional (requiere consentimiento)
8. **Notificaciones de alerta** para URLs de riesgo MEDIUM/HIGH

---

## Arquitectura

```
+-------------------+
|   USUARIO         |
|   (celular)       |
+--------+----------+
         |
         | Pega/comparte URL
         v
+------------------------+        (OPCIONAL)         +-------------------+
|   APP MOVIL            |                           |    BACKEND        |
|   (Flutter)            |                           |    (FastAPI)      |
|                        |   POST /analyze           |                   |
| +--------------------+ | ----------------------->  | - /health         |
| | LocalAnalyzer      | | <-----------------------  | - /analyze        |
| | (Motor Heuristico) | |   {score, risk, signals}  | - /ingest         |
| +--------------------+ |                           | - /report         |
|                        |   POST /report            |                   |
| - Input URL            | ----------------------->  +-------------------+
| - Semaforo             |
| - Senales              |
| - Share Intent         |
| - Cloud-Assisted       |
+------------------------+

MODO OFFLINE (Default):
  - LocalAnalyzer ejecuta 15+ reglas heuristicas
  - Score 0-100 calculado localmente
  - Sin dependencia de internet

MODO CLOUD-ASSISTED (Opcional):
  - Requiere consentimiento del usuario
  - Analisis mejorado con modelos ML del servidor
  - Fallback automatico a modo local si servidor no disponible
```

---

## Proteccion SMS Automatica (v1.2.0)

### Descripcion

La app detecta automaticamente URLs en mensajes SMS entrantes y las analiza sin intervencion del usuario. Funciona incluso cuando la app esta cerrada.

### Arquitectura SMS

```
+-------------------+
|   SMS ENTRANTE    |
|   (cualquier app) |
+--------+----------+
         |
         | Android Broadcast
         v
+------------------------+
|   SmsReceiver          |
|   (BroadcastReceiver)  |
|                        |
| - Detecta SMS_RECEIVED |
| - Extrae URLs (regex)  |
| - Valida formato URL   |
+--------+---------------+
         |
         | URL encontrada
         v
+------------------------+        +-------------------+
|   SmsAnalyzer          | -----> |    BACKEND        |
|   (Background Thread)  |        |    (FastAPI)      |
|                        | <----- |                   |
| - POST /analyze        |        | {score, risk,     |
| - Timeout: 15s         |        |  signals}         |
+--------+---------------+        +-------------------+
         |
         | Si riesgo MEDIUM/HIGH
         v
+------------------------+
|   NotificationHelper   |
|                        |
| - Canal HIGH (rojo)    |
| - Canal MEDIUM (naranja)|
| - Vibracion + LED      |
| - Abre app al tocar    |
+------------------------+
```

### Permisos Requeridos

| Permiso | Uso | Obligatorio |
|---------|-----|-------------|
| `RECEIVE_SMS` | Detectar SMS entrantes | Si |
| `READ_SMS` | Leer contenido del SMS | Si |
| `POST_NOTIFICATIONS` | Mostrar alertas (Android 13+) | Si |
| `VIBRATE` | Vibrar en alertas de alto riesgo | No |
| `INTERNET` | Comunicarse con el backend | Si |

**Nota:** NO se solicitan permisos innecesarios como bateria, ubicacion, camara, etc.

### Flujo de Deteccion

1. **Llega SMS** con URL sospechosa
2. **SmsReceiver** detecta el broadcast `SMS_RECEIVED`
3. **Extrae URLs** usando expresion regular
4. **SmsAnalyzer** envia URL al backend (thread separado)
5. **Backend responde** con score y nivel de riesgo
6. Si **MEDIUM o HIGH**: muestra notificacion de alerta
7. Si la **app esta abierta**: muestra SnackBar adicional
8. Usuario **toca notificacion**: abre app con detalles

### Canales de Notificacion

| Canal | Nombre | Importancia | Uso |
|-------|--------|-------------|-----|
| `alerta_link_high` | Alertas de Alto Riesgo | HIGH | Score >= 71 |
| `alerta_link_medium` | Alertas de Riesgo Medio | DEFAULT | Score 31-70 |

### Pantalla de Configuracion SMS

```
+----------------------------------+
|  < Proteccion SMS               |
+----------------------------------+
|                                  |
|  +----------------------------+  |
|  |  [ESCUDO VERDE]            |  |
|  |  Proteccion Activa         |  |
|  |  Los SMS seran analizados  |  |
|  +----------------------------+  |
|                                  |
|  Como funciona?                  |
|  1. Recibes SMS con enlace      |
|  2. ALERTA-LINK lo detecta      |
|  3. Se analiza automaticamente  |
|  4. Recibes alerta si peligroso |
|                                  |
|  Permisos necesarios:           |
|  [x] Recibir SMS      [ACTIVO]  |
|  [x] Leer SMS         [ACTIVO]  |
|  [x] Notificaciones   [ACTIVO]  |
|                                  |
|  +----------------------------+  |
|  | Privacidad:                |  |
|  | - Solo analizamos URLs     |  |
|  | - No guardamos mensajes    |  |
|  | - No compartimos datos     |  |
|  +----------------------------+  |
+----------------------------------+
```

### Archivos Kotlin (Android)

| Archivo | Descripcion |
|---------|-------------|
| `SmsReceiver.kt` | BroadcastReceiver que detecta SMS entrantes |
| `SmsAnalyzer.kt` | Envia URLs al backend y procesa resultados |
| `NotificationHelper.kt` | Crea y muestra notificaciones de alerta |
| `MainActivity.kt` | Maneja permisos y Platform Channels |

### Archivos Dart (Flutter)

| Archivo | Descripcion |
|---------|-------------|
| `sms_service.dart` | Comunicacion Flutter <-> Android via MethodChannel |
| `sms_protection_screen.dart` | UI para configurar proteccion SMS |

---

## Pantallas

### 1. Home (Input URL)

**Funcionalidad:**
- Campo de texto para pegar URL
- Boton "Analizar"
- Toggle Cloud-Assisted con consentimiento
- Badge dinamico OFFLINE/CLOUD
- Recibe URLs compartidas desde otras apps (Share Intent)
- Historial local (ultimos 10 analisis)

**UI:**
```
+----------------------------------+
|  ALERTA-LINK           [?]      |
+----------------------------------+
|                                  |
|         [ESCUDO]                 |
|         OFFLINE                  |
|                                  |
|  Pega aqui el enlace sospechoso: |
|  +----------------------------+  |
|  | https://...          [PEGAR]  |
|  +----------------------------+  |
|                                  |
|  [       ANALIZAR URL       ]    |
|                                  |
|  +----------------------------+  |
|  | Cloud-Assisted    [TOGGLE]   |
|  | Analisis 100% local          |
|  +----------------------------+  |
|                                  |
|  Universidad Manuela Beltran    |
+----------------------------------+
```

### 2. Resultado

**Funcionalidad:**
- Semaforo visual (verde/amarillo/rojo)
- Score numerico 0-100
- Veredicto con icono y explicacion
- Lista de senales detectadas con peso
- Recomendaciones de seguridad
- Boton "Reportar" (solo si es sospechoso)
- Info tecnica (tiempo de analisis, modo)
- Compartir resultado

**UI:**
```
+----------------------------------+
|  < Resultado del Analisis  [SHARE]
+----------------------------------+
|       [SEMAFORO ROJO]            |
|        Score: 85/100             |
+----------------------------------+
|                                  |
|  URL analizada:                  |
|  +----------------------------+  |
|  | http://banc0-xyz.tk/login |  |
|  +----------------------------+  |
|                                  |
|  [!] URL PELIGROSA              |
|  Esta URL presenta multiples     |
|  indicadores de phishing.       |
|                                  |
|  Senales detectadas (5):        |
|  +----------------------------+  |
|  | ! IP como host       +25  |  |
|  | ! TLD de riesgo      +15  |  |
|  | ! Sin HTTPS          +10  |  |
|  | ! Palabras sospechosas +20 |  |
|  | ! Typosquatting      +15  |  |
|  +----------------------------+  |
|                                  |
|  Recomendaciones:               |
|  1. No ingrese datos personales |
|  2. Verifique URL oficial       |
|  3. Reporte este enlace         |
|                                  |
|  [    REPORTAR ESTE ENLACE    ] |
|  [    ANALIZAR OTRA URL       ] |
|                                  |
|  Analisis local | 15ms          |
+----------------------------------+
```

### 3. Reportar

**Funcionalidad:**
- Verificacion de conectividad
- Tipo de amenaza (phishing/malware/scam/unknown)
- Comentario opcional (donde lo recibio)
- Dialogo de consentimiento antes de enviar
- Guardado local si no hay internet
- Envio automatico cuando haya conexion

**UI:**
```
+----------------------------------+
|  < Reportar URL                 |
+----------------------------------+
|  [ONLINE] Conectado al servidor  |
+----------------------------------+
|                                  |
|  URL a reportar:                |
|  +----------------------------+  |
|  | http://banc0-xyz.tk/login |  |
|  +----------------------------+  |
|                                  |
|  Que tipo de amenaza es?        |
|  +----------------------------+  |
|  | [X] Phishing              |  |
|  |     Roba credenciales     |  |
|  +----------------------------+  |
|  | [ ] Malware               |  |
|  |     Descarga software     |  |
|  +----------------------------+  |
|  | [ ] Estafa                |  |
|  |     Fraude, premios falsos |  |
|  +----------------------------+  |
|  | [ ] No estoy seguro       |  |
|  +----------------------------+  |
|                                  |
|  Comentario (opcional):         |
|  +----------------------------+  |
|  | Recibi este SMS de...     |  |
|  +----------------------------+  |
|                                  |
|  [       ENVIAR REPORTE       ] |
|                                  |
|  Tu reporte es anonimo          |
+----------------------------------+
```

---

## Motor Heuristico Local

El `LocalAnalyzer` aplica 15+ reglas heuristicas sin necesidad de internet:

### Reglas y Pesos

| Regla | Peso | Descripcion |
|-------|------|-------------|
| IP_AS_HOST | 25 | URL usa IP en lugar de dominio |
| HTTP_NO_HTTPS | 10 | Sin certificado SSL |
| SUSPICIOUS_TLD | 15 | TLDs riesgosos (.tk, .ml, .xyz, etc.) |
| EXCESSIVE_SUBDOMAINS | 12 | Mas de 3 subdominios |
| SUSPICIOUS_WORDS | 8-20 | Palabras como "verify", "suspend", "update-security" |
| BRAND_IMPERSONATION | 30 | Suplantacion de marcas (bancolombia, davivienda, etc.) |
| URL_SHORTENER | 15 | Uso de acortadores (bit.ly, t.co) |
| LONG_PATH | 8 | Path excesivamente largo |
| ENCODED_CHARS | 10 | Caracteres codificados en URL |
| LOGIN_FORM_KEYWORDS | 12 | Palabras relacionadas con login |
| TYPOSQUATTING | 25 | Dominios similares a marcas legitimas |
| NUMERIC_DOMAIN | 8 | Dominios con muchos numeros |

### Umbrales de Riesgo

| Nivel | Score | Color |
|-------|-------|-------|
| LOW | 0-30 | Verde |
| MEDIUM | 31-70 | Amarillo |
| HIGH | 71-100 | Rojo |

---

## Servicios

### LocalAnalyzer
Analisis heuristico 100% offline.
```dart
final analyzer = LocalAnalyzer();
final result = analyzer.analyze('https://suspicious-url.tk');
// result.score, result.riskLevel, result.signals, result.recommendations
```

### ConnectivityService
Verifica conexion a internet y disponibilidad del servidor.
```dart
final hasInternet = await ConnectivityService.hasInternet();
final serverOk = await ConnectivityService.isServerAvailable(baseUrl);
```

### PreferencesService
Maneja preferencias y consentimiento del usuario.
```dart
await preferencesService.setCloudAssistedEnabled(true);
await preferencesService.addToHistory(url, score, riskLevel);
```

### ShareIntentService
Recibe URLs compartidas desde otras apps.
```dart
shareIntentService.onUrlReceived = (url) {
  // URL compartida desde SMS, WhatsApp, etc.
};
shareIntentService.initialize();
```

### ApiService
Comunicacion con backend (opcional).
```dart
final api = ApiService();
final result = await api.analyzeUrl(url);
await api.reportUrl(url: url, label: 'phishing');
```

### SmsService
Maneja comunicacion con Android para deteccion de SMS.
```dart
// Inicializar (en main.dart)
SmsService.initialize();

// Verificar permisos
final hasPermission = await SmsService.hasSmsPermission();
final status = await SmsService.getPermissionsStatus();

// Solicitar permisos
await SmsService.requestAllPermissions();

// Escuchar eventos de SMS
SmsService.onSmsUrlAnalyzed = (url, score, riskLevel, sender) {
  // URL analizada desde SMS
};

SmsService.onNotificationOpened = (url, score, riskLevel) {
  // Usuario toco la notificacion
};
```

---

## Configuracion

### API Base URL

Editar `lib/config/api_config.dart`:
```dart
class ApiConfig {
  // Desarrollo (emulador Android)
  static const String baseUrl = 'http://10.0.2.2:8000';

  // Red local
  // static const String baseUrl = 'http://192.168.1.100:8000';

  // Produccion
  // static const String baseUrl = 'https://api.alerta-link.com';
}
```

### Permisos Android

En `android/app/src/main/AndroidManifest.xml`:
```xml
<!-- Internet: Comunicacion con backend -->
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>

<!-- SMS: Deteccion automatica de phishing -->
<uses-permission android:name="android.permission.RECEIVE_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>

<!-- Notificaciones: Alertas al usuario (Android 13+) -->
<uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>

<!-- Vibracion: Alertas de alto riesgo -->
<uses-permission android:name="android.permission.VIBRATE"/>

<!-- Recibir URLs compartidas -->
<intent-filter>
    <action android:name="android.intent.action.SEND"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <data android:mimeType="text/plain"/>
</intent-filter>

<!-- SMS Receiver -->
<receiver
    android:name=".SmsReceiver"
    android:exported="true"
    android:permission="android.permission.BROADCAST_SMS">
    <intent-filter android:priority="999">
        <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
    </intent-filter>
</receiver>
```

---

## Desarrollo

### Requisitos
- Flutter 3.x
- Dart 3.x
- Android Studio / VS Code
- Android SDK 21+ (minSdk)

### Comandos
```bash
cd mobile

# Crear estructura de proyecto (si no existe)
flutter create . --org com.umb --project-name alerta_link

# Instalar dependencias
flutter pub get

# Ejecutar en emulador/dispositivo
flutter run

# Build APK de debug
flutter build apk --debug

# Build APK de release
flutter build apk --release

# Build AAB para Play Store
flutter build appbundle --release

# Analizar codigo
flutter analyze

# Ejecutar tests
flutter test
```

---

## Dependencias

```yaml
# pubspec.yaml
dependencies:
  flutter:
    sdk: flutter
  cupertino_icons: ^1.0.6
  http: ^1.1.0                    # HTTP client (opcional)
  shared_preferences: ^2.2.2      # Almacenamiento local
  receive_sharing_intent: ^1.6.5  # Recibir URLs compartidas
  url_launcher: ^6.2.2            # Abrir URLs externas
```

---

## Flujo de Usuario

### Escenario 1: Analisis desde SMS

1. **Usuario recibe SMS sospechoso**
   - "Tu cuenta sera suspendida. Verifica: http://banco-xyz.tk/verify"

2. **Copia enlace y abre ALERTA-LINK**
   - Pega URL en el campo de texto
   - Presiona "ANALIZAR URL"

3. **App analiza localmente (15ms)**
   - LocalAnalyzer aplica reglas heuristicas
   - Calcula score y senales

4. **Muestra resultado**
   - Semaforo ROJO (score 87/100)
   - Senales: "TLD de riesgo", "Typosquatting", "Sin HTTPS"
   - Recomendacion: "No ingrese datos personales"

5. **Usuario reporta (opcional)**
   - Presiona "Reportar este enlace"
   - Acepta consentimiento
   - Se envia al servidor (o guarda local si offline)

### Escenario 2: Deteccion Automatica desde SMS (v1.2.0)

1. **Usuario recibe SMS con enlace sospechoso**
   - "BANCOLOMBIA: Su cuenta sera bloqueada. Verifique: http://bancol0mbia.xyz/verify"

2. **SmsReceiver detecta el SMS automaticamente**
   - Funciona incluso con la app cerrada
   - Extrae la URL del mensaje

3. **SmsAnalyzer envia al backend**
   - Analiza en background (thread separado)
   - No bloquea el telefono

4. **Backend responde: Score 92, HIGH RISK**

5. **NotificationHelper muestra alerta**
   - Notificacion de alta prioridad con vibracion
   - "ALERTA: URL Peligrosa Detectada"
   - "De: +57... | Riesgo: 92/100"

6. **Usuario toca la notificacion**
   - Abre ALERTA-LINK con detalles completos
   - Ve todas las senales detectadas

### Escenario 3: Compartir desde WhatsApp

1. **Usuario recibe mensaje de WhatsApp con enlace**

2. **Long-press en URL > Compartir > ALERTA-LINK**
   - Share Intent recibe la URL automaticamente

3. **App muestra URL y boton para analizar**
   - Snackbar: "URL recibida - Presiona ANALIZAR"

4. **Analisis y resultado igual que escenario 1**

---

## Manejo de Errores

| Situacion | Comportamiento |
|-----------|----------------|
| Sin internet | Analisis 100% local funciona normalmente |
| Servidor caido | Fallback automatico a analisis local |
| URL invalida | Mensaje "La URL no tiene un formato valido" |
| Cloud sin consentimiento | Dialogo de consentimiento antes de activar |
| Reporte offline | Guardado local, envio cuando haya conexion |

---

## Estado del Desarrollo - Fase 3 (Completada)

| Componente | Estado |
|------------|--------|
| Pantalla Home | COMPLETADO |
| Toggle Cloud-Assisted | COMPLETADO |
| Pantalla Resultado | COMPLETADO |
| Semaforo + Score + Senales | COMPLETADO |
| Pantalla Reportar | COMPLETADO |
| Consentimiento Reporte | COMPLETADO |
| Share Intent | COMPLETADO |
| LocalAnalyzer (15+ reglas) | COMPLETADO |
| ConnectivityService | COMPLETADO |
| PreferencesService | COMPLETADO |
| Historial local | COMPLETADO |
| Integracion API (opcional) | COMPLETADO |
| **Proteccion SMS (v1.2.0)** | **COMPLETADO** |
| SmsReceiver (BroadcastReceiver) | COMPLETADO |
| SmsAnalyzer (analisis background) | COMPLETADO |
| NotificationHelper (alertas) | COMPLETADO |
| SmsProtectionScreen (UI) | COMPLETADO |
| Permisos SMS runtime | COMPLETADO |

---

## Autores

- Cristia Salazar
- Samuel Ortiz Ospina
- Juan Stiven Castro

**Universidad Manuela Beltran - 2025**

---

**Ultima actualizacion:** 2026-01-23
