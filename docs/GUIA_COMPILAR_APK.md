# Guia: Compilar el APK de ALERTA-LINK

> Guia paso a paso para compilar el APK de la app movil cada vez que hagas cambios en el codigo Flutter o cambies de dominio.

---

## Cuando necesitas recompilar

Tienes que generar un APK nuevo cada vez que cambies cualquiera de estas cosas:

| Cambio | Archivos afectados |
|--------|--------------------|
| Dominio del backend | `lib/services/api_service.dart`, `SmsAnalyzer.kt`, `network_security_config.xml` |
| Logica de UI | Cualquier archivo en `lib/` |
| Logica de analisis SMS | `android/.../SmsAnalyzer.kt`, `NotificationHelper.kt` |
| Permisos Android | `AndroidManifest.xml` |
| Dependencias | `pubspec.yaml` |
| Version | `pubspec.yaml` (campo `version:`) |

> Si solo cambias archivos del backend (Python), **NO necesitas recompilar el APK**.

---

## Pre-requisitos

Antes de empezar verifica:

```powershell
# Flutter instalado y funcionando
flutter --version
# Debe mostrar: Flutter X.Y.Z, Dart X.Y.Z

# Doctor sin errores criticos
flutter doctor
# Las cosas marcadas con [!] o [X] en Android toolchain hay que resolverlas

# Adb instalado (opcional, solo si vas a instalar por USB)
adb --version
```

---

## Paso 1: Actualizar la version (recomendado)

Edita [alerta_link_flutter/pubspec.yaml](../alerta_link_flutter/pubspec.yaml) linea 19:

```yaml
# Antes
version: 1.2.0+2

# Despues (ejemplo)
version: 1.2.1+3
```

### Como elegir el numero

```
1.2.1+3
^ ^ ^ ^
| | | +-- Build number (debe SIEMPRE incrementar)
| | +---- Patch: solo bug fixes o cambios menores (ej: dominio)
| +------ Minor: nuevas funcionalidades
+-------- Major: cambios grandes que rompen compatibilidad
```

**Ejemplos:**
- Cambias el dominio: `1.2.0` -> `1.2.1` (patch)
- Agregas analisis de WhatsApp: `1.2.1` -> `1.3.0` (minor)
- Rediseno completo de la app: `1.3.0` -> `2.0.0` (major)

> El build number (`+N`) tiene que aumentar **SIEMPRE**, sino Google Play rechaza la subida.

---

## Paso 2: Limpiar builds anteriores

```powershell
cd "C:\Users\samuel Ortiz\Documents\proyecto de tesis\desarrollo\alerta_link_flutter"
flutter clean
```

**Que hace:** Borra `build/`, `.dart_tool/`, `android/.gradle/`. Garantiza que no quede cacheado el codigo viejo.

**Cuando es OBLIGATORIO:**
- Cambiaste la URL del backend
- Cambiaste algo en `android/app/build.gradle`
- Tuviste errores raros en compilacion anterior

---

## Paso 3: Bajar dependencias

```powershell
flutter pub get
```

**Que hace:** Descarga los paquetes que estan en `pubspec.yaml` (http, shared_preferences, etc.).
**Tarda:** 20-60 segundos.

---

## Paso 4: Compilar el APK

```powershell
flutter build apk --release
```

**Que hace:** Compila el codigo Dart, lo combina con el codigo nativo Android, lo firma con la clave de debug (suficiente para tu prueba piloto) y genera el APK final.

**Tarda:** 3-8 minutos la primera vez. 1-3 minutos las siguientes.

**Output esperado al final:**
```
Running Gradle task 'assembleRelease'...
Built build\app\outputs\flutter-apk\app-release.apk (46.5MB).
```

### Variantes utiles

```powershell
# APK liviano por arquitectura (genera 3 APKs mas pequenios)
flutter build apk --release --split-per-abi

# App Bundle (para subir a Play Store)
flutter build appbundle --release

# Debug (mas pesado, pero permite ver logs detallados)
flutter build apk --debug

# Build con URL custom (para testing rapido sin cambiar codigo)
flutter build apk --release --dart-define=API_URL=http://192.168.1.50:8000
```

---

## Paso 5: Renombrar y copiar a la raiz

El APK queda en `build\app\outputs\flutter-apk\app-release.apk`. Para tener un archivo con nombre claro:

```powershell
Copy-Item "build\app\outputs\flutter-apk\app-release.apk" "..\ALERTA-LINK-v1.2.1.apk" -Force
```

Ajusta el numero de version al que pusiste en `pubspec.yaml`.

---

## Script todo-en-uno

Si quieres pegar todo de una vez (ajusta el numero de version):

```powershell
$version = "1.2.1"
cd "C:\Users\samuel Ortiz\Documents\proyecto de tesis\desarrollo\alerta_link_flutter"
flutter clean
flutter pub get
flutter build apk --release
Copy-Item "build\app\outputs\flutter-apk\app-release.apk" "..\ALERTA-LINK-v$version.apk" -Force
Write-Host ""
Write-Host "APK listo: ..\ALERTA-LINK-v$version.apk" -ForegroundColor Green
Get-Item "..\ALERTA-LINK-v$version.apk" | Select-Object Name, @{N="Size MB";E={[math]::Round($_.Length/1MB,1)}}, LastWriteTime
```

---

## Instalar el APK en el celular

### Opcion 1: USB con adb (mas rapido)

**Pre-requisitos en el celular:**
1. Configuracion -> Acerca del telefono -> tocar 7 veces "Numero de compilacion"
2. Configuracion -> Opciones de desarrollador (apareci aparte) -> activar **Depuracion USB**

**En el PC:**
```powershell
cd "C:\Users\samuel Ortiz\Documents\proyecto de tesis\desarrollo"
adb install -r ALERTA-LINK-v1.2.1.apk
```

> `-r` = reinstalar/actualizar (mantiene los datos de la app).
> Sin `-r` requiere desinstalar primero.

### Opcion 2: Transferencia de archivos

1. Copia `ALERTA-LINK-v1.2.1.apk` al celular (USB, Drive, WhatsApp, email, Bluetooth, etc.)
2. Asegurate que el celular permite instalar "apps de origen desconocido":
   - Configuracion -> Seguridad -> Instalar apps desconocidas
   - O cuando intentes instalar, Android te pedira permiso
3. Abre el APK en el celular -> Toca **Instalar**

### Opcion 3: ADB inalambrico (Android 11+)

```powershell
# Una vez conectado por USB para emparejar
adb pair <celular_ip>:<puerto>
adb connect <celular_ip>:5555

# Despues ya puedes instalar sin cable
adb install -r ALERTA-LINK-v1.2.1.apk
```

---

## IMPORTANTE: Antes de instalar

**Desinstala la version anterior** si tiene una URL distinta:

- Mantén presionado el ícono de **ALERTA-LINK** -> Desinstalar

O por adb:
```powershell
adb uninstall com.alertalink.alerta_link
```

**Por que:** Si no desinstalas, Android puede dar error de "firma incompatible" o quedarse con cache de la URL vieja.

---

## Verificar que la instalacion funciona

Una vez instalado:

1. Abre **ALERTA-LINK** en el celular
2. Verifica que el backend + tunnel siguen corriendo en tu PC
3. Prueba con una URL segura:
   ```
   https://www.google.com
   ```
   Esperado: semaforo **VERDE** ✅
4. Prueba con una URL de phishing:
   ```
   http://secure-paypal-verify.xyz
   ```
   Esperado: semaforo **ROJO** 🔴 con 5+ senales

---

## Troubleshooting

### `flutter clean` falla con "ERROR: file in use"

**Causa:** Algun proceso esta usando un archivo de `build/`.
**Solucion:** Cierra Android Studio, VS Code, emulador, y vuelve a intentar.

### `flutter build apk` falla con "Could not resolve all dependencies"

**Causa:** Sin internet o problemas de proxy.
**Solucion:**
```powershell
flutter pub get
# Reintentar
flutter build apk --release
```

### "Gradle build failed - SDK location not found"

**Causa:** Variable `ANDROID_HOME` no esta configurada.
**Solucion:**
1. Verifica donde tienes el Android SDK (ej: `C:\Users\<user>\AppData\Local\Android\Sdk`)
2. Crea `alerta_link_flutter/android/local.properties` con:
   ```
   sdk.dir=C:\\Users\\<user>\\AppData\\Local\\Android\\Sdk
   flutter.sdk=C:\\Users\\<user>\\flutter
   ```

### APK instala pero la app cierra al abrir

**Causa:** Crash en runtime. Conecta el celular por USB y mira los logs:
```powershell
adb logcat | findstr "ALERTA-LINK"
# O para ver todos los crashes:
adb logcat *:E
```

### El analizador dice "Sin conexion al servidor"

**Causa:** El backend o el tunnel no estan corriendo, o la URL en el APK esta mal.
**Solucion:**
1. Verifica que `curl https://alerta.mirrorhub.tech/health` responde 200
2. Si si responde pero la app no -> el APK fue compilado con URL vieja, recompila

### "Cleartext HTTP traffic not permitted"

**Causa:** Estas intentando usar `http://` (sin S) pero el `network_security_config.xml` solo permite HTTPS para tu dominio.
**Solucion:** Usa siempre `https://`. Si necesitas HTTP para pruebas locales, asegurate que el dominio este en la seccion de `cleartextTrafficPermitted="true"` del XML.

### El APK pesa demasiado (>50 MB)

**Solucion:** Usa `--split-per-abi` para generar 3 APKs mas pequenios (uno por arquitectura: arm, arm64, x86):
```powershell
flutter build apk --release --split-per-abi
```
Quedan en `build\app\outputs\flutter-apk\` como:
- `app-armeabi-v7a-release.apk` (~17 MB)
- `app-arm64-v8a-release.apk` (~18 MB)
- `app-x86_64-release.apk` (~19 MB)

Solo necesitas instalar el que coincida con la arquitectura del celular (la mayoria son `arm64-v8a` en 2025).

---

## Checklist antes de distribuir el APK

- [ ] La version en `pubspec.yaml` esta actualizada
- [ ] El backend en `lib/services/api_service.dart` apunta al dominio correcto
- [ ] El backend + tunnel funcionan (`curl /health` responde 200)
- [ ] `flutter clean` ejecutado antes del build
- [ ] APK probado en al menos 1 celular real
- [ ] URL segura probada (Google) -> semaforo verde
- [ ] URL phishing probada -> semaforo rojo
- [ ] Apk renombrado con la version (`ALERTA-LINK-vX.Y.Z.apk`)

---

## Comandos de referencia rapida

```powershell
# Compilar APK completo
cd alerta_link_flutter && flutter clean && flutter pub get && flutter build apk --release

# Solo verificar errores sin compilar
flutter analyze

# Probar la app en modo desarrollo (sin compilar APK)
flutter run

# Listar dispositivos conectados
flutter devices
# o
adb devices

# Ver logs en tiempo real
adb logcat | findstr -i "alerta"

# Desinstalar la app
adb uninstall com.alertalink.alerta_link

# Reinstalar manteniendo datos
adb install -r ALERTA-LINK-v1.2.1.apk
```

---

## Donde queda cada cosa

| Que | Donde |
|-----|-------|
| Codigo fuente Dart | `alerta_link_flutter/lib/` |
| Codigo nativo Android | `alerta_link_flutter/android/app/src/main/kotlin/` |
| Recursos (XML, iconos) | `alerta_link_flutter/android/app/src/main/res/` |
| Manifesto Android | `alerta_link_flutter/android/app/src/main/AndroidManifest.xml` |
| Dependencias Flutter | `alerta_link_flutter/pubspec.yaml` |
| APK generado | `alerta_link_flutter/build/app/outputs/flutter-apk/app-release.apk` |
| APK renombrado | `ALERTA-LINK-vX.Y.Z.apk` (raiz del proyecto) |

---

## Historial de versiones

| Version | Fecha | Cambios | Dominio |
|---------|-------|---------|---------|
| 1.2.0 | 2026-01-23 | Deteccion automatica de SMS phishing | samuelortizospina.me (obsoleto) |
| 1.2.1 | 2026-05-16 | Migracion a nuevo dominio | alerta.mirrorhub.tech |

---

**Ultima actualizacion:** 2026-05-16
