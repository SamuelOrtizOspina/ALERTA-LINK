# ALERTA-LINK - Reporte de Auditoria de Seguridad

**Fecha:** 2026-01-09
**Auditor:** Security Tester (Claude)
**Version Auditada:** 0.1.0

---

## Resumen Ejecutivo

| Severidad | Cantidad | Estado |
|-----------|----------|--------|
| CRITICA | 2 | Requiere accion inmediata |
| ALTA | 4 | Requiere correccion antes de produccion |
| MEDIA | 5 | Corregir en proxima iteracion |
| BAJA | 4 | Mejoras recomendadas |
| INFO | 3 | Notas informativas |

**Riesgo General:** MEDIO-ALTO (no listo para produccion sin correcciones)

---

## VULNERABILIDADES CRITICAS (2)

### CRIT-01: CORS Configurado como Wildcard (*)

**Archivo:** `backend/app/core/config.py:72`
```python
CORS_ORIGINS: str = "*"
```

**Archivo:** `backend/app/main.py:75-81`
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,  # <-- "*" permite cualquier origen
    allow_credentials=True,  # <-- PELIGROSO con *
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Riesgo:** Un atacante puede hacer requests desde cualquier sitio web malicioso y:
- Robar datos de usuarios autenticados
- Realizar CSRF (Cross-Site Request Forgery)
- Acceder a la API desde dominios no autorizados

**Impacto:** CRITICO - Violacion de Same-Origin Policy

**Recomendacion:**
```python
# En produccion, especificar dominios exactos:
CORS_ORIGINS: str = "https://alertalink.co,https://app.alertalink.co"

# NUNCA usar allow_credentials=True con origins="*"
```

---

### CRIT-02: Trafico HTTP en Texto Plano Permitido (Android)

**Archivo:** `alerta_link_flutter/android/app/src/main/AndroidManifest.xml:11`
```xml
android:usesCleartextTraffic="true"
```

**Riesgo:**
- Las comunicaciones HTTP no estan cifradas
- Ataques Man-in-the-Middle (MITM) pueden interceptar:
  - URLs analizadas (privacidad del usuario)
  - API keys en headers
  - Datos sensibles

**Impacto:** CRITICO - Exposicion de datos en transito

**Recomendacion:**
```xml
<!-- Solo para desarrollo local -->
android:usesCleartextTraffic="false"

<!-- Usar Network Security Config para excepciones especificas -->
android:networkSecurityConfig="@xml/network_security_config"
```

Crear `network_security_config.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <!-- Solo para debug local -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

---

## VULNERABILIDADES ALTAS (4)

### HIGH-01: Secret Key Hardcodeada con Valor por Defecto

**Archivo:** `backend/app/core/config.py:42`
```python
SECRET_KEY: str = "dev-secret-key-cambiar-en-produccion"
```

**Riesgo:** Si se despliega sin cambiar:
- Tokens JWT pueden ser falsificados
- Sessions pueden ser hijackeadas
- Cualquier funcionalidad criptografica esta comprometida

**Impacto:** ALTO - Compromiso de autenticacion

**Recomendacion:**
```python
# Hacer la key obligatoria sin default
SECRET_KEY: str = Field(..., env='SECRET_KEY')  # Sin valor default

# O validar en startup
def __init__(self):
    if self.SECRET_KEY == "dev-secret-key-cambiar-en-produccion":
        raise ValueError("SECRET_KEY no configurada para produccion")
```

---

### HIGH-02: Credenciales de Base de Datos en Texto Plano

**Archivo:** `backend/app/core/config.py:39`
```python
DATABASE_URL: str = "postgresql://alerta:alerta123@localhost:5432/alertalink"
```

**Riesgo:**
- Password "alerta123" es extremadamente debil
- Credenciales por defecto conocidas
- Si se sube a git accidentalmente, exposicion total

**Impacto:** ALTO - Acceso no autorizado a BD

**Recomendacion:**
```python
# Sin valor default - forzar configuracion via .env
DATABASE_URL: str = ""

# Validar en startup
if not settings.DATABASE_URL:
    logger.warning("DATABASE_URL no configurada - usando fallback JSONL")
```

---

### HIGH-03: URL Base del API Hardcodeada (Flutter)

**Archivo:** `alerta_link_flutter/lib/services/api_service.dart:10`
```dart
static String baseUrl = 'http://10.0.2.2:8000';  // HTTP, no HTTPS
```

**Riesgo:**
- URL en texto plano en el codigo fuente
- Usa HTTP en lugar de HTTPS
- IP de emulador hardcodeada para produccion

**Impacto:** ALTO - MITM, exposicion de configuracion

**Recomendacion:**
```dart
// Usar configuracion por ambiente
class ApiConfig {
  static String get baseUrl {
    const isProduction = bool.fromEnvironment('dart.vm.product');
    if (isProduction) {
      return 'https://api.alertalink.co';  // HTTPS obligatorio
    }
    return const String.fromEnvironment(
      'API_URL',
      defaultValue: 'http://10.0.2.2:8000'
    );
  }
}
```

---

### HIGH-04: Deserializacion Insegura de Pickle

**Archivo:** `backend/app/services/predictor.py:47-49`
```python
with open(model_path, 'rb') as f:
    model_data = pickle.load(f)  # <-- Peligroso
```

**Riesgo:**
- `pickle.load()` puede ejecutar codigo arbitrario
- Si un atacante reemplaza el archivo .pkl, puede obtener RCE
- El archivo .pkl no tiene verificacion de integridad

**Impacto:** ALTO - Remote Code Execution (RCE)

**Recomendacion:**
```python
import hashlib

# Verificar hash del modelo antes de cargar
EXPECTED_MODEL_HASH = "sha256:abc123..."  # Hash conocido

def load_model(self):
    model_path = settings.MODEL_PATH

    # Verificar integridad
    with open(model_path, 'rb') as f:
        content = f.read()
        actual_hash = f"sha256:{hashlib.sha256(content).hexdigest()}"

    if actual_hash != EXPECTED_MODEL_HASH:
        raise SecurityError("Modelo ML corrupto o modificado")

    # Ahora cargar
    model_data = pickle.loads(content)
```

---

## VULNERABILIDADES MEDIAS (5)

### MED-01: Logging de Informacion Sensible

**Archivo:** `backend/app/api/routes/analyze.py:75`
```python
logger.info(f"Analizando URL en modo {mode_used.value}: tranco={use_tranco}, vt={use_virustotal}")
```

**Riesgo:** URLs potencialmente sensibles en logs

**Recomendacion:** Truncar o hashear URLs en logs

---

### MED-02: Sin Rate Limiting en Endpoints

**Archivos:** Todos los endpoints en `backend/app/api/routes/`

**Riesgo:**
- Abuso de API (DoS)
- Consumo excesivo de API VirusTotal (limite 4/min)
- Brute force posible

**Recomendacion:**
```python
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@router.post("/analyze")
@limiter.limit("10/minute")
async def analyze_url(request: Request, ...):
```

---

### MED-03: NotificationListenerService Expuesto

**Archivo:** `alerta_link_flutter/android/app/src/main/AndroidManifest.xml:52-53`
```xml
<service
    android:name=".PushListenerService"
    android:exported="true"  <!-- Peligroso -->
```

**Riesgo:** Otras apps maliciosas podrian interactuar con el servicio

**Recomendacion:** Ya tiene permiso requerido, pero considerar `exported="false"` si no es necesario

---

### MED-04: Sin Validacion de Input en Comentarios de Reportes

**Archivo:** `backend/app/api/routes/report.py`

**Riesgo:**
- XSS almacenado si comentarios se muestran sin sanitizar
- Injection en JSONL

**Recomendacion:** Sanitizar `comment` y `contact` antes de guardar

---

### MED-05: Timeout Muy Largo en Requests HTTP

**Archivo:** `alerta_link_flutter/lib/services/api_service.dart:32`
```dart
.timeout(const Duration(seconds: 30));
```

**Riesgo:** DoS por conexiones lentas

**Recomendacion:** Reducir a 10-15 segundos

---

## VULNERABILIDADES BAJAS (4)

### LOW-01: DEBUG Mode Configurable

**Archivo:** `backend/app/core/config.py:29`
```python
DEBUG: bool = False
```
**Nota:** Esta bien por defecto, asegurar que NUNCA sea True en produccion

---

### LOW-02: Sin Cabeceras de Seguridad HTTP

**Recomendacion:** Agregar middleware con:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000`

---

### LOW-03: Versionado de API sin Deprecation Strategy

El API usa `/api/v1` pero no hay plan de deprecacion documentado

---

### LOW-04: Intent Filters Muy Amplios

**Archivo:** `AndroidManifest.xml:41-48`
```xml
<intent-filter>
    <data android:scheme="http" />
    <data android:scheme="https" />
</intent-filter>
```

**Riesgo:** App puede ser invocada por cualquier URL, considerar usar App Links verificados

---

## NOTAS INFORMATIVAS (3)

### INFO-01: Proteccion SSRF Implementada

**Archivo:** `backend/app/core/security.py`

Buena implementacion de validacion SSRF:
- Bloquea IPs privadas
- Bloquea localhost
- Bloquea metadata endpoints (AWS, GCP)
- Resolucion DNS segura

---

### INFO-02: API Keys en .env (Correcto)

El archivo `.env` esta en `.gitignore` - correcto

---

### INFO-03: Fallback JSONL sin Autenticacion

Cuando PostgreSQL no esta disponible, los datos se guardan en archivos JSONL sin proteccion adicional. Aceptable para desarrollo.

---

## RESUMEN DE ACCIONES REQUERIDAS

### Antes de Produccion (Bloqueantes)

| # | Vulnerabilidad | Accion | Prioridad |
|---|----------------|--------|-----------|
| 1 | CRIT-01 | Configurar CORS con dominios especificos | P0 |
| 2 | CRIT-02 | Deshabilitar cleartext traffic | P0 |
| 3 | HIGH-01 | Eliminar SECRET_KEY default | P0 |
| 4 | HIGH-02 | Eliminar DATABASE_URL default | P0 |
| 5 | HIGH-03 | Usar HTTPS en produccion | P0 |
| 6 | HIGH-04 | Verificar hash de modelo ML | P1 |

### Mejoras Recomendadas

| # | Vulnerabilidad | Accion | Prioridad |
|---|----------------|--------|-----------|
| 7 | MED-02 | Implementar rate limiting | P1 |
| 8 | MED-04 | Sanitizar inputs de reportes | P1 |
| 9 | LOW-02 | Agregar cabeceras de seguridad | P2 |
| 10 | MED-05 | Reducir timeouts | P2 |

---

## CONCLUSION

El sistema ALERTA-LINK tiene una base de seguridad razonable para desarrollo (proteccion SSRF, API keys en .env), pero requiere **correcciones criticas antes de despliegue en produccion**.

Las vulnerabilidades mas graves son:
1. CORS permisivo con `*`
2. Trafico HTTP sin cifrar en Android
3. Secretos con valores por defecto

Una vez corregidas estas issues, el sistema estara en condiciones aceptables para una prueba piloto controlada.

---

**Proxima Revision Recomendada:** Despues de aplicar correcciones
**Clasificacion:** CONFIDENCIAL - Solo para equipo de desarrollo
