# ALERTA-LINK - Correcciones de Seguridad Implementadas

**Fecha:** 2026-01-09
**Version:** 0.1.0 -> 0.1.1 (Security Patch)

---

## Resumen de Correcciones

| ID | Severidad | Problema | Estado |
|----|-----------|----------|--------|
| CRIT-01 | CRITICA | CORS = "*" | CORREGIDO |
| CRIT-02 | CRITICA | cleartext traffic Android | CORREGIDO |
| HIGH-01 | ALTA | SECRET_KEY con default | CORREGIDO |
| HIGH-02 | ALTA | DATABASE_URL con password debil | CORREGIDO |
| HIGH-03 | ALTA | URL HTTP hardcodeada | CORREGIDO |
| HIGH-04 | ALTA | pickle.load sin verificacion | CORREGIDO |
| MED-02 | MEDIA | Sin rate limiting | CORREGIDO |

---

## Detalle de Correcciones

### CRIT-01: CORS Configurado Correctamente

**Archivo:** `backend/app/core/config.py`

**Antes:**
```python
CORS_ORIGINS: str = "*"
```

**Despues:**
```python
CORS_ORIGINS: str = "https://samuelortizospina.me,https://api.samuelortizospina.me,http://localhost:8000,http://10.0.2.2:8000"
```

**Archivo:** `backend/app/main.py`

**Cambios:**
- Usa `settings.cors_origins_list` en lugar de string
- Metodos HTTP especificos en lugar de "*"
- Headers especificos permitidos

---

### CRIT-02: Cleartext Traffic Deshabilitado

**Archivo nuevo:** `alerta_link_flutter/android/app/src/main/res/xml/network_security_config.xml`

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <!-- Excepcion solo para desarrollo local -->
    <domain-config cleartextTrafficPermitted="true">
        <domain>10.0.2.2</domain>
        <domain>localhost</domain>
    </domain-config>
</network-security-config>
```

**Archivo:** `AndroidManifest.xml`

**Antes:**
```xml
android:usesCleartextTraffic="true"
```

**Despues:**
```xml
android:networkSecurityConfig="@xml/network_security_config"
```

---

### HIGH-01 & HIGH-02: Secrets sin Valores Default

**Archivo:** `backend/app/core/config.py`

**Antes:**
```python
DATABASE_URL: str = "postgresql://alerta:alerta123@localhost:5432/alertalink"
SECRET_KEY: str = "dev-secret-key-cambiar-en-produccion"
```

**Despues:**
```python
DATABASE_URL: str = ""
SECRET_KEY: str = ""
```

**Agregado:** Funcion `validate_security()` que verifica configuracion critica.

---

### HIGH-03: URL HTTPS con Dominio Configurable

**Archivo:** `alerta_link_flutter/lib/services/api_service.dart`

**Antes:**
```dart
static String baseUrl = 'http://10.0.2.2:8000';
```

**Despues:**
```dart
class ApiConfig {
  static const String productionUrl = 'https://api.samuelortizospina.me';
  static const String developmentUrl = 'http://10.0.2.2:8000';

  static String get baseUrl {
    return isProduction ? productionUrl : developmentUrl;
  }
}
```

---

### HIGH-04: Verificacion Hash del Modelo ML

**Archivo:** `backend/app/services/predictor.py`

**Agregado:**
```python
class URLPredictor:
    AUTHORIZED_MODEL_HASH = "2d9263ff9a4d4a59d2295998672d4c62a602927646a19eb9ca8be322df11e670"

    def _verify_model_integrity(self, model_path):
        # Calcula SHA256 y compara con hash autorizado
        # Rechaza modelo si hash no coincide
```

**Beneficio:** Previene ejecucion de codigo malicioso si el archivo .pkl es modificado.

---

### MED-02: Rate Limiting Implementado

**Archivo:** `backend/requirements.txt`

**Agregado:**
```
slowapi>=0.1.9
```

**Archivo:** `backend/app/main.py`

**Agregado:**
```python
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
```

**Archivo:** `backend/app/api/routes/analyze.py`

**Agregado:**
```python
@router.post("/analyze")
@limiter.limit("30/minute")  # 30 requests por minuto por IP
async def analyze_url(request: Request, data: AnalyzeRequest):
```

---

## Verificacion de Correcciones

### Test CORS
```bash
# Debe rechazar origen no autorizado
curl -H "Origin: https://malicious.com" http://localhost:8000/health
```

### Test Rate Limiting
```bash
# Despues de 30 requests en 1 minuto, debe retornar 429
for i in {1..35}; do curl -X POST http://localhost:8000/analyze -d '{"url":"test.com"}'; done
```

### Test Hash del Modelo
```bash
# Modificar el archivo .pkl y reiniciar el servidor
# Debe mostrar error de hash no coincide
```

---

## Archivos Modificados

1. `backend/app/core/config.py` - CORS, secrets
2. `backend/app/main.py` - CORS middleware, rate limiter
3. `backend/app/api/routes/analyze.py` - Rate limiting
4. `backend/app/services/predictor.py` - Verificacion hash
5. `backend/requirements.txt` - slowapi
6. `alerta_link_flutter/lib/services/api_service.dart` - URL config
7. `alerta_link_flutter/android/app/src/main/AndroidManifest.xml` - Network security
8. `alerta_link_flutter/android/app/src/main/res/xml/network_security_config.xml` - NUEVO
9. `.env.example` - Actualizado con instrucciones

---

## Recomendaciones Adicionales

1. **Antes de produccion:**
   - Generar SECRET_KEY unica
   - Configurar HTTPS en el servidor
   - Revisar logs de seguridad

2. **Monitoreo:**
   - Implementar alertas para rate limit excedido
   - Monitorear intentos de CORS bloqueados

---

**Estado:** Sistema listo para prueba piloto controlada
