# API Reference - ALERTA-LINK

> Documentacion de los endpoints REST del backend

**Base URL:** `http://localhost:8000`

**Documentacion Interactiva:** `http://localhost:8000/docs` (Swagger UI)

---

## Endpoints

### GET /health

Verifica el estado del servicio.

**Request:**
```bash
curl http://localhost:8000/health
```

**Response:**
```json
{
  "status": "ok",
  "version": "0.1.0",
  "model_loaded": true
}
```

---

### POST /analyze

Analiza una URL y devuelve score de riesgo con senales explicables.

**Request:**
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://paypa1-secure.xyz/login",
    "options": {
      "enable_crawler": false,
      "timeout_seconds": 20,
      "max_redirects": 5
    }
  }'
```

**Response:**
```json
{
  "url": "https://paypa1-secure.xyz/login",
  "normalized_url": "https://paypa1-secure.xyz/login",
  "score": 85,
  "risk_level": "HIGH",
  "signals": [
    {
      "id": "SUSPICIOUS_WORDS",
      "severity": "HIGH",
      "weight": 20,
      "evidence": {"count": 4},
      "explanation": "La URL contiene 4 palabras sospechosas asociadas con phishing"
    },
    {
      "id": "RISKY_TLD",
      "severity": "MEDIUM",
      "weight": 10,
      "evidence": {"tld": "xyz"},
      "explanation": "El dominio usa un TLD frecuentemente asociado con sitios maliciosos"
    }
  ],
  "recommendations": [
    "NO ingrese informacion personal o credenciales en este sitio",
    "Esta URL presenta multiples indicadores de phishing",
    "Verifique la URL oficial del servicio que busca"
  ],
  "crawl": {
    "enabled": false,
    "status": "SKIPPED"
  },
  "timestamps": {
    "requested_at": "2026-01-01T12:00:00Z",
    "completed_at": "2026-01-01T12:00:00Z",
    "duration_ms": 45
  }
}
```

**Campos de Request:**

| Campo | Tipo | Requerido | Descripcion |
|-------|------|-----------|-------------|
| url | string | Si | URL a analizar (10-2048 chars) |
| options.enable_crawler | bool | No | Habilitar crawling (default: false) |
| options.timeout_seconds | int | No | Timeout en segundos (default: 20) |
| options.max_redirects | int | No | Max redirects (default: 5) |

**Campos de Response:**

| Campo | Tipo | Descripcion |
|-------|------|-------------|
| score | int | Score de riesgo 0-100 |
| risk_level | string | LOW, MEDIUM, HIGH |
| signals | array | Lista de senales detectadas |
| recommendations | array | Recomendaciones al usuario |

---

### POST /ingest

Ingesta una URL al dataset para futuro entrenamiento.

**Request:**
```bash
curl -X POST http://localhost:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example-phishing.xyz/login",
    "label": 1,
    "source": "manual",
    "metadata": {
      "reporter": "security_team",
      "confidence": "high"
    }
  }'
```

**Response:**
```json
{
  "status": "received",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "stored": true,
  "url_hash": "a1b2c3d4e5f6...",
  "message": "URL ingestada exitosamente"
}
```

**Campos de Request:**

| Campo | Tipo | Requerido | Descripcion |
|-------|------|-----------|-------------|
| url | string | Si | URL a ingestar |
| label | int | No | 0=legitimo, 1=malicioso |
| source | string | No | manual, feed, user, api |
| metadata | object | No | Metadatos adicionales |

---

### POST /report

Reporta una URL sospechosa desde la app movil.

**Request:**
```bash
curl -X POST http://localhost:8000/report \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://suspicious-site.xyz/verify",
    "label": "phishing",
    "comment": "Recibi este enlace por SMS, parece phishing de banco"
  }'
```

**Response:**
```json
{
  "status": "received",
  "report_id": "rpt_550e8400-e29b-41d4-a716-446655440000",
  "message": "Gracias. Tu reporte fue registrado."
}
```

**Campos de Request:**

| Campo | Tipo | Requerido | Descripcion |
|-------|------|-----------|-------------|
| url | string | Si | URL a reportar |
| label | string | Si | phishing, malware, scam, unknown |
| comment | string | No | Comentario del usuario |
| contact | string | No | Contacto opcional |

---

## Codigos de Error

| Codigo | Descripcion |
|--------|-------------|
| 400 | URL invalida o parametros incorrectos |
| 422 | Error de validacion (Pydantic) |
| 500 | Error interno del servidor |

**Ejemplo de Error:**
```json
{
  "detail": "URL invalida: IP privada bloqueada: 192.168.1.1"
}
```

---

## Seguridad SSRF

Todos los endpoints que reciben URLs validan contra SSRF:

- Bloquea IPs privadas (10.x, 172.16-31.x, 192.168.x)
- Bloquea localhost (127.x)
- Bloquea metadata endpoints (169.254.169.254)
- Solo permite HTTP/HTTPS

---

## Rate Limiting

(Por implementar en produccion)

| Endpoint | Limite |
|----------|--------|
| /analyze | 100 req/min |
| /ingest | 50 req/min |
| /report | 20 req/min |

---

**Ultima actualizacion:** 2026-01-01
