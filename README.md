# ALERTA-LINK: Sistema de Analisis Forense Automatico

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Flutter](https://img.shields.io/badge/Flutter-3.10+-02569B.svg)](https://flutter.dev/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-009688.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-Academic-green.svg)](#licencia)

> Sistema forense automatico para detectar URLs de smishing/phishing mediante APP MOVIL con score de riesgo explicable

**Universidad Manuela Beltran** | Ingenieria de Software | 2026

**Autores:** Cristian Salazar, Samuel Ortiz Ospina, Juan Stiven Castro

---

## Tabla de Contenido

1. [Que es ALERTA-LINK](#1-que-es-alerta-link)
2. [Arquitectura del sistema](#2-arquitectura-del-sistema)
3. [Estructura del proyecto](#3-estructura-del-proyecto)
4. [Instalacion y Configuracion](#4-instalacion-y-configuracion)
5. [Base de Datos](#5-base-de-datos)
6. [API Endpoints](#6-api-endpoints)
7. [Motor de Deteccion](#7-motor-de-deteccion)
8. [Integraciones Externas](#8-integraciones-externas)
9. [Dataset y Entrenamiento](#9-dataset-y-entrenamiento)
10. [Scripts Disponibles](#10-scripts-disponibles)
11. [Resultados de Pruebas](#11-resultados-de-pruebas)
12. [Historial de Versiones](#12-historial-de-versiones)

---

## 1. Que es ALERTA-LINK

### El problema
En Colombia el smishing (phishing por SMS) representa el **40% de las estafas digitales**. Segun Kaspersky, Colombia recibio **30.9 millones de intentos de phishing** en 2023. No existe una herramienta **local, gratuita y en espanol** que permita verificar si un enlace es peligroso.

### La solucion
Una **APP MOVIL** (Flutter/Android) donde el usuario:
1. **Pega o comparte una URL sospechosa** (recibida por SMS/WhatsApp)
2. **Recibe un analisis inmediato** con:
   - Score de riesgo (0-100)
   - Semaforo visual (BAJO/MEDIO/ALTO)
   - Senales detectadas con explicacion
   - Recomendaciones de que hacer
3. **Opcionalmente reporta** la URL para ayudar a otros

### Principios del sistema
| Principio | Que significa |
|-----------|---------------|
| **Offline-first** | Analisis basico sin depender de APIs externas |
| **Explicable** | Cada punto del score tiene una razon visible |
| **Privacy by default** | No guarda datos sin consentimiento |
| **Local + Cloud** | Funciona offline, mejora con conexion |

---

## 2. Arquitectura del sistema

```
+-------------------+
|   USUARIO         |
|   (celular)       |
+--------+----------+
         |
         | Comparte/pega URL
         v
+-------------------+          POST /analyze          +-------------------+
|   APP MOVIL       | ------------------------------> |    BACKEND        |
|   (Flutter)       | <------------------------------ |    (FastAPI)      |
|                   |    {score, risk, signals}       |                   |
| - Input URL       |                                 | - /health         |
| - Semaforo        |          POST /report           | - /analyze        |
| - Senales         | ------------------------------> | - /ingest         |
| - Share Target    |                                 | - /report         |
+-------------------+                                 +--------+----------+
                                                               |
                            +----------------------------------+----------------------------------+
                            |                                  |                                  |
                            v                                  v                                  v
                   +-------------------+             +-------------------+             +-------------------+
                   |   ML Model        |             |   Tranco API      |             |   VirusTotal API  |
                   |   (.pkl)          |             |   (Top 1M sites)  |             |   (Threat Intel)  |
                   | LogisticRegression|             |   Dominios legit. |             |   Verificacion    |
                   +-------------------+             +-------------------+             +-------------------+
```

---

## 3. Estructura del proyecto

```
desarrollo/
|
|-- README.md                    # Este archivo
|-- .env                         # Variables de entorno (API keys) - NO SUBIR
|-- .env.example                 # Plantilla de configuracion
|-- .gitignore                   # Archivos ignorados
|
|-- backend/                     # API FastAPI (Python)
|   |-- app/
|   |   |-- main.py              # Punto de entrada
|   |   |-- api/routes/          # Endpoints
|   |   |   |-- analyze.py       # POST /analyze
|   |   |   |-- health.py        # GET /health, /whois
|   |   |   |-- ingest.py        # POST /ingest
|   |   |   |-- report.py        # POST /report
|   |   |   +-- settings.py      # GET/POST /settings
|   |   |-- core/
|   |   |   |-- config.py        # Configuracion (.env)
|   |   |   +-- security.py      # Proteccion SSRF
|   |   |-- db/                  # Capa de base de datos
|   |   |-- models/              # Modelos SQLAlchemy
|   |   |-- schemas/             # Modelos Pydantic
|   |   +-- services/
|   |       |-- predictor.py           # Motor ML (GradientBoosting)
|   |       |-- heuristic_predictor.py # Motor Heuristico
|   |       |-- feature_extractor.py   # 24 features de URLs
|   |       |-- tranco_service.py      # API Tranco
|   |       |-- virustotal_service.py  # API VirusTotal
|   |       |-- whois_service.py       # Verificacion WHOIS
|   |       |-- crawler_service.py     # Crawler Headless
|   |       +-- content_analyzer.py    # Analisis HTML
|   |-- models/                  # Modelos entrenados
|   |   |-- step1_baseline.pkl   # Modelo ML GradientBoosting
|   |   +-- heuristic_weights.json  # Pesos del modelo heuristico
|   +-- requirements.txt
|
|-- alerta_link_flutter/         # APP MOVIL (Flutter/Android)
|   |-- lib/
|   |   |-- main.dart            # Punto de entrada
|   |   |-- ui/                  # Pantallas
|   |   |-- services/            # Servicios (API)
|   |   |-- models/              # Modelos de datos
|   |   +-- logic/               # Logica de negocio
|   |-- android/                 # Configuracion Android
|   +-- pubspec.yaml             # Dependencias Flutter
|
|-- database/                    # Migraciones Alembic
|   |-- alembic.ini
|   +-- migrations/
|
|-- datasets/
|   +-- splits/
|       |-- train.csv            # 6,000 URLs balanceadas
|       |-- val.csv              # 800 URLs validacion
|       +-- test.csv             # 800 URLs prueba
|
|-- scripts/                     # Scripts de utilidad
|
+-- docs/                        # Documentacion
    |-- DOCUMENTACION_MAESTRA.md # Documentacion completa
    +-- database/                # Docs de BD
```

---

## 4. Instalacion y Configuracion

### Requisitos
- Python 3.11+
- pip

### Instalacion

```bash
# 1. Clonar repositorio
git clone <repo-url>
cd desarrollo

# 2. Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# 3. Instalar dependencias
pip install -r backend/requirements.txt

# 4. Configurar variables de entorno
cp .env.example .env
# Editar .env con tus API keys

# 5. Iniciar servidor
cd backend
uvicorn app.main:app --reload --port 8000
```

### Configuracion (.env)

```env
# =============================================================================
# ALERTA-LINK - Variables de Entorno
# =============================================================================

# Base de Datos PostgreSQL
DATABASE_URL=postgresql://alerta:alerta123@localhost:5432/alertalink

# Tranco API - Lista de dominios legitimos (Top 1M)
# Obtener en: https://tranco-list.eu/
TRANCO_API_KEY=tu-api-key-de-tranco
TRANCO_API_EMAIL=tu-email@ejemplo.com
TRANCO_RANK_THRESHOLD=100000

# VirusTotal API - Verificacion de URLs maliciosas
# Obtener en: https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=tu-api-key-de-virustotal
VIRUSTOTAL_THRESHOLD=3            # Minimo detecciones para malicioso
VIRUSTOTAL_UNCERTAINTY_MIN=30     # Score minimo para consultar VT
VIRUSTOTAL_UNCERTAINTY_MAX=70     # Score maximo para consultar VT
```

---

## 5. Base de Datos

### Arquitectura de Persistencia

ALERTA-LINK usa **PostgreSQL** como base de datos principal con **fallback automatico** a archivos JSONL cuando PostgreSQL no esta disponible.

```
┌──────────────┐
│   FastAPI    │
│  (Endpoints) │
└──────┬───────┘
       │
       ▼
┌──────────────────────────────────┐
│     get_db_optional()            │
│  (Dependencia con fallback)      │
└──────┬───────────────┬───────────┘
       │               │
       ▼               ▼
┌────────────┐   ┌────────────┐
│ PostgreSQL │   │   JSONL    │
│ (Primario) │   │ (Fallback) │
└────────────┘   └────────────┘
```

### Tablas

| Tabla | Proposito |
|-------|-----------|
| `ingested_urls` | URLs para entrenamiento del modelo ML |
| `reports` | Reportes de usuarios desde la app movil |
| `analysis_results` | Historico de analisis realizados |

### Configuracion

```bash
# Instalar PostgreSQL (opcional - usa JSONL si no esta disponible)
# Windows: https://www.postgresql.org/download/windows/
# Linux: sudo apt install postgresql

# Crear base de datos
createdb alertalink

# Ejecutar migraciones
cd database
alembic upgrade head
```

### Migraciones Disponibles

| Version | Descripcion |
|---------|-------------|
| 001 | Tablas iniciales (ingested_urls, reports) |
| 002 | Tabla analysis_results para historico |

Ver documentacion completa: [docs/database/DATABASE_INTEGRATION.md](docs/database/DATABASE_INTEGRATION.md)

---

## 6. API Endpoints

### GET /health
Verifica estado del servicio incluyendo base de datos y APIs.

```bash
curl http://localhost:8000/api/v1/health
```

**Response:**
```json
{
  "status": "ok",
  "version": "0.1.0",
  "model_loaded": true,
  "database": {
    "available": true,
    "storage": "postgresql"
  },
  "apis": {
    "tranco": true,
    "virustotal": true
  }
}
```

### GET /health/db
Verifica estado detallado de la base de datos.

```bash
curl http://localhost:8000/api/v1/health/db
```

**Response:**
```json
{
  "status": "connected",
  "engine": "postgresql",
  "host": "localhost:5432/alertalink",
  "pool_size": 5
}
```

### POST /analyze
Analiza una URL y retorna score de riesgo con senales explicables.

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://secure-paypal-verify.xyz/login"}'
```

**Response:**
```json
{
  "url": "https://secure-paypal-verify.xyz/login",
  "score": 100,
  "risk_level": "HIGH",
  "signals": [
    {
      "id": "BRAND_IMPERSONATION",
      "severity": "HIGH",
      "weight": 40,
      "evidence": {
        "brand_detected": "paypal",
        "fake_domain": "secure-paypal-verify.xyz",
        "official_domain": "paypal.com"
      },
      "explanation": "PHISHING DETECTADO: Este sitio 'secure-paypal-verify.xyz' intenta suplantar a 'PAYPAL'. El dominio oficial es 'paypal.com'. NO ingrese sus credenciales."
    },
    {
      "id": "RISKY_TLD",
      "severity": "MEDIUM",
      "weight": 10,
      "explanation": "RIESGO ALTO: El dominio usa '.xyz', un TLD con 60% de tasa de abuso."
    }
  ],
  "recommendations": [
    "NO ingrese informacion personal o credenciales en este sitio",
    "Verifique la URL oficial del servicio que busca"
  ]
}
```

### POST /ingest
Ingesta URLs para entrenamiento futuro.

### POST /report
Reporta URLs sospechosas desde la app movil.

---

## 7. Motor de Deteccion

### Algoritmo de Scoring

```
1. Extrae 24 features de la URL
2. Genera senales heuristicas (14+ tipos)
3. Calcula ML score con LogisticRegression
4. Combina: score = max(ML, heuristic) + critical_boost
5. Si dominio en Tranco: score -= 30 (sitio legitimo)
6. Si score 30-70: consulta VirusTotal
7. Ajusta score final (0-100)
8. Clasifica: LOW (0-30), MEDIUM (31-70), HIGH (71-100)
```

### Senales Detectadas

| Senal | Severidad | Peso | Descripcion |
|-------|-----------|------|-------------|
| BRAND_IMPERSONATION | HIGH | 40 | Suplanta marca conocida |
| IP_AS_HOST | HIGH | 25 | Usa IP en lugar de dominio |
| PUNYCODE_DETECTED | HIGH | 20 | Ataque homografico (xn--) |
| VIRUSTOTAL_DETECTION | HIGH | 10-40 | Detectado por antivirus |
| PASTE_SERVICE | MEDIUM | 20 | Servicio de paste (pastebin) |
| URL_SHORTENER | MEDIUM | 15 | URL acortada |
| RISKY_TLD | MEDIUM | 10-15 | TLD de alto riesgo (.xyz, .tk) |
| SUSPICIOUS_WORDS | MEDIUM | 7-25 | Palabras de phishing |
| DOMAIN_NOT_IN_TRANCO | MEDIUM | 15 | Dominio no verificado |
| AT_SYMBOL | MEDIUM | 15 | Contiene @ (ofuscacion) |
| NO_HTTPS | LOW | 5 | Sin conexion segura |
| LONG_URL | LOW | 5 | URL muy larga |
| HIGH_DIGIT_RATIO | LOW | 5 | Muchos numeros |

### Features del Modelo (24)

| Feature | Tipo | Descripcion |
|---------|------|-------------|
| url_length | int | Longitud total |
| domain_length | int | Longitud del dominio |
| path_length | int | Longitud del path |
| num_digits | int | Cantidad de digitos |
| num_hyphens | int | Cantidad de guiones |
| num_dots | int | Cantidad de puntos |
| num_subdomains | int | Subdominios |
| entropy | float | Entropia de Shannon |
| has_https | binary | Usa HTTPS |
| has_port | binary | Puerto custom |
| has_at_symbol | binary | Contiene @ |
| contains_ip | binary | IP como host |
| has_punycode | binary | Caracteres unicode |
| shortener_detected | binary | URL acortada |
| paste_service_detected | binary | Servicio paste |
| has_suspicious_words | int | Palabras sospechosas |
| tld_risk | binary | TLD riesgoso |
| excessive_subdomains | binary | >3 subdominios |
| digit_ratio | float | Proporcion digitos |
| num_params | int | Parametros query |
| special_chars | int | Caracteres especiales |
| in_tranco | binary | En Tranco Top 1M |
| tranco_rank | float | Ranking normalizado |
| brand_impersonation | binary | Suplanta marca |

---

## 8. Integraciones Externas

### Tranco API
**Proposito:** Verificar si un dominio es legitimo (Top 1 Millon sitios)

- **URL:** https://tranco-list.eu/
- **Rate limit:** 1 query/segundo
- **Uso:** Reduce score -30 puntos si dominio verificado
- **Excepcion:** No reduce si es paste service o URL shortener

### VirusTotal API
**Proposito:** Consultar cuando hay incertidumbre en el analisis

- **URL:** https://www.virustotal.com/api/v3
- **Rate limit:** 4 queries/minuto (plan gratuito)
- **Uso:** Solo consulta si score esta entre 30-70
- **Threshold:** 3+ detecciones = malicioso

**Logica de consulta:**
- Score < 30: No consulta (sitio seguro)
- Score 30-70: Consulta VT para confirmar
- Score > 70: No consulta (ya es phishing)

---

## 9. Dataset y Entrenamiento

### Dataset Actual

| Metrica | Valor |
|---------|-------|
| Total URLs Train | 6,000 |
| Legitimas | 3,000 (50%) |
| Maliciosas | 3,000 (50%) |
| URLs Validacion | 800 |
| URLs Test | 800 |
| Verificacion VT | Si |

### Fuentes de Datos

| Fuente | Tipo |
|--------|------|
| Phishing.Database | URLs phishing verificadas |
| Tranco Top 1M | URLs legitimas |
| VirusTotal | Verificacion de maliciosas |

### Entrenar Modelo

```bash
# 1. Entrenar modelo
cd backend
python -m scripts.train_step1

# 2. Evaluar modelo
python -m scripts.evaluate_step1
```

### Metricas del Modelo ML

| Metrica | Valor |
|---------|-------|
| Accuracy | 97.5% |
| Precision | 98.1% |
| Recall | 96.8% |
| F1-Score | 97.4% |

### Metricas del Modelo Heuristico

| Metrica | Valor |
|---------|-------|
| Accuracy | 75.9% |
| Precision | 87.4% |
| Recall | 60.4% |
| F1-Score | 71.4% |

---

## 10. Scripts Disponibles

### Construccion de Datos
```bash
# Dataset grande con verificacion VirusTotal (recomendado)
python scripts/build_large_dataset.py

# Dataset simple
python scripts/build_training_dataset.py
```

### Entrenamiento
```bash
# Entrenar modelo baseline
python scripts/train_step1.py

# Evaluar modelo
python scripts/evaluate_step1.py
```

### Pruebas
```bash
# Test del predictor completo
python scripts/test_real_predictor.py

# Test integracion VirusTotal
python scripts/test_virustotal_integration.py

# Test integracion Tranco
python scripts/test_tranco_integration.py
```

### Datos de VirusTotal
```bash
# Verificar URLs de prueba
python scripts/fetch_virustotal_data.py --verify

# Enriquecer dataset existente
python scripts/fetch_virustotal_data.py --enrich

# Agregar URLs verificadas al training
python scripts/fetch_virustotal_data.py --add
```

---

## 11. Resultados de Pruebas

| URL | Score | Nivel | Resultado |
|-----|-------|-------|-----------|
| google.com | 0/100 | LOW | Legitimo |
| paypal.com/login | 0/100 | LOW | Legitimo |
| pastebin.com/xxx | 30/100 | LOW | Sospechoso |
| secure-paypal.xyz | 100/100 | HIGH | Phishing |
| kutt.it/kms-activator | 40/100 | MEDIUM | Sospechoso |
| amazon-gift-free.top | 100/100 | HIGH | Phishing |
| 192.168.1.1/login | 100/100 | HIGH | Phishing |
| bit.ly/free-gift | 40/100 | MEDIUM | Sospechoso |

---

## 12. Historial de Versiones

| Version | Fecha | Descripcion |
|---------|-------|-------------|
| 1.2.0 | 2026-01-19 | WHOIS verificacion + Crawler headless |
| 1.1.0 | 2026-01-18 | Modelo heuristico calibrado |
| 1.0.0 | 2026-01-10 | Dataset 6000 URLs + VirusTotal |
| 0.9.0 | 2026-01-08 | Integracion Tranco API |
| 0.8.0 | 2026-01-05 | App Flutter funcional |

---

## Seguridad

### Proteccion SSRF
- Bloquea IPs privadas (10.x, 172.16.x, 192.168.x)
- Bloquea localhost y variantes
- Bloquea metadata endpoints (AWS, GCP)
- Resolucion DNS segura

### Manejo de API Keys
- Almacenadas en `.env` (ignorado por git)
- Nunca en codigo fuente
- Plantilla en `.env.example`

### Rate Limiting
- `/analyze`: 30 requests/minuto por IP
- VirusTotal: 4 queries/minuto (plan gratuito)

---

## Marco Legal

- **Ley 1581/2012** - Proteccion de Datos Personales (Colombia)
- **Ley 1273/2009** - Delitos Informaticos (Colombia)
- **Principios UNESCO IA Etica** - Transparencia y explicabilidad

---

## Licencia

Proyecto de tesis - Universidad Manuela Beltran 2026

---

## Contacto

- **Repositorio:** [GitHub](https://github.com/samuelortizospina/alerta-link)
- **API Produccion:** https://api.samuelortizospina.me

---

**Ultima actualizacion:** 2026-01-19
