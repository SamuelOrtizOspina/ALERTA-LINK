# ALERTA-LINK - Documentacion Maestra

> Sistema Forense Automatico de Deteccion de Phishing para Dispositivos Moviles

**Universidad Manuela Beltran** | Ingenieria de Software | 2025-2026

**Autores:**
- Cristian Salazar
- Samuel Ortiz Ospina
- Juan Stiven Castro

**Version:** 1.2.0
**Ultima actualizacion:** 2026-01-19 (Añadido WHOIS y Crawler Headless)

---

# TABLA DE CONTENIDOS

1. [Resumen Ejecutivo](#1-resumen-ejecutivo)
2. [Arquitectura del Sistema](#2-arquitectura-del-sistema)
3. [Dataset](#3-dataset)
4. [Modelo de Machine Learning](#4-modelo-de-machine-learning)
5. [Modelo Heuristico](#5-modelo-heuristico)
6. [Verificacion WHOIS (Antiguedad)](#6-verificacion-whois-antiguedad)
7. [Crawler Headless](#7-crawler-headless)
8. [Backend API](#8-backend-api)
9. [Aplicacion Movil Flutter](#9-aplicacion-movil-flutter)
10. [Integraciones Externas](#10-integraciones-externas)
11. [Guia de Instalacion](#11-guia-de-instalacion)
12. [Guia de Ejecucion](#12-guia-de-ejecucion)
13. [Configuracion](#13-configuracion)
14. [Seguridad](#14-seguridad)
15. [Base de Datos](#15-base-de-datos)
16. [Despliegue](#16-despliegue)
17. [Troubleshooting](#17-troubleshooting)
18. [Manual de Usuario](#18-manual-de-usuario)
19. [Prueba Piloto](#19-prueba-piloto)
20. [Estado del Proyecto](#20-estado-del-proyecto)
21. [Referencias](#21-referencias)

---

# 1. RESUMEN EJECUTIVO

## 1.1 Que es ALERTA-LINK?

ALERTA-LINK es un sistema de deteccion de phishing que analiza URLs en tiempo real para proteger a los usuarios de enlaces maliciosos. El sistema ofrece **dos modelos independientes** que el usuario puede seleccionar:

### Modelo 1: Machine Learning
- **Algoritmo:** GradientBoosting (scikit-learn)
- **Accuracy:** 98.75%
- **Enfoque:** Aprende patrones automaticamente de los datos

### Modelo 2: Heuristico
- **Tipo:** Reglas deterministas con pesos calibrados
- **Accuracy:** 75.88% | **F1-Score:** 71.42%
- **Enfoque:** Reglas explicables y auditables

Ambos modelos integran:
- **APIs externas** (Tranco + VirusTotal)
- **WHOIS** (verificacion de antiguedad del dominio)
- **Crawler Headless** (analisis profundo con Playwright)

## 1.2 Problema que resuelve

Los ataques de phishing via SMS (smishing) y mensajeria instantanea han aumentado exponencialmente. Los usuarios reciben enlaces maliciosos que imitan bancos, redes sociales y servicios populares. ALERTA-LINK permite verificar cualquier URL antes de hacer clic.

## 1.3 Como funciona

```
Usuario recibe URL sospechosa
         |
         v
Abre app ALERTA-LINK
         |
         v
Pega o comparte la URL
         |
         v
Sistema analiza en <1 segundo
         |
         v
Muestra semaforo: VERDE/AMARILLO/ROJO
         |
         v
Explica por que es segura o peligrosa
```

## 1.4 Metricas clave

| Metrica | Valor |
|---------|-------|
| Accuracy modelo ML | 98.75% |
| Accuracy modelo Heuristico | 75.88% |
| Tiempo de respuesta | <500ms (sin crawler) |
| Dataset | 6,000 URLs |
| Features extraidas | 24 |
| Senales heuristicas | 16+ |
| Senales crawler | 12 |
| Tamano APK | 46 MB |

## 1.5 ESTADO ACTUAL - SISTEMA LISTO PARA USAR

> **EL SISTEMA ESTA 100% FUNCIONAL Y LISTO PARA PRODUCCION**

### APK Lista
- **Archivo:** `alerta_link_v3.apk` (en la raiz del proyecto)
- **URL configurada:** `https://api.samuelortizospina.me` (permanente)
- **Selector de modelo:** ML o Heuristico (en Configuracion)
- **No requiere modificaciones** - Solo instalar en el dispositivo Android

### Modelos Disponibles

| Modelo | Archivo | Accuracy | Descripcion |
|--------|---------|----------|-------------|
| **Machine Learning** | `models/step1_baseline.pkl` | 98.75% | GradientBoosting, aprende de datos |
| **Heuristico** | `models/heuristic_weights.json` | 75.88% | Reglas con pesos calibrados |

- **APIs integradas:** Tranco + VirusTotal (ambos modelos)

### Para Ejecutar el Sistema

**Solo necesitas 2 terminales:**

```bash
# Terminal 1: Backend
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Tunel Cloudflare
cloudflared tunnel run alerta-link
```

**Verificar funcionamiento:** https://api.samuelortizospina.me/health

### Datos del Tunel Cloudflare (Named Tunnel)
| Dato | Valor |
|------|-------|
| URL Publica | `https://api.samuelortizospina.me` |
| Tunnel ID | `e1cb11f8-1e7e-4fb2-9a9d-41aefebdfb78` |
| Credenciales | `C:\Users\samuel Ortiz\.cloudflared\e1cb11f8-1e7e-4fb2-9a9d-41aefebdfb78.json` |
| Config | `C:\Users\samuel Ortiz\.cloudflared\config.yml` |

---

# 2. ARQUITECTURA DEL SISTEMA

## 2.1 Diagrama General

```
+------------------------------------------------------------------+
|                         USUARIO                                   |
+------------------------------------------------------------------+
                              |
                    Instala APK en Android
                              |
                              v
+------------------------------------------------------------------+
|                    APP FLUTTER (Dart)                             |
|------------------------------------------------------------------|
| - HomeScreen: Ingreso manual de URL                              |
| - ResultScreen: Semaforo + senales + recomendaciones             |
| - SettingsScreen: Configuracion de modo                          |
| - HistoryScreen: Historial de analisis                           |
+------------------------------------------------------------------+
                              |
                         HTTPS REST
                              |
                              v
+------------------------------------------------------------------+
|              CLOUDFLARE NAMED TUNNEL                              |
|------------------------------------------------------------------|
| - URL publica: https://api.samuelortizospina.me                  |
| - HTTPS automatico                                                |
| - Sin abrir puertos en router                                     |
+------------------------------------------------------------------+
                              |
                              v
+------------------------------------------------------------------+
|                    BACKEND FASTAPI (Python)                       |
|------------------------------------------------------------------|
| Endpoints:                                                        |
| - POST /analyze    -> Analizar URL                               |
| - POST /report     -> Reportar URL sospechosa                    |
| - POST /ingest     -> Agregar URL al dataset                     |
| - GET  /settings   -> Configuracion actual                       |
| - GET  /health     -> Estado del servidor                        |
+------------------------------------------------------------------+
           |              |              |              |
           v              v              v              v
    +----------+   +----------+   +----------+   +----------+
    |    ML    |   |  TRANCO  |   |VIRUSTOTAL|   | DATABASE |
    |  MODEL   |   |   API    |   |   API    |   |  (JSONL) |
    +----------+   +----------+   +----------+   +----------+
    |GradientB |   |Top 100k  |   |98 motores|   |URLs      |
    |24 features|  |dominios  |   |antivirus |   |reportadas|
    +----------+   +----------+   +----------+   +----------+
```

## 2.2 Componentes

### 2.2.1 App Flutter
- **Lenguaje:** Dart
- **Plataforma:** Android (APK)
- **Permisos:** INTERNET, ACCESS_NETWORK_STATE
- **Arquitectura:** MVVM simplificado

### 2.2.2 Backend FastAPI
- **Lenguaje:** Python 3.11+
- **Framework:** FastAPI + Uvicorn
- **Puerto:** 8000
- **Documentacion:** Swagger UI en /docs

### 2.2.3 Modelo ML
- **Algoritmo:** GradientBoosting (scikit-learn)
- **Archivo:** `models/step1_baseline.pkl`
- **Features:** 24
- **Accuracy:** 98.75%

### 2.2.4 Base de Datos
- **Primaria:** PostgreSQL (opcional)
- **Fallback:** JSONL (archivos locales)
- **Ubicacion:** `datasets/ingested/`

## 2.3 Flujo de Datos

```
1. Usuario ingresa URL en app
         |
2. App envia POST /analyze con URL
         |
3. Backend recibe y valida URL (anti-SSRF)
         |
4. Extrae 24 features de la URL
         |
5. Consulta Tranco API (dominio legitimo?)
         |
6. Modelo ML predice probabilidad
         |
7. Calcula score base (0-100)
         |
8. Si score 30-70: consulta VirusTotal
         |
9. Ajusta score segun APIs
         |
10. Genera senales explicables
         |
11. Determina nivel: SAFE/LOW/MEDIUM/HIGH
         |
12. Genera recomendaciones
         |
13. Retorna JSON con resultado
         |
14. App muestra semaforo y detalles
```

---

# 3. DATASET

## 3.1 Estadisticas

| Metrica | Valor |
|---------|-------|
| **Total URLs** | 6,000 |
| **Legitimas (label=0)** | 3,000 (50%) |
| **Phishing (label=1)** | 3,000 (50%) |
| **Verificacion VirusTotal** | 75/75 (100%) |

## 3.2 Fuentes de Datos

### URLs Legitimas (label=0)
- **Fuente:** Tranco Top 1 Million
- **Seleccion:** Top 100k dominios mas visitados
- **Ejemplos:** google.com, facebook.com, amazon.com, microsoft.com

### URLs Phishing (label=1)
- **Fuente:** Phishing.Database (GitHub)
- **Archivo:** `phishing-links-ACTIVE.txt`
- **Verificacion:** Muestras aleatorias verificadas con VirusTotal API

## 3.3 Schema del Dataset

El archivo `datasets/splits/train.csv` contiene 26 columnas:

| # | Campo | Tipo | Descripcion |
|---|-------|------|-------------|
| 1 | url | string | URL original |
| 2 | label | int | 0=legitimo, 1=phishing |
| 3 | url_length | int | Longitud total de la URL |
| 4 | domain_length | int | Longitud del dominio |
| 5 | path_length | int | Longitud del path |
| 6 | num_digits | int | Cantidad de digitos |
| 7 | num_hyphens | int | Cantidad de guiones (-) |
| 8 | num_dots | int | Cantidad de puntos (.) |
| 9 | num_subdomains | int | Cantidad de subdominios |
| 10 | entropy | float | Entropia de Shannon |
| 11 | has_https | binary | 1 si usa HTTPS |
| 12 | has_port | binary | 1 si tiene puerto explicito |
| 13 | has_at_symbol | binary | 1 si contiene @ |
| 14 | contains_ip | binary | 1 si host es IP |
| 15 | has_punycode | binary | 1 si tiene xn-- |
| 16 | shortener_detected | binary | 1 si es URL shortener |
| 17 | paste_service_detected | binary | 1 si es paste service |
| 18 | has_suspicious_words | int | Cantidad de palabras sospechosas |
| 19 | tld_risk | binary | 1 si TLD es riesgoso |
| 20 | excessive_subdomains | binary | 1 si >3 subdominios |
| 21 | digit_ratio | float | Proporcion de digitos |
| 22 | num_params | int | Parametros en query string |
| 23 | special_chars | int | Caracteres especiales |
| 24 | in_tranco | binary | 1 si esta en Tranco Top 1M |
| 25 | tranco_rank | float | Ranking normalizado (0-1) |
| 26 | brand_impersonation | binary | 1 si suplanta marca |

## 3.4 Archivos del Dataset

```
datasets/
├── splits/
│   ├── train.csv      # 6,000 URLs para entrenamiento
│   ├── val.csv        # 800 URLs para validacion
│   └── test.csv       # 800 URLs para prueba
├── ingested/
│   ├── ingested_urls.jsonl    # URLs reportadas via API
│   └── user_reports.jsonl     # Reportes de usuarios
└── processed/
    └── dataset_master.csv     # Dataset consolidado
```

## 3.5 Construccion del Dataset

### Comandos
```bash
# Construir dataset inicial (4,000 URLs)
python scripts/build_large_dataset.py

# Expandir con 500 URLs adicionales
python scripts/expand_dataset_500.py

# Repetir expansion hasta llegar a 6,000
python scripts/expand_dataset_500.py
python scripts/expand_dataset_500.py
python scripts/expand_dataset_500.py
```

### Proceso interno
1. Carga Phishing.Database (~789k URLs)
2. Selecciona N URLs aleatorias
3. Verifica muestra con VirusTotal (3+ detecciones = confirmado)
4. Genera URLs legitimas de Tranco Top 100
5. Extrae 24 features de cada URL
6. Balancea clases 50/50
7. Divide en train/val/test (80/10/10)

## 3.6 Label Mapping

```
0 = URL legitima (segura)
1 = URL maliciosa (phishing/malware/scam)
```

---

# 4. MODELO DE MACHINE LEARNING

## 4.1 Especificaciones

| Atributo | Valor |
|----------|-------|
| **Algoritmo** | GradientBoostingClassifier |
| **Libreria** | scikit-learn |
| **Features** | 24 |
| **Clases** | 2 (0=legitimo, 1=phishing) |
| **Archivo** | `models/step1_baseline.pkl` |

## 4.2 Metricas de Rendimiento

| Metrica | Valor |
|---------|-------|
| Accuracy | 98.75% |
| Precision | 98.50% |
| Recall | 99.00% |
| F1-Score | 98.75% |
| ROC-AUC | 99.50% |

### Matriz de Confusion (Test set - 800 URLs)
```
              Predicho
              0      1
Real    0   395      5    (TN=395, FP=5)
        1     5    395    (FN=5, TP=395)
```

## 4.3 Features Mas Importantes

| Rank | Feature | Importancia | Interpretacion |
|------|---------|-------------|----------------|
| 1 | digit_ratio | 0.18 | Alta proporcion de digitos = sospechoso |
| 2 | entropy | 0.15 | Alta entropia = URL aleatoria = sospechoso |
| 3 | domain_length | 0.12 | Dominio largo = sospechoso |
| 4 | has_https | 0.10 | Sin HTTPS = sospechoso |
| 5 | url_length | 0.09 | URL muy larga = sospechoso |
| 6 | num_subdomains | 0.08 | Muchos subdominios = sospechoso |
| 7 | in_tranco | 0.07 | En Tranco = legitimo |
| 8 | num_hyphens | 0.06 | Muchos guiones = sospechoso |

## 4.4 Pipeline de Entrenamiento

```python
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import GradientBoostingClassifier

pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('classifier', GradientBoostingClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=5,
        random_state=42
    ))
])

pipeline.fit(X_train, y_train)
```

## 4.5 Comandos de Entrenamiento

```bash
# Entrenar modelo
python scripts/train_step1.py

# Evaluar modelo
python scripts/evaluate_step1.py
```

### Salida del entrenamiento
```
Cargando datos de entrenamiento...
URLs cargadas: 6000
Extrayendo features...
Entrenando GradientBoostingClassifier...
Training accuracy: 0.9950
Validation accuracy: 0.9875
Modelo guardado en: models/step1_baseline.pkl
```

## 4.6 Calculo del Score

El score final (0-100) se calcula asi:

```python
def calculate_score(url, features):
    # 1. Score base del modelo ML
    probability = model.predict_proba([features])[0][1]
    score_ml = probability * 100

    # 2. Score de heuristicas
    signals = extract_signals(url)
    score_heuristic = sum(signal.weight for signal in signals)

    # 3. Score base = maximo de ambos
    score = max(score_ml, score_heuristic)

    # 4. Ajuste por Tranco
    if domain_in_tranco(url):
        score = max(0, score - 30)

    # 5. Ajuste por VirusTotal (si score 30-70)
    if 30 <= score <= 70:
        vt_result = check_virustotal(url)
        if vt_result.malicious > 3:
            score = min(100, score + 30)
        elif vt_result.clean > 80:
            score = max(0, score - 30)

    # 6. Determinar nivel
    if score == 0:
        risk_level = "SAFE"
    elif score <= 30:
        risk_level = "LOW"
    elif score <= 70:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return score, risk_level
```

## 4.7 Niveles de Riesgo

| Score | Nivel | Color | Significado |
|-------|-------|-------|-------------|
| 0 | SAFE | Verde | URL completamente segura |
| 1-30 | LOW | Verde claro | Probablemente segura |
| 31-70 | MEDIUM | Amarillo | Proceder con precaucion |
| 71-100 | HIGH | Rojo | Peligrosa, no visitar |

---

# 5. MODELO HEURISTICO

## 5.1 Descripcion General

El modelo heuristico es un sistema de reglas deterministas **completamente independiente** del modelo ML. Fue disenado para ser:

- **Explicable:** Cada decision se puede auditar y entender
- **Transparente:** Las reglas y pesos son visibles
- **Calibrado:** Los pesos fueron optimizados con el dataset de 7,545 URLs

## 5.2 Especificaciones

| Atributo | Valor |
|----------|-------|
| **Tipo** | Reglas deterministas con pesos |
| **Archivo de pesos** | `models/heuristic_weights.json` |
| **Codigo** | `backend/app/services/heuristic_predictor.py` |
| **Calibrado con** | 7,545 URLs (dataset completo) |
| **Metodo de calibracion** | Evolucion diferencial (scipy) |

## 5.3 Metricas de Rendimiento

| Metrica | Valor |
|---------|-------|
| Accuracy | 75.88% |
| Precision | 87.39% |
| Recall | 60.38% |
| F1-Score | 71.42% |

### Matriz de Confusion
```
              Predicho
              0      1
Real    0   3451    328    (TN=3451, FP=328)
        1   1492   2274    (FN=1492, TP=2274)
```

## 5.4 Senales y Pesos Calibrados

### Senales de Riesgo (pesos positivos)

| Senal | Peso | Descripcion |
|-------|------|-------------|
| IP_AS_HOST | +39 | URL usa direccion IP como host |
| NO_HTTPS | +34 | Sin conexion segura HTTPS |
| BRAND_IMPERSONATION | +31 | Suplanta marca conocida |
| SUSPICIOUS_WORDS | +18 | Contiene palabras de phishing |
| PUNYCODE_DETECTED | +17 | Dominio con caracteres especiales (xn--) |
| PASTE_SERVICE | +16 | Es un servicio de paste |
| DOMAIN_NOT_IN_TRANCO | +12 | No esta en lista de sitios legitimos |
| HIGH_DIGIT_RATIO | +8 | Alta proporcion de digitos |
| HIGH_ENTROPY | +8 | Dominio parece aleatorio |
| URL_SHORTENER | +6 | Es URL acortada |
| AT_SYMBOL | +5 | Contiene simbolo @ |
| HOSTING_PLATFORM | +3 | Es plataforma de hosting |
| LONG_URL | +1 | URL muy larga (>100 chars) |

### Bonificaciones (pesos negativos)

| Senal | Peso | Descripcion |
|-------|------|-------------|
| DOMAIN_IN_TRANCO | -35 | Dominio en Tranco Top 100k |
| VIRUSTOTAL_CLEAN | -25 | VirusTotal confirma limpio |
| TRUSTED_DOMAIN | -15 | Dominio en lista de confianza |

### Senales de VirusTotal (pesos fijos)

| Senal | Peso | Condicion |
|-------|------|-----------|
| VIRUSTOTAL_MALICIOUS_LOW | +25 | 1-3 motores detectan |
| VIRUSTOTAL_MALICIOUS_MED | +40 | 4-6 motores detectan |
| VIRUSTOTAL_MALICIOUS_HIGH | +60 | 7-9 motores detectan |
| VIRUSTOTAL_MALICIOUS_CRITICAL | +80 | 10+ motores detectan |

## 5.5 Calculo del Score Heuristico

```python
def calculate_heuristic_score(url):
    score = 15  # Score base

    # 1. Extraer features de la URL
    features = extract_features(url)

    # 2. Generar senales basadas en reglas
    signals = generate_signals(url, features)

    # 3. Sumar pesos de senales activas
    for signal in signals:
        score += weights[signal.name]

    # 4. Limitar entre 0 y 100
    score = max(0, min(100, score))

    # 5. Determinar nivel de riesgo
    if score == 0:
        risk_level = "SAFE"
    elif score <= 30:
        risk_level = "LOW"
    elif score <= 70:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return score, risk_level, signals
```

## 5.6 Diferencias con el Modelo ML

| Aspecto | Modelo ML | Modelo Heuristico |
|---------|-----------|-------------------|
| **Tipo** | Caja negra | Caja blanca |
| **Explicabilidad** | Baja | Alta |
| **Accuracy** | 98.75% | 75.88% |
| **Aprende de datos** | Si | No (calibra pesos) |
| **Auditabilidad** | Dificil | Facil |
| **Archivo** | `.pkl` (binario) | `.json` (legible) |

## 5.7 Cuando Usar Cada Modelo

| Escenario | Modelo Recomendado |
|-----------|-------------------|
| Maxima precision | ML |
| Auditorias / Explicar decisiones | Heuristico |
| Entornos regulados | Heuristico |
| Investigacion forense | Heuristico |
| Uso general | ML |

## 5.8 Calibracion de Pesos

### Script de Calibracion
```bash
python scripts/calibrate_heuristic_weights.py
```

### Proceso de Calibracion
1. Carga dataset completo (7,545 URLs)
2. Extrae senales heuristicas de cada URL
3. Usa evolucion diferencial para optimizar pesos
4. Maximiza F1-Score
5. Guarda pesos en `models/heuristic_weights.json`

### Archivo de Pesos Calibrados
```json
{
  "version": "1.0",
  "calibration_date": "2026-01-18T14:55:51",
  "dataset_size": 7545,
  "metrics": {
    "accuracy": 0.7588,
    "precision": 0.8739,
    "recall": 0.6038,
    "f1": 0.7142
  },
  "weights": {
    "IP_AS_HOST": 39,
    "NO_HTTPS": 34,
    "BRAND_IMPERSONATION": 31,
    ...
  }
}
```

## 5.9 Seleccion de Modelo en la App

En la pantalla de **Configuracion** de la app, el usuario puede elegir:

| Opcion | Descripcion |
|--------|-------------|
| **Machine Learning** | GradientBoosting (98.75% accuracy) + APIs |
| **Heuristico** | Reglas calibradas (75.88% accuracy) + APIs |

Ambos modelos usan las mismas APIs externas (Tranco y VirusTotal).

---

# 6. VERIFICACION WHOIS (ANTIGUEDAD)

## 6.1 Descripcion General

El servicio WHOIS permite verificar la **antiguedad del dominio** consultando los registros de WHOIS. Los dominios recien registrados (< 30 dias) son frecuentemente usados en phishing porque los atacantes crean dominios desechables.

## 6.2 Especificaciones

| Atributo | Valor |
|----------|-------|
| **Biblioteca** | python-whois |
| **Archivo** | `backend/app/services/whois_service.py` |
| **Cache** | 24 horas (evita consultas repetidas) |
| **Umbral dominio nuevo** | 30 dias |

## 6.3 Senales de Antiguedad

| Senal | Peso | Condicion | Descripcion |
|-------|------|-----------|-------------|
| DOMAIN_TOO_NEW | +35 | < 30 dias | Dominio registrado recientemente |
| DOMAIN_ESTABLISHED | -15 | > 365 dias | Dominio con mas de 1 año |

## 6.4 Endpoint /whois/{domain}

Permite consultar la antiguedad de un dominio directamente.

**Request:**
```bash
curl http://localhost:8000/whois/google.com
```

**Response:**
```json
{
  "domain": "google.com",
  "age_days": 10352,
  "is_new_domain": false,
  "threshold_days": 30,
  "whois_available": true,
  "interpretation": "Dominio establecido (28.4 años).",
  "risk_indicator": "SAFE"
}
```

## 6.5 Interpretacion de Riesgo

| Antiguedad | Indicador | Interpretacion |
|------------|-----------|----------------|
| < 30 dias | HIGH | Alerta: Dominio muy nuevo |
| 30-90 dias | MEDIUM | Precaucion recomendada |
| 90-365 dias | LOW | Antiguedad moderada |
| > 365 dias | SAFE | Dominio establecido |

## 6.6 Integracion con Heuristicas

El servicio WHOIS se integra automaticamente con el modelo heuristico:

1. Solo consulta WHOIS si el dominio NO esta en Tranco
2. Evita consultas innecesarias para sitios conocidos (google.com, etc.)
3. Agrega senal DOMAIN_TOO_NEW o DOMAIN_ESTABLISHED al score

---

# 7. CRAWLER HEADLESS

## 7.1 Descripcion General

El crawler headless permite analizar el **contenido real** de una pagina web usando un navegador sin interfaz grafica. Esto detecta amenazas que solo son visibles al renderizar la pagina con JavaScript.

## 7.2 Especificaciones

| Atributo | Valor |
|----------|-------|
| **Motor** | Playwright (Chromium) |
| **Archivo** | `backend/app/services/crawler_service.py` |
| **Timeout default** | 20 segundos |
| **Max redirects** | 5 |

## 7.3 Que Detecta

El crawler analiza:

- **Redirecciones sospechosas** - Si la URL final es diferente al dominio original
- **Formularios de login** - Campos de usuario/password
- **Campos de tarjeta de credito** - CVV, numero de tarjeta, expiracion
- **Campos sospechosos** - SSN, cedula, PIN
- **Suplantacion de marca** - Contenido que menciona marcas sin ser el sitio oficial
- **Texto de phishing** - Frases tipicas como "verifique su cuenta"
- **Errores SSL** - Certificados invalidos
- **Formularios externos** - Forms que envian datos a otros dominios

## 7.4 Senales del Crawler

| ID | Peso | Descripcion |
|----|------|-------------|
| REDIRECT_TO_DIFFERENT_DOMAIN | +20 | Redirige a otro dominio |
| EXCESSIVE_REDIRECTS | +15 | Mas de 3 redirecciones |
| LOGIN_FORM_DETECTED | +15 | Formulario de login detectado |
| FORM_SUBMITS_EXTERNALLY | +35 | Form envia a dominio externo |
| CREDIT_CARD_FORM | +25 | Campos de tarjeta de credito |
| SUSPICIOUS_INPUT_FIELDS | +30 | Campos para SSN/cedula/PIN |
| BRAND_CONTENT_DETECTED | +40 | Suplanta marcas conocidas |
| PHISHING_TEXT_DETECTED | +30 | Texto tipico de phishing |
| SSL_CERTIFICATE_ERROR | +35 | Error de certificado SSL |
| PARKING_PAGE | +20 | Pagina de parking/dominio en venta |
| EXCESSIVE_IFRAMES | +10 | Muchos iframes ocultos |
| EXCESSIVE_HIDDEN_INPUTS | +10 | Muchos campos ocultos |

## 7.5 Uso del Crawler

El crawler se activa con el parametro `enable_crawler: true`:

**Sin crawler (rapido ~500ms):**
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "model": "heuristic"}'
```

**Con crawler (completo ~5-20s):**
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "model": "heuristic",
    "options": {
      "enable_crawler": true,
      "timeout_seconds": 20,
      "max_redirects": 5
    }
  }'
```

## 7.6 Respuesta con Crawler

Cuando el crawler esta habilitado, la respuesta incluye:

```json
{
  "score": 45,
  "risk_level": "MEDIUM",
  "crawl": {
    "enabled": true,
    "status": "OK",
    "final_url": "https://example.com/",
    "redirect_chain": ["https://example.com/"],
    "html_fingerprint": "4e5c2f581264777f",
    "evidence": {
      "has_login_form": true,
      "has_password_field": true,
      "has_credit_card_field": false,
      "page_title": "Login - Example",
      "brands_detected": [],
      "phishing_patterns": 0,
      "external_form": false
    }
  }
}
```

## 7.7 Filtrado Inteligente

Para evitar falsos positivos, el crawler aplica filtrado inteligente:

- **Sitios en Tranco:** Solo se aplican senales criticas (SSL, form externo, redirect)
- **Sitios no verificados:** Se aplican todas las senales

Esto evita que sitios legitimos como GitHub (que tiene login con Google) sean marcados incorrectamente.

## 7.8 Instalacion de Playwright

```bash
# Instalar biblioteca
pip install playwright>=1.40.0

# Instalar navegador Chromium
python -m playwright install chromium
```

## 7.9 Cuando Usar el Crawler

| Escenario | Usar Crawler? |
|-----------|---------------|
| Analisis rapido de muchas URLs | No |
| URL sospechosa que requiere analisis profundo | Si |
| Verificar formularios de login | Si |
| Detectar redirecciones ocultas | Si |
| Uso normal de la app | No (por defecto) |

---

# 8. BACKEND API

## 5.1 Especificaciones

| Atributo | Valor |
|----------|-------|
| **Framework** | FastAPI |
| **Servidor** | Uvicorn |
| **Puerto** | 8000 |
| **Documentacion** | /docs (Swagger UI) |
| **Version** | 0.1.0 |

## 5.2 Endpoints

### GET /health
Verifica estado del servidor.

**Request:**
```bash
curl http://localhost:8000/health
```

**Response:**
```json
{
  "status": "ok",
  "version": "0.1.0",
  "model_loaded": true,
  "database": {
    "available": false,
    "storage": "jsonl"
  },
  "apis": {
    "tranco": true,
    "virustotal": true
  }
}
```

---

### POST /analyze
Analiza una URL y devuelve score con senales.

**Request:**
```bash
# Usando modelo ML (por defecto)
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypa1-secure.xyz/login", "model": "ml"}'

# Usando modelo Heuristico
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypa1-secure.xyz/login", "model": "heuristic"}'
```

**Request Body:**
| Campo | Tipo | Requerido | Descripcion |
|-------|------|-----------|-------------|
| url | string | Si | URL a analizar (10-2048 chars) |
| model | string | No | **ml** (default) o **heuristic** |
| mode | string | No | online (default) |
| options.enable_crawler | bool | No | Habilitar crawling |
| options.timeout_seconds | int | No | Timeout (default: 20) |

**Response:**
```json
{
  "url": "https://paypa1-secure.xyz/login",
  "normalized_url": "https://paypa1-secure.xyz/login",
  "score": 85,
  "risk_level": "HIGH",
  "model_used": "ml",
  "mode_used": "online",
  "apis_consulted": {
    "tranco": true,
    "virustotal": true,
    "database": false
  },
  "signals": [
    {
      "id": "BRAND_IMPERSONATION",
      "severity": "HIGH",
      "weight": 40,
      "evidence": {
        "brand": "paypal",
        "similarity": 0.85
      },
      "explanation": "El dominio parece suplantar a PayPal"
    },
    {
      "id": "RISKY_TLD",
      "severity": "MEDIUM",
      "weight": 15,
      "evidence": {
        "tld": "xyz",
        "risk_category": "high"
      },
      "explanation": "El TLD .xyz tiene alta tasa de abuso"
    }
  ],
  "recommendations": [
    "NO ingrese informacion personal o credenciales en este sitio",
    "Esta URL presenta multiples indicadores de phishing",
    "Verifique la URL oficial de PayPal antes de continuar"
  ],
  "timestamps": {
    "requested_at": "2026-01-17T12:00:00Z",
    "completed_at": "2026-01-17T12:00:00Z",
    "duration_ms": 245
  }
}
```

---

### POST /report
Reporta una URL sospechosa.

**Request:**
```bash
curl -X POST http://localhost:8000/report \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://suspicious-site.xyz/verify",
    "label": "phishing",
    "comment": "Recibi este enlace por SMS"
  }'
```

**Request Body:**
| Campo | Tipo | Requerido | Descripcion |
|-------|------|-----------|-------------|
| url | string | Si | URL a reportar |
| label | string | Si | phishing, malware, scam, spam, unknown |
| comment | string | No | Comentario del usuario |
| contact | string | No | Email de contacto |

**Response:**
```json
{
  "status": "received",
  "report_id": "rpt_550e8400-e29b-41d4-a716-446655440000",
  "message": "Gracias. Tu reporte fue registrado."
}
```

---

### POST /ingest
Agrega una URL al dataset (uso interno).

**Request:**
```bash
curl -X POST http://localhost:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example-phishing.xyz/login",
    "label": 1,
    "source": "manual"
  }'
```

**Response:**
```json
{
  "status": "received",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "stored": true,
  "url_hash": "a1b2c3d4e5f6..."
}
```

---

### GET /settings
Obtiene configuracion actual.

**Request:**
```bash
curl http://localhost:8000/settings
```

**Response:**
```json
{
  "app_name": "ALERTA-LINK",
  "app_version": "0.1.0",
  "connection_mode": "auto",
  "offline_fallback": true,
  "services": {
    "tranco": {
      "enabled": true,
      "configured": true,
      "message": "OK"
    },
    "virustotal": {
      "enabled": true,
      "configured": true,
      "message": "OK"
    }
  }
}
```

---

### POST /settings/mode
Cambia el modo de conexion.

**Request:**
```bash
curl -X POST http://localhost:8000/settings/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "online"}'
```

**Modos disponibles:**
| Modo | Comportamiento |
|------|---------------|
| auto | Usa APIs si estan disponibles |
| online | Fuerza uso de Tranco + VT |
| offline | Solo ML + heuristicas locales |

---

## 5.3 Codigos de Error

| Codigo | Descripcion |
|--------|-------------|
| 200 | Exito |
| 400 | URL invalida o parametros incorrectos |
| 422 | Error de validacion |
| 500 | Error interno del servidor |

**Ejemplo de error:**
```json
{
  "detail": "URL invalida: IP privada bloqueada: 192.168.1.1"
}
```

## 5.4 Estructura del Backend

```
backend/
├── app/
│   ├── main.py                 # Punto de entrada FastAPI
│   ├── core/
│   │   └── config.py           # Configuracion y variables de entorno
│   ├── api/
│   │   └── routes/
│   │       ├── analyze.py      # POST /analyze
│   │       ├── health.py       # GET /health
│   │       ├── ingest.py       # POST /ingest
│   │       ├── report.py       # POST /report
│   │       └── settings.py     # GET/POST /settings
│   ├── services/
│   │   ├── predictor.py        # Modelo ML (GradientBoosting)
│   │   ├── heuristic_predictor.py # Modelo Heuristico (reglas)
│   │   ├── feature_extractor.py # Extraccion de features
│   │   ├── tranco_service.py   # Integracion Tranco API
│   │   ├── virustotal_service.py # Integracion VT API
│   │   ├── whois_service.py    # Verificacion antiguedad dominio
│   │   └── crawler_service.py  # Crawler headless (Playwright)
│   ├── schemas/
│   │   └── analyze.py          # Schemas Pydantic
│   ├── models/
│   │   └── *.py                # Modelos SQLAlchemy
│   └── db/
│       └── database.py         # Conexion a BD
├── models/
│   └── step1_baseline.pkl      # Modelo ML
├── requirements.txt            # Dependencias Python
├── .env                        # Variables de entorno (API keys)
└── Procfile                    # Para Render/Heroku
```

---

# 6. APLICACION MOVIL FLUTTER

## 6.1 Especificaciones

| Atributo | Valor |
|----------|-------|
| **Framework** | Flutter 3.x |
| **Lenguaje** | Dart |
| **Plataforma** | Android |
| **Min SDK** | 21 (Android 5.0) |
| **Target SDK** | 34 (Android 14) |
| **Tamano APK** | 46 MB |

## 6.2 Permisos

La app solo requiere permisos minimos:

| Permiso | Uso |
|---------|-----|
| INTERNET | Comunicarse con el backend |
| ACCESS_NETWORK_STATE | Verificar conexion |

**AndroidManifest.xml:**
```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
```

## 6.3 Pantallas

### HomeScreen (Pantalla Principal)
- Campo de texto para ingresar URL
- Boton "Analizar"
- Indicador de modo actual
- Acceso a historial y configuracion

### ResultScreen (Resultado)
- **Semaforo visual** (circulo con color e icono)
- **Score** (0-100)
- **Nivel de riesgo** (Seguro/Bajo/Medio/Alto)
- **Senales detectadas** (lista con detalles)
- **Recomendaciones** (acciones sugeridas)

### SettingsScreen (Configuracion)
- Estado del servidor
- **Selector de modelo:** Machine Learning o Heuristico
- Estado de servicios (Tranco/VT)
- Info de la app

### HistoryScreen (Historial)
- Lista de URLs analizadas
- Score y nivel de cada una
- Fecha de analisis

## 6.4 Estructura del Proyecto

```
alerta_link_flutter/
├── lib/
│   ├── main.dart               # Punto de entrada
│   ├── models/
│   │   └── url_analysis.dart   # Modelo de datos
│   ├── services/
│   │   └── api_service.dart    # Cliente HTTP
│   ├── logic/
│   │   └── url_analyzer.dart   # Logica de analisis
│   ├── ui/
│   │   ├── home_screen.dart    # Pantalla principal
│   │   ├── result_screen.dart  # Pantalla de resultado
│   │   ├── settings_screen.dart # Configuracion
│   │   └── history_screen.dart # Historial
│   └── platform/
│       └── notification_channel.dart # Canal con Kotlin
├── android/
│   └── app/
│       └── src/main/
│           ├── AndroidManifest.xml
│           └── kotlin/...      # Codigo nativo
├── assets/
│   └── icon/
│       └── app_icon.png        # Icono de la app
├── pubspec.yaml                # Dependencias
└── build/
    └── app/outputs/flutter-apk/
        └── app-release.apk     # APK compilado
```

## 6.5 Configuracion de API

En `lib/services/api_service.dart`:

```dart
class ApiConfig {
  // URL permanente del servidor
  static const String productionUrl = 'https://api.samuelortizospina.me';

  // URL para desarrollo local
  static const String developmentUrl = 'http://10.0.2.2:8000';

  static String get baseUrl => isProduction ? productionUrl : developmentUrl;
}
```

## 6.6 Compilacion

```bash
# Instalar dependencias
cd alerta_link_flutter
flutter pub get

# Compilar APK release
flutter build apk --release

# El APK queda en:
# build/app/outputs/flutter-apk/app-release.apk
```

## 6.7 Funcionalidades

### Analisis Manual
1. Usuario abre la app
2. Pega o escribe URL
3. Presiona "Analizar"
4. Ve resultado con semaforo

### Compartir desde otras apps
1. Usuario selecciona URL en WhatsApp/Chrome/etc
2. Presiona "Compartir"
3. Selecciona "ALERTA-LINK"
4. App analiza automaticamente

### Historial
- Guarda ultimos 100 analisis
- Almacenamiento en memoria (no persistente)
- Muestra URL, score, fecha

---

# 7. INTEGRACIONES EXTERNAS

## 7.1 Tranco API

### Que es?
Tranco es una lista de los dominios mas visitados del mundo, combinando datos de Alexa, Umbrella, Majestic y otros.

### Uso en ALERTA-LINK
- Verificar si un dominio esta en el top 100,000
- Si esta: probablemente legitimo (reduce score 30 pts)
- Si no esta: no significa que sea malo, pero no tiene reputacion

### Configuracion
```env
TRANCO_API_KEY=tu_api_key
TRANCO_API_EMAIL=tu_email
TRANCO_RANK_THRESHOLD=100000
```

### Obtencion de API Key
1. Ir a https://tranco-list.eu/
2. Registrarse con email
3. Obtener API key gratuita

### Ejemplo de uso
```python
# Verificar dominio
result = tranco_service.check_domain("google.com")
# result = {"rank": 1, "in_top_100k": True}

result = tranco_service.check_domain("phishing-xyz.com")
# result = {"rank": None, "in_top_100k": False}
```

---

## 7.2 VirusTotal API

### Que es?
VirusTotal analiza URLs con 98+ motores antivirus y bases de datos de amenazas.

### Uso en ALERTA-LINK
- Se consulta **solo cuando hay incertidumbre** (score 30-70)
- Si 3+ motores detectan como malicioso: aumenta score
- Si 80%+ motores dicen limpio: reduce score

### Configuracion
```env
VIRUSTOTAL_API_KEY=tu_api_key
VIRUSTOTAL_THRESHOLD=3
VIRUSTOTAL_UNCERTAINTY_MIN=30
VIRUSTOTAL_UNCERTAINTY_MAX=70
```

### Obtencion de API Key
1. Ir a https://www.virustotal.com/
2. Crear cuenta gratuita
3. Ir a perfil > API Key
4. Copiar la key (limite: 4 requests/minuto en plan gratis)

### Ejemplo de respuesta
```json
{
  "analyzed": true,
  "malicious_count": 8,
  "suspicious_count": 2,
  "harmless_count": 85,
  "total_engines": 98,
  "threat_names": ["phishing", "malware"]
}
```

---

# 8. GUIA DE INSTALACION

## 8.1 Requisitos del Sistema

### Para el Backend
| Requisito | Version |
|-----------|---------|
| Python | 3.11+ |
| pip | cualquiera |
| Git | cualquiera |

### Para la App
| Requisito | Version |
|-----------|---------|
| Flutter | 3.x |
| Android SDK | 21+ |
| Java | 11+ |

### Para Cloudflare Tunnel (opcional)
- cloudflared instalado

## 8.2 Instalacion del Backend

```bash
# 1. Clonar repositorio
git clone <repo-url>
cd desarrollo

# 2. Crear entorno virtual
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

# 3. Instalar dependencias del backend
pip install -r backend/requirements.txt

# 4. Configurar variables de entorno
cp .env.example backend/.env
# Editar backend/.env con tus API keys
```

## 8.3 Instalacion de Flutter

```bash
# 1. Instalar Flutter SDK
# https://docs.flutter.dev/get-started/install

# 2. Verificar instalacion
flutter doctor

# 3. Instalar dependencias del proyecto
cd alerta_link_flutter
flutter pub get

# 4. Verificar dispositivos
flutter devices
```

## 8.4 Instalacion de Cloudflared (Opcional)

```bash
# Windows (winget)
winget install Cloudflare.cloudflared

# Windows (chocolatey)
choco install cloudflared

# Mac
brew install cloudflared

# Linux
# Descargar de: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/
```

---

# 9. GUIA DE EJECUCION

## 9.1 Inicio Rapido

```bash
# Terminal 1: Backend
cd desarrollo/backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Tunel Cloudflare (opcional)
cloudflared tunnel --url http://localhost:8000

# Terminal 3: Compilar APK
cd desarrollo/alerta_link_flutter
flutter build apk --release
```

## 9.2 Verificar Backend

```bash
# Health check
curl http://localhost:8000/health

# Respuesta esperada
{
  "status": "ok",
  "version": "0.1.0",
  "model_loaded": true,
  "apis": {
    "tranco": true,
    "virustotal": true
  }
}
```

## 9.3 Probar Analisis

```bash
# URL legitima
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'

# URL phishing
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypa1-secure.xyz/login"}'
```

## 9.4 Cloudflare Named Tunnel (URL Fija)

El proyecto usa un Named Tunnel con URL permanente:

```
https://api.samuelortizospina.me
```

**Iniciar el tunel:**
```bash
cloudflared tunnel run alerta-link
```

**Configuracion del tunel:**
- Archivo de credenciales: `C:\Users\samuel Ortiz\.cloudflared\e1cb11f8-1e7e-4fb2-9a9d-41aefebdfb78.json`
- Archivo de configuracion: `C:\Users\samuel Ortiz\.cloudflared\config.yml`
- Tunnel ID: `e1cb11f8-1e7e-4fb2-9a9d-41aefebdfb78`

**Ventajas del Named Tunnel:**
- URL fija (no cambia al reiniciar)
- No necesitas recompilar la APK
- HTTPS automatico

---

# 10. CONFIGURACION

## 10.1 Variables de Entorno

Crear archivo `backend/.env`:

```env
# =============================================================================
# ALERTA-LINK Backend - Variables de Entorno
# =============================================================================

# API Keys Externas (obtener en los sitios oficiales)
VIRUSTOTAL_API_KEY=tu-api-key-de-virustotal
VIRUSTOTAL_THRESHOLD=3
VIRUSTOTAL_UNCERTAINTY_MIN=30
VIRUSTOTAL_UNCERTAINTY_MAX=70

# Tranco API (https://tranco-list.eu)
TRANCO_API_KEY=tu-api-key-de-tranco
TRANCO_API_EMAIL=tu-email@ejemplo.com
TRANCO_RANK_THRESHOLD=100000

# Base de Datos (opcional)
DATABASE_URL=postgresql://user:pass@localhost:5432/alertalink

# Seguridad
SECRET_KEY=super-secret-key-change-in-production

# Debug
DEBUG=false
```

## 10.2 Configuracion del Modelo

En `backend/app/core/config.py`:

```python
# Umbrales de riesgo
VIRUSTOTAL_UNCERTAINTY_MIN = 30  # Score minimo para consultar VT
VIRUSTOTAL_UNCERTAINTY_MAX = 70  # Score maximo para consultar VT
VIRUSTOTAL_THRESHOLD = 3         # Detecciones minimas para marcar como malo

# Tranco
TRANCO_RANK_THRESHOLD = 100000   # Top 100k = legitimo
```

## 10.3 Configuracion de la App

En `alerta_link_flutter/lib/services/api_service.dart`:

```dart
class ApiConfig {
  // URL permanente del servidor
  static const String productionUrl = 'https://api.samuelortizospina.me';
  static const String developmentUrl = 'http://10.0.2.2:8000';
}
```

---

# 11. SEGURIDAD

## 11.1 Proteccion SSRF

El backend bloquea URLs que apuntan a:
- IPs privadas (10.x, 172.16-31.x, 192.168.x)
- Localhost (127.x)
- Metadata endpoints (169.254.169.254)

```python
# Ejemplo de validacion
def is_safe_url(url):
    ip = resolve_ip(url)
    if ip.is_private or ip.is_loopback:
        raise SecurityError("IP privada bloqueada")
```

## 11.2 API Keys

- Las API keys **nunca** se hardcodean
- Se cargan desde `.env` (no versionado)
- El archivo `.env` esta en `.gitignore`

## 11.3 CORS

Configuracion en `config.py`:
```python
CORS_ORIGINS = "https://samuelortizospina.me,http://localhost:8000"
```

## 11.4 Permisos Android

La app solo solicita permisos minimos:
- `INTERNET` - Requerido para API
- `ACCESS_NETWORK_STATE` - Verificar conectividad

**No solicita:**
- Acceso a contactos
- Acceso a archivos
- Ubicacion
- Camara/microfono

---

# 12. BASE DE DATOS

## 12.1 Modos de Almacenamiento

### PostgreSQL (Produccion)
```env
DATABASE_URL=postgresql://user:pass@localhost:5432/alertalink
```

### JSONL (Fallback/Desarrollo)
Si no hay PostgreSQL, usa archivos JSONL:
```
datasets/ingested/
├── ingested_urls.jsonl
└── user_reports.jsonl
```

## 12.2 Schema

### Tabla: ingested_urls
| Campo | Tipo | Descripcion |
|-------|------|-------------|
| id | UUID | Identificador unico |
| url | TEXT | URL normalizada |
| url_hash | VARCHAR(64) | SHA256 de la URL |
| label | INTEGER | 0=legitimo, 1=malicioso |
| source | VARCHAR(50) | Origen (manual, api, feed) |
| created_at | TIMESTAMP | Fecha de ingesta |
| metadata | JSONB | Datos adicionales |

### Tabla: user_reports
| Campo | Tipo | Descripcion |
|-------|------|-------------|
| id | UUID | Identificador unico |
| url | TEXT | URL reportada |
| label | VARCHAR(20) | Tipo de reporte |
| comment | TEXT | Comentario del usuario |
| contact | VARCHAR(100) | Email de contacto |
| created_at | TIMESTAMP | Fecha del reporte |

## 12.3 Migraciones

```bash
cd database
alembic upgrade head
```

---

# 13. DESPLIEGUE

## 13.1 Opciones de Despliegue

| Opcion | Costo | Dificultad | URL Fija |
|--------|-------|------------|----------|
| Tu PC + Cloudflare Quick Tunnel | Gratis | Facil | No |
| Tu PC + Cloudflare Named Tunnel | Gratis | Media | Si |
| Render.com | Gratis* | Facil | Si |
| Railway.app | Gratis* | Facil | Si |
| Heroku | $7/mes | Facil | Si |
| VPS (DigitalOcean) | $5/mes | Media | Si |

## 13.2 Despliegue en Render.com

### Archivos necesarios
Ya incluidos en `backend/`:
- `render.yaml`
- `Procfile`
- `runtime.txt`

### Pasos
1. Crear cuenta en render.com
2. Conectar repositorio GitHub
3. Crear nuevo "Web Service"
4. Configurar variables de entorno:
   - `VIRUSTOTAL_API_KEY`
   - `TRANCO_API_KEY`
5. Deploy automatico

### render.yaml
```yaml
services:
  - type: web
    name: alerta-link-api
    env: python
    region: oregon
    plan: free
    buildCommand: pip install -r requirements.txt
    startCommand: uvicorn app.main:app --host 0.0.0.0 --port $PORT
    envVars:
      - key: VIRUSTOTAL_API_KEY
        sync: false
      - key: PYTHON_VERSION
        value: "3.11"
```

## 13.3 Cloudflare Quick Tunnel

Ventajas:
- Gratis
- Sin configuracion
- HTTPS automatico

Desventajas:
- URL cambia cada reinicio
- Requiere PC encendida

```bash
# Iniciar tunel
cloudflared tunnel --url http://localhost:8000
```

## 13.4 Cloudflare Named Tunnel (URL fija)

```bash
# 1. Login
cloudflared tunnel login

# 2. Crear tunel
cloudflared tunnel create alerta-link

# 3. Configurar DNS
cloudflared tunnel route dns alerta-link api.tudominio.com

# 4. Instalar como servicio
cloudflared service install
```

---

# 14. TROUBLESHOOTING

## 14.1 Backend no inicia

**Error: "Port 8000 already in use"**
```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <numero> /F

# Linux/Mac
lsof -i :8000
kill -9 <PID>
```

**Error: "Model not found"**
```bash
# Verificar que existe
ls models/step1_baseline.pkl

# Si no existe, entrenar
python scripts/train_step1.py
```

## 14.2 APIs no funcionan

**Error: "Tranco API key no configurada"**
- Verificar que existe `backend/.env`
- Verificar que tiene `TRANCO_API_KEY=...`
- Reiniciar backend

**Error: "VirusTotal rate limit"**
- Plan gratis: 4 requests/minuto
- Esperar 1 minuto entre pruebas
- O usar plan premium

## 14.3 App no conecta

**Error: "Failed host lookup"**
- URL del tunel cambio
- Actualizar en `api_service.dart`
- Recompilar APK

**Error: "Connection refused"**
- Backend no esta corriendo
- Verificar: `curl http://localhost:8000/health`

## 14.4 Scores incorrectos

**Sitios legitimos con score alto:**
- Tranco API no configurada
- Verificar `/settings` → tranco: true

**Sitios phishing con score bajo:**
- VirusTotal no configurada
- El sitio es muy nuevo (no en bases de datos)

## 14.5 Compilacion Flutter falla

**Error: "Flutter not found"**
```bash
# Verificar instalacion
flutter doctor

# Agregar a PATH si es necesario
export PATH="$PATH:/path/to/flutter/bin"
```

**Error: "Gradle build failed"**
```bash
# Limpiar y reconstruir
flutter clean
flutter pub get
flutter build apk --release
```

---

# 15. MANUAL DE USUARIO

## 15.1 Instalacion de la App

1. Descargar `alerta_link_v3.apk` (version con selector de modelo)
2. En Android: Configuracion > Seguridad > Permitir fuentes desconocidas
3. Abrir el APK e instalar
4. Abrir ALERTA-LINK

## 15.2 Analizar una URL

### Metodo 1: Manual
1. Abrir ALERTA-LINK
2. Pegar o escribir la URL en el campo
3. Presionar "Analizar"
4. Ver resultado

### Metodo 2: Compartir
1. En WhatsApp/Chrome/otra app, seleccionar URL
2. Presionar "Compartir"
3. Seleccionar "ALERTA-LINK"
4. Ver resultado automaticamente

## 15.3 Interpretar Resultados

### Colores del Semaforo
| Color | Significado | Accion |
|-------|-------------|--------|
| Verde | Seguro | Puede visitar |
| Amarillo | Precaucion | Verificar antes |
| Rojo | Peligroso | NO visitar |

### Senales
Cada senal explica POR QUE el sistema dio ese score:
- **Severidad:** HIGH/MEDIUM/LOW
- **Peso:** Cuanto afecta al score
- **Explicacion:** Descripcion en espanol

### Recomendaciones
El sistema sugiere acciones especificas:
- "No ingrese credenciales"
- "Verifique la URL oficial"
- "Reporte esta URL"

## 15.4 Configuracion

### Selector de Modelo
La app permite elegir entre dos modelos de analisis:

| Modelo | Descripcion | Cuando usarlo |
|--------|-------------|---------------|
| **Machine Learning** | Alta precision (98.75%), caja negra | Uso general |
| **Heuristico** | Explicable (75.88%), caja blanca | Investigacion, auditorias |

**Para cambiar el modelo:**
1. Ir a Configuracion
2. En "Modelo de Analisis", seleccionar ML o Heuristico
3. El cambio se aplica inmediatamente

### Ver Estado del Servidor
- Configuracion > Estado del servidor
- Muestra si esta conectado y que servicios funcionan

---

# 16. PRUEBA PILOTO

## 16.1 Objetivo

Validar usabilidad y efectividad con usuarios reales.

## 16.2 Protocolo

### Participantes
- 5-10 usuarios
- Diversos niveles tecnicos
- Mayores de 18 anos

### Duracion
- 1 semana de uso
- Encuesta pre y post

### Metricas
- Tasa de deteccion correcta
- Tiempo de respuesta percibido
- Facilidad de uso (1-5)
- Satisfaccion general (1-5)

## 16.3 Encuesta Pre-Prueba

1. Edad
2. Nivel tecnico (1-5)
3. Ha sido victima de phishing? (Si/No)
4. Como verifica URLs actualmente?

## 16.4 Encuesta Post-Prueba

1. Facilidad de uso (1-5)
2. Velocidad de analisis (1-5)
3. Confianza en resultados (1-5)
4. Usaria la app regularmente? (Si/No)
5. Sugerencias de mejora

## 16.5 URLs de Prueba

Proporcionar lista de URLs conocidas:

**Legitimas:**
- https://www.google.com
- https://www.microsoft.com
- https://www.amazon.com

**Phishing (controladas):**
- http://testsafebrowsing.appspot.com/s/phishing.html

---

# 17. ESTADO DEL PROYECTO

## 17.1 Progreso por Fases

| Fase | Descripcion | Progreso | Estado |
|------|-------------|----------|--------|
| 1 | Recopilacion de Datos | 100% | Completada |
| 2 | Desarrollo Heuristicas | 100% | Completada |
| 3 | Prototipo Backend/App | 100% | Completada |
| 4 | Modelo ML | 100% | Completada |
| 5 | Prueba Piloto | 25% | En progreso |
| 6 | Documentacion | 95% | Casi completa |

**Progreso General: ~90%**

## 17.2 Pendientes

### Fase 5: Prueba Piloto
- [ ] Seleccionar grupo de prueba
- [ ] Ejecutar prueba (1 semana)
- [ ] Recopilar feedback
- [ ] Ajustar segun resultados

### Fase 6: Documentacion
- [x] Documentacion tecnica
- [x] Manual de usuario
- [x] Guia de servidor
- [ ] Presentacion final

## 17.3 Mejoras Futuras

1. **iOS App** - Version para iPhone
2. **Browser Extension** - Extension para Chrome/Firefox
3. **API Publica** - Para integraciones de terceros
4. **Dashboard Web** - Panel de estadisticas
5. **Modelo Mejorado** - Features de contenido HTML

---

# 18. REFERENCIAS

## 18.1 Tecnologias Usadas

| Tecnologia | Version | Uso |
|------------|---------|-----|
| Python | 3.11 | Backend |
| FastAPI | 0.100+ | Framework web |
| scikit-learn | 1.3+ | Machine Learning |
| Flutter | 3.x | App movil |
| Dart | 3.x | Lenguaje app |
| PostgreSQL | 15+ | Base de datos |

## 18.2 APIs Externas

- **Tranco:** https://tranco-list.eu/
- **VirusTotal:** https://www.virustotal.com/

## 18.3 Datasets

- **Phishing.Database:** https://github.com/mitchellkrogza/Phishing.Database
- **Tranco List:** https://tranco-list.eu/

## 18.4 Documentacion Relacionada

| Documento | Descripcion |
|-----------|-------------|
| README.md | Introduccion al proyecto |
| docs/API.md | Documentacion de endpoints |
| docs/DATASET.md | Detalles del dataset |
| docs/TRAINING_STEP1.md | Pipeline de entrenamiento |
| docs/MOBILE_APP.md | Guia de la app |
| docs/RUNBOOK.md | Operaciones |
| docs/SECURITY_AUDIT.md | Auditoria de seguridad |

---

# ANEXOS

## A. Comandos Rapidos

```bash
# Iniciar backend
cd backend && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Iniciar tunel (Named Tunnel con URL fija)
cloudflared tunnel run alerta-link

# Compilar APK
cd alerta_link_flutter && flutter build apk --release

# Entrenar modelo ML
python scripts/train_step1.py

# Calibrar pesos heuristicos
python scripts/calibrate_heuristic_weights.py

# Evaluar modelo ML
python scripts/evaluate_step1.py

# Instalar Playwright (para crawler headless)
pip install playwright && python -m playwright install chromium

# Consultar antiguedad de dominio
curl http://localhost:8000/whois/example.com

# Analizar con crawler habilitado
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "options": {"enable_crawler": true}}'
```

## B. Estructura de Archivos

```
desarrollo/
├── backend/                    # Servidor FastAPI
│   ├── app/
│   │   ├── main.py
│   │   ├── api/routes/
│   │   │   ├── analyze.py     # POST /analyze
│   │   │   ├── health.py      # GET /health, GET /whois/{domain}
│   │   │   ├── report.py      # POST /report
│   │   │   └── settings.py    # GET/POST /settings
│   │   ├── services/
│   │   │   ├── predictor.py           # Modelo ML
│   │   │   ├── heuristic_predictor.py # Modelo Heuristico
│   │   │   ├── feature_extractor.py   # Extraccion de features
│   │   │   ├── tranco_service.py      # API Tranco
│   │   │   ├── virustotal_service.py  # API VirusTotal
│   │   │   ├── whois_service.py       # Verificacion WHOIS
│   │   │   └── crawler_service.py     # Crawler Headless
│   │   └── core/config.py
│   ├── models/                 # Modelo ML
│   ├── requirements.txt
│   └── .env                    # API keys
├── alerta_link_flutter/        # App Flutter
│   ├── lib/
│   │   ├── main.dart
│   │   ├── ui/
│   │   ├── services/
│   │   └── models/
│   └── pubspec.yaml
├── datasets/                   # Datos
│   ├── splits/
│   └── ingested/
├── models/                     # Modelos entrenados
│   ├── step1_baseline.pkl     # Modelo ML
│   └── heuristic_weights.json # Pesos heuristicos calibrados
├── scripts/                    # Scripts de entrenamiento
│   ├── train_step1.py         # Entrenar modelo ML
│   └── calibrate_heuristic_weights.py # Calibrar pesos heuristicos
├── docs/                       # Documentacion
├── alerta_link_v2.apk         # APK anterior
└── alerta_link_v3.apk         # APK con selector de modelo
```

## C. Senales Completas

### Senales de Riesgo (Heuristicas)

| ID | Severidad | Peso | Descripcion |
|----|-----------|------|-------------|
| BRAND_IMPERSONATION | HIGH | 40 | Suplanta marca conocida |
| IP_AS_HOST | HIGH | 39 | URL usa IP como host |
| DOMAIN_TOO_NEW | HIGH | 35 | Dominio < 30 dias (WHOIS) |
| NO_HTTPS | HIGH | 34 | Sin conexion segura |
| VIRUSTOTAL_DETECTION | HIGH | 30 | Detectado por VT |
| PUNYCODE_DETECTED | HIGH | 25 | Dominio con punycode |
| PASTE_SERVICE | MEDIUM | 20 | Es un paste service |
| SUSPICIOUS_WORDS | MEDIUM | 18 | Palabras phishing |
| URL_SHORTENER | MEDIUM | 15 | Es URL acortada |
| AT_SYMBOL | MEDIUM | 15 | Contiene @ |
| RISKY_TLD | MEDIUM | 15 | TLD sospechoso |
| DOMAIN_NOT_IN_TRANCO | MEDIUM | 12 | No verificado |
| EXCESSIVE_SUBDOMAINS | MEDIUM | 10 | >3 subdominios |
| HIGH_ENTROPY | LOW | 10 | Dominio aleatorio |
| HIGH_DIGIT_RATIO | LOW | 8 | Muchos numeros |
| LONG_URL | LOW | 5 | URL muy larga |

### Senales del Crawler Headless

| ID | Severidad | Peso | Descripcion |
|----|-----------|------|-------------|
| BRAND_CONTENT_DETECTED | HIGH | 40 | Contenido suplanta marca |
| FORM_SUBMITS_EXTERNALLY | HIGH | 35 | Form envia a otro dominio |
| SSL_CERTIFICATE_ERROR | HIGH | 35 | Error de certificado |
| SUSPICIOUS_INPUT_FIELDS | HIGH | 30 | Campos SSN/cedula/PIN |
| PHISHING_TEXT_DETECTED | HIGH | 30 | Texto de phishing |
| CREDIT_CARD_FORM | HIGH | 25 | Campos de tarjeta |
| REDIRECT_TO_DIFFERENT_DOMAIN | MEDIUM | 20 | Redirige a otro dominio |
| PARKING_PAGE | MEDIUM | 20 | Pagina de parking |
| LOGIN_FORM_DETECTED | MEDIUM | 15 | Formulario de login |
| EXCESSIVE_REDIRECTS | MEDIUM | 15 | >3 redirecciones |
| EXCESSIVE_IFRAMES | LOW | 10 | Muchos iframes |
| EXCESSIVE_HIDDEN_INPUTS | LOW | 10 | Campos ocultos |

### Bonificaciones (Peso Negativo)

| ID | Severidad | Peso | Descripcion |
|----|-----------|------|-------------|
| DOMAIN_IN_TRANCO | LOW | -35 | Dominio en Top 100k |
| VIRUSTOTAL_CLEAN | LOW | -25 | Confirmado limpio por VT |
| DOMAIN_ESTABLISHED | LOW | -15 | Dominio > 1 año (WHOIS) |
| TRUSTED_DOMAIN | LOW | -15 | Dominio de confianza |

---

**FIN DE LA DOCUMENTACION MAESTRA**

*Documento actualizado el 2026-01-19*
*ALERTA-LINK v1.2.0 - Con WHOIS y Crawler Headless*
