# Runbook - ALERTA-LINK

> Guia de operaciones, troubleshooting y comandos utiles

---

## Requisitos

- Python 3.11+
- Docker y Docker Compose (opcional)
- PostgreSQL 15+ (opcional, hay fallback a JSONL)
- Git

---

## Instalacion

### 1. Clonar repositorio
```bash
git clone <repo-url>
cd desarrollo
```

### 2. Crear entorno virtual
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

### 3. Instalar dependencias
```bash
# Para scripts de ML
pip install pandas numpy scikit-learn

# Para backend
pip install -r backend/requirements.txt
```

---

## Pipeline de ML

### Paso 1: Construir dataset
```bash
python scripts/build_dataset.py
```

**Salida esperada:**
```
Cargando PhiUSIIL desde ...
PhiUSIIL: 235795 filas cargadas
Cargando Phishing.Database desde ...
...
DATASET CONSTRUIDO EXITOSAMENTE
```

**Archivos generados:**
- `datasets/processed/dataset_master.csv`
- `datasets/splits/train.csv`
- `datasets/splits/val.csv`
- `datasets/splits/test.csv`

### Paso 2: Entrenar modelo
```bash
python scripts/train_step1.py
```

**Salida esperada:**
```
Cargando datos de entrenamiento...
Extrayendo features de X URLs...
Entrenando modelo LogisticRegression...
Training accuracy: 0.XXXX
ENTRENAMIENTO COMPLETADO
```

**Archivos generados:**
- `models/step1_baseline.pkl`

### Paso 3: Evaluar modelo
```bash
python scripts/evaluate_step1.py
```

**Salida esperada:**
```
Evaluando en validation...
  Accuracy: 0.XXXX
  F1-Score: 0.XXXX
Evaluando en test...
  Test F1: 0.XXXX
EVALUACION COMPLETADA
```

**Archivos generados:**
- `reports/step1_metrics.json`

---

## Backend

### Desarrollo local
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Acceder a:
- API: http://localhost:8000
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Con Docker
```bash
# Solo backend (sin DB)
docker build -t alertalink-api ./backend
docker run -p 8000:8000 alertalink-api

# Backend + PostgreSQL
docker-compose up -d
```

### Variables de Entorno

| Variable | Default | Descripcion |
|----------|---------|-------------|
| DATABASE_URL | postgresql://alerta:alerta123@localhost:5432/alertalink | URL de PostgreSQL |
| DEBUG | false | Modo debug |
| SECRET_KEY | super-secret-... | Clave secreta |

---

## Base de Datos

### Iniciar PostgreSQL con Docker
```bash
docker-compose up -d postgres
```

### Verificar conexion
```bash
docker exec -it alertalink-db psql -U alerta -d alertalink -c "SELECT 1"
```

### Migraciones (cuando esten implementadas)
```bash
cd database
alembic upgrade head
```

---

## Troubleshooting

### Error: "Modelo no encontrado"
```
Modelo no encontrado en models/step1_baseline.pkl
```
**Solucion:** Ejecutar primero los scripts de entrenamiento
```bash
python scripts/build_dataset.py
python scripts/train_step1.py
```

### Error: "PhiUSIIL no encontrado"
```
PhiUSIIL no encontrado en datos_ya_entrenados_pushing/...
```
**Solucion:** Verificar que el archivo CSV existe en la ruta correcta

### Error: "URL invalida: IP privada bloqueada"
```
{"detail": "URL invalida: IP privada bloqueada: 192.168.1.1"}
```
**Explicacion:** La proteccion SSRF bloquea IPs privadas. Esto es comportamiento esperado.

### Error: Puerto 8000 en uso
```
[Errno 10048] error while attempting to bind on address ('0.0.0.0', 8000)
```
**Solucion:** Usar otro puerto o matar el proceso existente
```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Linux
lsof -i :8000
kill -9 <PID>
```

### Modelo con bajo rendimiento
Si F1 < 0.80:
1. Verificar balance de clases en dataset
2. Revisar si hay URLs duplicadas
3. Considerar agregar mas features
4. Ajustar hiperparametros (C, regularizacion)

---

## Logs

### Ver logs del backend
```bash
# Docker
docker logs -f alertalink-api

# Local
uvicorn app.main:app --reload --log-level debug
```

### Archivos de log
Los datos ingestados se guardan en:
- `datasets/ingested/ingested_urls.jsonl`
- `datasets/ingested/user_reports.jsonl`

---

## Comandos Utiles

### Contar URLs en dataset
```bash
wc -l datasets/processed/dataset_master.csv
```

### Ver estadisticas
```bash
cat datasets/processed/dataset_stats.json | python -m json.tool
```

### Test rapido del API
```bash
# Health check
curl http://localhost:8000/health

# Analizar URL
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

### Limpiar todo y reconstruir
```bash
rm -rf datasets/processed/*
rm -rf datasets/splits/*
rm -rf models/*
rm -rf reports/*
python scripts/build_dataset.py
python scripts/train_step1.py
python scripts/evaluate_step1.py
```

---

**Ultima actualizacion:** 2026-01-01
