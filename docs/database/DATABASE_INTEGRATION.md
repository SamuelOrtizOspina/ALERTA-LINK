# Integracion de Base de Datos - ALERTA-LINK

## Resumen

ALERTA-LINK usa PostgreSQL como base de datos principal con fallback automatico a archivos JSONL cuando PostgreSQL no esta disponible.

## Arquitectura

```
┌─────────────────────────────────────────────────────────┐
│                      FastAPI                             │
│                    (Endpoints)                           │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│              Capa de Dependencias                        │
│         (get_db_optional / get_db)                       │
└─────────────────────┬───────────────────────────────────┘
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│   PostgreSQL    │     │  JSONL Fallback │
│   (Primario)    │     │   (Secundario)  │
└─────────────────┘     └─────────────────┘
```

## Modelos SQLAlchemy

### IngestedUrl
Almacena URLs para entrenamiento del modelo ML.

```python
class IngestedUrl(Base):
    __tablename__ = "ingested_urls"

    id: UUID              # ID unico
    url_normalized: str   # URL normalizada
    url_hash: str         # SHA256 para deduplicacion
    label: int            # 0=legitimo, 1=malicioso
    source: str           # manual, feed, user, api
    raw_payload: JSONB    # Metadatos adicionales
    created_at: datetime
```

### Report
Almacena reportes de usuarios desde la app movil.

```python
class Report(Base):
    __tablename__ = "reports"

    id: UUID              # ID unico
    url_normalized: str   # URL reportada
    url_hash: str         # SHA256
    label: str            # phishing, malware, scam, unknown
    comment: str          # Comentario del usuario
    contact: str          # Contacto opcional
    source: str           # mobile_app, web, api
    created_at: datetime
```

### AnalysisResult
Almacena historico de analisis de URLs.

```python
class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id: UUID              # ID unico
    url_normalized: str   # URL analizada
    url_hash: str         # SHA256
    score: int            # 0-100
    risk_level: str       # LOW, MEDIUM, HIGH
    signals: JSONB        # Lista de senales detectadas
    ml_score: int         # Score del modelo ML
    heuristic_score: int  # Score de heuristicas
    tranco_verified: bool # Si se verifico con Tranco
    tranco_rank: int      # Ranking en Tranco
    virustotal_checked: bool  # Si se consulto VT
    virustotal_detections: int  # Detecciones de VT
    mode_used: str        # online, offline, auto
    duration_ms: int      # Duracion en ms
    created_at: datetime
```

## Configuracion

### Variables de Entorno

```env
# .env
DATABASE_URL=postgresql://alerta:alerta123@localhost:5432/alertalink
```

### Conexion Lazy

El engine se crea de forma lazy para evitar fallos al iniciar si PostgreSQL no esta disponible:

```python
from app.db import is_db_available

if is_db_available():
    # Usar PostgreSQL
else:
    # Usar JSONL fallback
```

## Uso en Endpoints

### Con Fallback Automatico

```python
from app.db.dependencies import get_db_optional
from app.models import IngestedUrl

@router.post("/ingest")
async def ingest_url(
    request: IngestRequest,
    db: Optional[Session] = Depends(get_db_optional)
):
    if db is not None:
        # PostgreSQL disponible
        ingested = IngestedUrl.create(url=request.url, ...)
        db.add(ingested)
    else:
        # Fallback a JSONL
        save_to_jsonl(record, filepath)
```

### Sin Fallback (Requiere BD)

```python
from app.db.dependencies import get_db

@router.get("/stats")
async def get_stats(db: Session = Depends(get_db)):
    # Lanza error si BD no esta disponible
    return db.query(AnalysisResult).count()
```

## Migraciones

### Ejecutar Migraciones

```bash
cd database
alembic upgrade head
```

### Crear Nueva Migracion

```bash
alembic revision -m "descripcion_del_cambio"
```

### Migraciones Existentes

1. `001_initial_schema.py` - Tablas ingested_urls y reports
2. `002_add_analysis_results.py` - Tabla analysis_results

## Verificar Estado

### Endpoint de Health

```bash
curl http://localhost:8000/api/v1/health
```

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

### Endpoint de Estado de BD

```bash
curl http://localhost:8000/api/v1/health/db
```

```json
{
  "status": "connected",
  "engine": "postgresql",
  "host": "localhost:5432/alertalink",
  "pool_size": 5
}
```

## Indices

Todos los modelos tienen indices optimizados:

| Tabla | Indice | Columna(s) |
|-------|--------|------------|
| ingested_urls | idx_ingested_url_hash | url_hash |
| ingested_urls | idx_ingested_created_at | created_at DESC |
| ingested_urls | idx_ingested_label | label |
| reports | idx_reports_url_hash | url_hash |
| reports | idx_reports_created_at | created_at DESC |
| reports | idx_reports_label | label |
| analysis_results | idx_analysis_url_hash | url_hash |
| analysis_results | idx_analysis_created_at | created_at DESC |
| analysis_results | idx_analysis_score | score |
| analysis_results | idx_analysis_risk_level | risk_level |

## Estructura de Archivos

```
backend/app/
├── db/
│   ├── __init__.py       # Exporta funciones publicas
│   ├── database.py       # Engine, SessionLocal, verificacion
│   └── dependencies.py   # get_db, get_db_optional
├── models/
│   ├── __init__.py       # Exporta todos los modelos
│   ├── base.py           # Base declarativa
│   ├── ingested_url.py   # Modelo IngestedUrl
│   ├── report.py         # Modelo Report
│   └── analysis_result.py # Modelo AnalysisResult
└── api/routes/
    ├── ingest.py         # Usa get_db_optional
    ├── report.py         # Usa get_db_optional
    └── health.py         # Muestra estado BD
```

## Siguiente Paso

1. Instalar PostgreSQL localmente o usar Docker
2. Ejecutar migraciones: `alembic upgrade head`
3. Probar endpoints con BD activa
4. Verificar fallback desconectando BD
