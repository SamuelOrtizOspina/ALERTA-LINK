# FASE 2: Base de Datos + Modo Online/Offline

## Resumen Ejecutivo

**Objetivo:** Conectar el sistema a PostgreSQL con control del usuario sobre el modo de conexion.

**Estado actual (MVP):**
- Backend funcional con ML + Tranco + VirusTotal
- Datos guardados en archivos JSONL (fallback)
- Sin persistencia real en base de datos

**Meta Fase 2:**
- Persistencia en PostgreSQL
- Usuario controla modo online/offline
- Sincronizacion automatica cuando hay conexion

---

## Arquitectura Propuesta

```
+------------------+
|   APP MOVIL      |
|   (Kotlin)       |
+--------+---------+
         |
         | Toggle: Online/Offline
         v
+------------------+     Online      +------------------+
|   MODO OFFLINE   | <-------------> |   MODO ONLINE    |
| - Analisis local |                 | - Tranco API     |
| - Cache local    |                 | - VirusTotal API |
| - Room DB        |                 | - PostgreSQL     |
+------------------+                 +------------------+
         |                                    |
         |         Sincronizacion             |
         +----------> cuando hay <------------+
                      conexion
```

---

## Tareas de Implementacion

### SPRINT 1: Base de Datos Backend (3-4 dias)

#### 1.1 Crear Modelos SQLAlchemy
```
backend/app/models/
├── __init__.py
├── base.py           # Base declarativa
├── ingested_url.py   # Modelo IngestedUrl
├── report.py         # Modelo Report
└── analysis.py       # Modelo AnalysisResult (nuevo)
```

**Modelo IngestedUrl:**
```python
class IngestedUrl(Base):
    __tablename__ = "ingested_urls"

    id = Column(UUID, primary_key=True)
    url_normalized = Column(Text, nullable=False)
    url_hash = Column(Text, index=True)
    label = Column(Integer)  # 0=legitimo, 1=malicioso
    source = Column(Text, default="manual")
    raw_payload = Column(JSONB)
    created_at = Column(DateTime, default=datetime.utcnow)
```

**Modelo Report:**
```python
class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID, primary_key=True)
    url_normalized = Column(Text, nullable=False)
    url_hash = Column(Text, index=True)
    label = Column(Text)  # phishing, malware, scam, unknown
    comment = Column(Text)
    contact = Column(Text)
    source = Column(Text, default="mobile_app")
    created_at = Column(DateTime, default=datetime.utcnow)
```

**Modelo AnalysisResult (NUEVO):**
```python
class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(UUID, primary_key=True)
    url_normalized = Column(Text, nullable=False)
    url_hash = Column(Text, index=True)
    score = Column(Integer)  # 0-100
    risk_level = Column(Text)  # LOW, MEDIUM, HIGH
    signals = Column(JSONB)  # Lista de senales detectadas
    ml_score = Column(Integer)
    heuristic_score = Column(Integer)
    tranco_verified = Column(Boolean)
    virustotal_checked = Column(Boolean)
    created_at = Column(DateTime, default=datetime.utcnow)
```

#### 1.2 Crear Capa de Database
```
backend/app/db/
├── __init__.py
├── database.py       # Engine, SessionLocal
└── dependencies.py   # get_db para FastAPI
```

**database.py:**
```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
```

**dependencies.py:**
```python
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

#### 1.3 Actualizar Rutas para Usar BD
- `POST /ingest` → Guardar en `ingested_urls`
- `POST /report` → Guardar en `reports`
- `POST /analyze` → Guardar en `analysis_results` (opcional)

#### 1.4 Ejecutar Migraciones
```bash
cd database
alembic upgrade head
```

---

### SPRINT 2: Modo Online/Offline (2-3 dias)

#### 2.1 Configuracion de Modo
```python
# config.py
class Settings:
    # Modo de conexion
    CONNECTION_MODE: str = "auto"  # auto, online, offline
    OFFLINE_FALLBACK: bool = True  # Usar offline si falla online
```

#### 2.2 Nuevo Endpoint de Configuracion
```
GET  /settings          # Obtener configuracion actual
POST /settings/mode     # Cambiar modo (online/offline/auto)
```

**Request:**
```json
{
  "mode": "online",  // online, offline, auto
  "sync_on_connect": true
}
```

#### 2.3 Logica de Modo en Predictor
```python
def predict(self, url: str, mode: str = "auto"):
    if mode == "offline":
        # Solo ML local + heuristicas
        return self._predict_offline(url)
    elif mode == "online":
        # ML + Tranco + VirusTotal + BD
        return self._predict_online(url)
    else:  # auto
        # Intentar online, fallback a offline
        try:
            return self._predict_online(url)
        except ConnectionError:
            return self._predict_offline(url)
```

#### 2.4 Respuesta con Indicador de Modo
```json
{
  "url": "https://example.com",
  "score": 45,
  "risk_level": "MEDIUM",
  "mode_used": "online",  // Nuevo campo
  "apis_consulted": {
    "tranco": true,
    "virustotal": false,
    "database": true
  },
  "signals": [...]
}
```

---

### SPRINT 3: Sincronizacion (2-3 dias)

#### 3.1 Cola de Sincronizacion
```
backend/app/services/sync_service.py
```

**Funcionalidad:**
- Guardar operaciones pendientes cuando offline
- Sincronizar cuando vuelve la conexion
- Resolver conflictos (ultima escritura gana)

#### 3.2 Endpoint de Sincronizacion
```
POST /sync              # Sincronizar datos pendientes
GET  /sync/status       # Estado de sincronizacion
```

#### 3.3 Tabla de Sincronizacion
```sql
CREATE TABLE sync_queue (
    id UUID PRIMARY KEY,
    operation TEXT NOT NULL,  -- 'ingest', 'report', 'analysis'
    payload JSONB NOT NULL,
    status TEXT DEFAULT 'pending',  -- pending, synced, failed
    created_at TIMESTAMPTZ DEFAULT NOW(),
    synced_at TIMESTAMPTZ
);
```

---

### SPRINT 4: App Movil Android/Kotlin (COMPLETADO)

#### 4.1 Estructura de la App
```
android-app/app/src/main/java/com/alertalink/app/
├── AlertaLinkApp.kt           # Application class
├── model/
│   ├── AnalysisResult.kt      # Modelos de datos
│   ├── Signal.kt
│   └── Settings.kt            # Modelos de configuracion
├── network/
│   ├── ApiService.kt          # Interface Retrofit
│   └── ApiClient.kt           # Singleton API
└── ui/
    ├── MainActivity.kt        # Pantalla principal
    ├── ResultActivity.kt      # Resultado del analisis
    ├── SettingsActivity.kt    # Configuracion de modo
    ├── HistoryActivity.kt     # Historial
    ├── ReportActivity.kt      # Reportar URL
    └── SignalsAdapter.kt      # Adapter RecyclerView
```

#### 4.2 Toggle de Modo en Settings
```kotlin
// SettingsActivity.kt
binding.radioGroupMode.setOnCheckedChangeListener { _, checkedId ->
    val newMode = when (checkedId) {
        R.id.radioAuto -> ConnectionMode.AUTO
        R.id.radioOnline -> ConnectionMode.ONLINE
        R.id.radioOffline -> ConnectionMode.OFFLINE
        else -> ConnectionMode.AUTO
    }
    changeMode(newMode)
}
```

#### 4.3 Indicador Visual de Modo
```kotlin
// MainActivity.kt - Indicador de conexion
private fun updateConnectionStatus(isOnline: Boolean) {
    binding.connectionIndicator.setImageResource(
        if (isOnline) R.drawable.ic_cloud else R.drawable.ic_cloud_off
    )
    binding.connectionText.text = if (isOnline)
        getString(R.string.connection_online)
    else
        getString(R.string.connection_offline)
}
```

#### 4.4 Room Database para Cache Local (Pendiente)
```kotlin
// AnalysisDao.kt - Para implementar en Sprint 3
@Dao
interface AnalysisDao {
    @Insert
    suspend fun insert(analysis: AnalysisEntity)

    @Query("SELECT * FROM analysis WHERE synced = 0")
    suspend fun getPendingSync(): List<AnalysisEntity>
}
```

---

## Cronograma Estimado

| Sprint | Duracion | Entregable |
|--------|----------|------------|
| Sprint 1 | 3-4 dias | BD PostgreSQL funcional |
| Sprint 2 | 2-3 dias | Modo online/offline |
| Sprint 3 | 2-3 dias | Sincronizacion |
| Sprint 4 | 5-7 dias | App movil basica |
| **Total** | **12-17 dias** | **Fase 2 completa** |

---

## Criterios de Aceptacion

### Base de Datos
- [x] Modelos SQLAlchemy creados y funcionando
- [x] Migraciones creadas (pendiente ejecutar en PostgreSQL)
- [x] Endpoints guardan datos en BD (con fallback JSONL)
- [ ] Queries de lectura funcionan

### Modo Online/Offline
- [x] Usuario puede cambiar modo desde app (SettingsActivity)
- [x] Modo offline funciona sin internet (solo ML + heuristicas)
- [x] Modo online usa todas las APIs (Tranco + VirusTotal)
- [x] Modo auto detecta conexion (verifica disponibilidad de APIs)
- [x] Endpoint GET /settings implementado
- [x] Endpoint POST /settings/mode implementado
- [x] Endpoint GET /settings/status implementado
- [x] Response de /analyze incluye mode_used y apis_consulted

### Sincronizacion
- [ ] Datos offline se guardan localmente
- [ ] Sincronizacion automatica al reconectar
- [ ] Sin perdida de datos
- [ ] Conflictos resueltos correctamente

### App Movil (Android/Kotlin)
- [x] Input de URL funcional (MainActivity)
- [x] Semaforo de riesgo visible (ResultActivity)
- [x] Lista de senales explicadas (SignalsAdapter)
- [x] Toggle de modo accesible (SettingsActivity)
- [x] Historial de analisis (HistoryActivity)
- [x] Recibir URLs via Share Intent
- [x] Reportar URLs sospechosas (ReportActivity)

---

## Riesgos y Mitigaciones

| Riesgo | Probabilidad | Impacto | Mitigacion |
|--------|--------------|---------|------------|
| PostgreSQL no disponible | Media | Alto | Fallback a SQLite |
| APIs externas lentas | Alta | Medio | Timeout + cache |
| Conflictos de sync | Baja | Medio | Ultima escritura gana |
| App movil compleja | Media | Alto | MVP minimo primero |

---

## Siguiente Paso Inmediato

**Empezar con Sprint 1: Base de Datos Backend**

1. Crear modelos SQLAlchemy
2. Crear capa de database
3. Actualizar rutas
4. Ejecutar migraciones
5. Probar con PostgreSQL real

¿Procedemos con Sprint 1?
