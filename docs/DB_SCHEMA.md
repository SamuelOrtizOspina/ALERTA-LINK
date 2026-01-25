# Esquema de Base de Datos - ALERTA-LINK

> Documentacion del esquema PostgreSQL

---

## Vista General

```
+-------------------+     +-------------------+
|  ingested_urls    |     |     reports       |
+-------------------+     +-------------------+
| id (UUID)         |     | id (UUID)         |
| url_normalized    |     | url_normalized    |
| url_hash          |     | url_hash          |
| label             |     | label             |
| source            |     | comment           |
| raw_payload       |     | contact           |
| created_at        |     | source            |
+-------------------+     | created_at        |
                          +-------------------+
```

---

## Tablas

### ingested_urls

Almacena URLs ingestadas para entrenamiento futuro.

```sql
CREATE TABLE ingested_urls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_normalized TEXT NOT NULL,
    url_hash TEXT,
    label INTEGER CHECK (label IN (0, 1)),
    source TEXT DEFAULT 'manual',
    raw_payload JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indices
CREATE INDEX idx_ingested_created_at ON ingested_urls(created_at DESC);
CREATE INDEX idx_ingested_label ON ingested_urls(label);
CREATE INDEX idx_ingested_url_hash ON ingested_urls(url_hash);

-- Deduplicacion (opcional)
CREATE UNIQUE INDEX idx_ingested_unique_hash
ON ingested_urls(url_hash)
WHERE url_hash IS NOT NULL;
```

| Campo | Tipo | Nullable | Descripcion |
|-------|------|----------|-------------|
| id | UUID | No | Identificador unico |
| url_normalized | TEXT | No | URL normalizada |
| url_hash | TEXT | Si | SHA256 para deduplicacion |
| label | INT | Si | 0=legitimo, 1=malicioso |
| source | TEXT | Si | Fuente (manual, feed, user, api) |
| raw_payload | JSONB | Si | Payload original para auditoria |
| created_at | TIMESTAMPTZ | No | Fecha de creacion |

---

### reports

Almacena reportes de usuarios desde la app movil.

```sql
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_normalized TEXT NOT NULL,
    url_hash TEXT,
    label TEXT NOT NULL CHECK (label IN ('phishing', 'malware', 'scam', 'unknown')),
    comment TEXT,
    contact TEXT,
    source TEXT DEFAULT 'mobile_app',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indices
CREATE INDEX idx_reports_created_at ON reports(created_at DESC);
CREATE INDEX idx_reports_label ON reports(label);
CREATE INDEX idx_reports_url_hash ON reports(url_hash);
```

| Campo | Tipo | Nullable | Descripcion |
|-------|------|----------|-------------|
| id | UUID | No | Identificador del reporte |
| url_normalized | TEXT | No | URL normalizada |
| url_hash | TEXT | Si | SHA256 de la URL |
| label | TEXT | No | Tipo de amenaza reportada |
| comment | TEXT | Si | Comentario del usuario |
| contact | TEXT | Si | Contacto opcional |
| source | TEXT | Si | Fuente (mobile_app, webapp) |
| created_at | TIMESTAMPTZ | No | Fecha de creacion |

---

## Migraciones Alembic

### Estructura de Archivos
```
database/
  migrations/
    env.py
    versions/
      001_initial_schema.py
```

### Comandos
```bash
# Crear nueva migracion
cd database
alembic revision -m "descripcion"

# Aplicar migraciones
alembic upgrade head

# Revertir ultima migracion
alembic downgrade -1

# Ver historial
alembic history
```

---

## Queries Utiles

### Contar registros
```sql
SELECT 'ingested_urls' as tabla, COUNT(*) as total FROM ingested_urls
UNION ALL
SELECT 'reports', COUNT(*) FROM reports;
```

### Contar por label (ingest)
```sql
SELECT
    label,
    COUNT(*) as total,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) as porcentaje
FROM ingested_urls
WHERE label IS NOT NULL
GROUP BY label;
```

### Contar reportes por tipo
```sql
SELECT
    label,
    COUNT(*) as total
FROM reports
GROUP BY label
ORDER BY total DESC;
```

### Buscar por URL
```sql
SELECT * FROM ingested_urls
WHERE url_hash = encode(sha256('https://example.com'::bytea), 'hex');
```

### URLs mas reportadas
```sql
SELECT
    url_normalized,
    COUNT(*) as num_reports
FROM reports
GROUP BY url_normalized
ORDER BY num_reports DESC
LIMIT 10;
```

---

## Fallback JSONL

Si PostgreSQL no esta disponible, el backend usa archivos JSONL:

- `datasets/ingested/ingested_urls.jsonl`
- `datasets/ingested/user_reports.jsonl`

**Formato:**
```json
{"id": "uuid", "url": "...", "url_normalized": "...", "label": 1, "created_at": "..."}
```

---

## Privacidad

### Datos que se guardan:
- URL completa (necesaria para analisis)
- Hash de URL (deduplicacion)
- Label (si se proporciona)
- Timestamp

### Datos que NO se guardan:
- IP del usuario
- Identificadores del dispositivo
- Datos personales (a menos que el usuario los proporcione voluntariamente en contact)

### Retencion
- URLs ingestadas: Indefinido (para entrenamiento)
- Reportes: 1 ano (configurable)

---

## Docker Compose

```yaml
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: alertalink
      POSTGRES_USER: alerta
      POSTGRES_PASSWORD: alerta123
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
```

---

**Ultima actualizacion:** 2026-01-01
