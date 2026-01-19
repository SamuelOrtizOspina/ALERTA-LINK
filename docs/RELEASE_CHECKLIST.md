# Release Checklist - ALERTA-LINK

> Checklist para verificar antes de demo o despliegue

---

## Pre-Release Checklist

### Dataset y Modelo

- [ ] `datasets/processed/dataset_master.csv` existe
- [ ] `datasets/splits/train.csv` existe
- [ ] `datasets/splits/val.csv` existe
- [ ] `datasets/splits/test.csv` existe
- [ ] `models/step1_baseline.pkl` existe
- [ ] `reports/step1_metrics.json` existe
- [ ] F1-Score >= 0.80 en test set

**Comandos de verificacion:**
```bash
# Verificar archivos existen
ls datasets/processed/dataset_master.csv
ls models/step1_baseline.pkl

# Ver metricas
cat reports/step1_metrics.json | python -m json.tool | grep f1_score
```

---

### Backend

- [ ] `backend/requirements.txt` actualizado
- [ ] `backend/app/main.py` inicia sin errores
- [ ] Endpoint `/health` responde OK
- [ ] Endpoint `/analyze` funciona correctamente
- [ ] Endpoint `/ingest` guarda datos
- [ ] Endpoint `/report` guarda reportes
- [ ] Proteccion SSRF activa

**Comandos de verificacion:**
```bash
# Iniciar backend
cd backend
uvicorn app.main:app --port 8000

# En otra terminal
curl http://localhost:8000/health
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

---

### Docker

- [ ] `docker-compose.yml` actualizado
- [ ] `backend/Dockerfile` construye sin errores
- [ ] PostgreSQL inicia correctamente
- [ ] Backend conecta a PostgreSQL

**Comandos de verificacion:**
```bash
docker-compose up -d
docker-compose ps
docker logs alertalink-api
curl http://localhost:8000/health
```

---

### Documentacion

- [ ] `docs/INDEX.md` actualizado
- [ ] `docs/DATASET.md` refleja el dataset actual
- [ ] `docs/TRAINING_STEP1.md` documenta el modelo
- [ ] `docs/API.md` documenta todos los endpoints
- [ ] `docs/MOBILE_APP.md` describe la app
- [ ] `docs/RUNBOOK.md` tiene comandos correctos
- [ ] `README.md` actualizado

---

### App Movil (cuando este lista)

- [ ] `mobile/pubspec.yaml` tiene dependencias correctas
- [ ] `flutter pub get` funciona
- [ ] App compila sin errores
- [ ] App conecta al backend
- [ ] Pantalla Home funciona
- [ ] Pantalla Resultado muestra semaforo
- [ ] Funcion Reportar envia datos

---

## Demo Checklist

### Preparacion

1. [ ] Iniciar backend (docker o local)
2. [ ] Verificar modelo cargado (ver log "Modelo ML cargado")
3. [ ] Tener URLs de ejemplo listas
4. [ ] Verificar conexion a internet

### URLs de Ejemplo

**Legitimas (score bajo):**
```
https://www.google.com
https://www.bancolombia.com
https://www.microsoft.com
```

**Sospechosas (score alto):**
```
https://paypa1-secure.xyz/login
https://banco-verify.tk/cuenta
http://192.168.1.1/login
```

### Flujo de Demo

1. Mostrar `/health` - sistema OK
2. Analizar URL legitima - score bajo, semaforo verde
3. Analizar URL sospechosa - score alto, semaforo rojo
4. Mostrar senales detectadas
5. Mostrar recomendaciones
6. (Opcional) Demostrar reporte

---

## Post-Release

- [ ] Monitorear logs de errores
- [ ] Verificar uso de recursos (CPU, memoria)
- [ ] Revisar reportes de usuarios
- [ ] Recopilar feedback

---

## Rollback

Si algo falla:

```bash
# Detener servicios
docker-compose down

# Restaurar version anterior del modelo
git checkout HEAD~1 -- models/step1_baseline.pkl

# Reiniciar
docker-compose up -d
```

---

**Version:** 1.0
**Fecha:** 2026-01-01
