# ALERTA-LINK - Documentacion

> Sistema de Analisis Forense Automatico para deteccion de URLs de phishing/smishing

**Universidad Manuela Beltran** | Ingenieria de Software | 2025

**Autores:** Cristian Salazar, Samuel Ortiz Ospina, Juan Stiven Castro

---

## DOCUMENTO MAESTRO

**[DOCUMENTACION_MAESTRA.md](DOCUMENTACION_MAESTRA.md)** - Documento completo con TODA la documentacion del proyecto en un solo archivo. Incluye arquitectura, dataset, modelo ML, API, app, configuracion, despliegue, troubleshooting y manual de usuario.

---

## Tabla de Contenido

### Estado y Planificacion

1. [ESTADO_PROYECTO.md](ESTADO_PROYECTO.md) - Estado actual de todas las fases
2. [FASE2_PLAN.md](FASE2_PLAN.md) - Plan de Fase 2

### Documentacion Tecnica

3. [DATASET.md](DATASET.md) - Fuentes de datos, schema y estadisticas
4. [TRAINING_STEP1.md](TRAINING_STEP1.md) - Pipeline de entrenamiento baseline
5. [API.md](API.md) - Documentacion de endpoints REST
6. [MOBILE_APP.md](MOBILE_APP.md) - Guia de la aplicacion movil Android
7. [DB_SCHEMA.md](DB_SCHEMA.md) - Esquema de base de datos
8. [database/DATABASE_INTEGRATION.md](database/DATABASE_INTEGRATION.md) - Integracion de BD

### Usuario Final

9. [MANUAL_USUARIO.md](MANUAL_USUARIO.md) - Manual de usuario de la app
10. [PRUEBA_PILOTO.md](PRUEBA_PILOTO.md) - Protocolo de prueba piloto (Fase 5)

### Operaciones y Despliegue

11. [RUNBOOK.md](RUNBOOK.md) - Guia de operaciones y troubleshooting
12. [GUIA_SERVIDOR.md](GUIA_SERVIDOR.md) - Como iniciar el servidor (local y remoto)
13. [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) - Opciones de despliegue en la nube

### Seguridad

14. [SECURITY_AUDIT.md](SECURITY_AUDIT.md) - Auditoria de seguridad
15. [SECURITY_FIXES.md](SECURITY_FIXES.md) - Correcciones de seguridad aplicadas

### Politicas

16. [PRIVACY_POLICY.md](PRIVACY_POLICY.md) - Politica de privacidad
17. [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) - Checklist para despliegue

---

## Inicio Rapido

### 1. Construir dataset
```bash
python scripts/build_large_dataset.py
```

### 2. Entrenar modelo
```bash
python scripts/train_step1.py
```

### 3. Evaluar modelo
```bash
python scripts/evaluate_step1.py
```

### 4. Iniciar backend
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 5. Compilar app Flutter
```bash
cd alerta_link_flutter
flutter build apk --release
```

---

## Estado del Proyecto

| Componente | Estado | Descripcion |
|------------|--------|-------------|
| Dataset | OK | 6,000 URLs (3k legitimas + 3k phishing) |
| ML Model | OK | GradientBoosting 98.75% accuracy |
| Backend API | OK | FastAPI + VirusTotal integration |
| App Flutter | OK | Android APK con permisos minimos |
| Base de Datos | OK | PostgreSQL + fallback JSONL |
| Cloudflare Tunnel | OK | Acceso remoto sin abrir puertos |
| Manual Usuario | OK | Completo |

---

## Arquitectura del Sistema

```
+------------------+
|   App Flutter    |  ← APK Android
|   (Dart)         |
+--------+---------+
         |
         | HTTPS
         v
+------------------+
|  Cloudflare      |  ← Tunel seguro (opcional)
|  Tunnel          |
+--------+---------+
         |
         v
+------------------+
|  Backend FastAPI |  ← Tu PC o servidor cloud
|  (Python)        |
+--------+---------+
         |
    +----+----+----+
    |    |    |    |
    v    v    v    v
  ML   Tranco  VT   DB
Model  API   API  (JSONL)
```

---

## Progreso por Fases

| Fase | Descripcion | Progreso |
|------|-------------|----------|
| 1 | Recopilacion de Datos | 100% |
| 2 | Heuristicas | 100% |
| 3 | Prototipo | 100% |
| 4 | Modelo ML | 100% |
| 5 | Prueba Piloto | 25% |
| 6 | Documentacion | 90% |

**Progreso General: ~90%**

---

**Ultima actualizacion:** 2026-01-17
