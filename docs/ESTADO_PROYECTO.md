# ALERTA-LINK - Estado del Proyecto
**Fecha de actualizacion:** 2026-01-09

## Resumen Ejecutivo

Sistema Forense Automatico de Deteccion de Phishing para dispositivos moviles.

**Progreso general: ~90%**

---

## Estado por Fases (del PDF)

### FASE 1: Recopilacion de Datos - COMPLETADA (100%)
- Dataset: **5,000 URLs** (2,500 phishing + 2,500 legitimas)
- Fuentes: Phishing Database, URLs legitimas de Tranco Top 100
- Verificacion: **75 URLs verificadas con VirusTotal (100% confirmadas)**
- Expansiones: 3 rondas de 500 URLs cada una via VirusTotal API

### FASE 2: Desarrollo de Heuristicas - COMPLETADA (100%)
- **24 features extraidas** de cada URL
- **14+ senales de riesgo** explicables
- Integracion con:
  - Tranco API (verificacion de dominios legitimos)
  - VirusTotal API (verificacion de URLs maliciosas)

### FASE 3: Prototipo Backend/App - COMPLETADA (100%)

#### Backend FastAPI (100%)
| Endpoint | Estado | Descripcion |
|----------|--------|-------------|
| GET /health | OK | Verificar estado del servidor |
| GET /health/db | OK | Estado detallado de BD |
| POST /analyze | OK | Analizar URL y obtener score |
| POST /ingest | OK | Ingestar nueva URL al dataset |
| POST /report | OK | Reportar URL sospechosa |
| GET /settings | OK | Obtener configuracion |
| POST /settings/mode | OK | Cambiar modo (auto/online/offline) |
| GET /settings/status | OK | Estado de conectividad |

#### App Flutter + Kotlin (100%)

Nueva arquitectura hibrida donde Flutter maneja TODA la logica y Kotlin solo las notificaciones.

| Componente | Estado | Responsabilidad |
|------------|--------|-----------------|
| **Flutter (Dart)** | OK | UI, analisis, API calls, historial, config |
| **Kotlin (Android)** | OK | Solo NotificationListenerService |

##### Pantallas Flutter
| Pantalla | Estado | Descripcion |
|----------|--------|-------------|
| HomeScreen | OK | Ingreso manual de URL |
| ResultScreen | OK | Semaforo de riesgo + senales |
| SettingsScreen | OK | Toggle modo conexion |
| HistoryScreen | OK | Historial de analisis |

##### Arquitectura
```
+---------------------------+
|      Flutter (Dart)       |  <- TODA la logica aqui
|  - UI / Pantallas         |
|  - Analisis de URLs       |
|  - Llamadas a API         |
|  - Historial              |
|  - Configuracion          |
+-------------+-------------+
              |
      Platform Channel
         "push_channel"
              |
+-------------+-------------+
|      Kotlin (Android)     |  <- Solo notificaciones
|  - NotificationListener   |
|  - Extraer URLs           |
|  - Cancelar notificacion  |
+---------------------------+
```

#### App Android/Kotlin Legacy (90%)
| Pantalla | Estado | Descripcion |
|----------|--------|-------------|
| MainActivity | OK | Ingreso de URL |
| ResultActivity | OK | Semaforo de riesgo + senales |
| SettingsActivity | OK | Toggle modo conexion |
| HistoryActivity | OK | Historial de analisis |
| ReportActivity | OK | Reportar URLs |
| Share Intent | OK | Recibir URLs de otras apps |

### FASE 4: Modelo ML - COMPLETADA (100%)

**Metricas del modelo (dataset 5,000 URLs):**
| Metrica | Valor |
|---------|-------|
| Accuracy | 1.0000 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| F1-Score | 1.0000 |
| ROC-AUC | 1.0000 |

**Confusion Matrix (Test set - 800 URLs):**
```
         Predicho
          0    1
Real 0  400    0   (TN=400, FP=0)
     1    0  400   (FN=0, TP=400)
```

**Features mas importantes:**
1. digit_ratio (4.20)
2. has_https (-3.01)
3. domain_length (2.83)
4. num_hyphens (1.76)
5. num_dots (1.72)

### FASE 5: Validacion con Usuarios - EN PROGRESO (25%)
- [x] Disenar encuesta de usabilidad (ver docs/PRUEBA_PILOTO.md)
- [ ] Seleccionar grupo de prueba (5-10 usuarios)
- [ ] Ejecutar prueba piloto
- [ ] Recopilar feedback
- [ ] Ajustar segun resultados

### FASE 6: Documentacion Final - EN PROGRESO (80%)
- [x] Documentacion tecnica del backend
- [x] README de la app Android
- [x] README de la app Flutter
- [x] Plan de Fase 2
- [x] Estado del proyecto actualizado
- [x] Documentacion de prueba piloto
- [ ] Manual de usuario completo
- [ ] Presentacion final

---

## Modo Online/Offline

El sistema soporta 3 modos de operacion:

| Modo | Comportamiento | APIs usadas |
|------|---------------|-------------|
| **Auto** (default) | Detecta automaticamente | Si hay conexion: Tranco + VT |
| **Online** | Forzar uso de APIs | Tranco + VirusTotal |
| **Offline** | Solo analisis local | ML + Heuristicas |

El usuario puede cambiar el modo desde la app en cualquier momento.

---

## Arquitectura del Sistema

```
+------------------+
|   App Flutter    |
|   (Dart+Kotlin)  |
+--------+---------+
         |
         | HTTP REST
         v
+------------------+
|  Backend FastAPI |
|  (Python)        |
+--------+---------+
         |
    +----+----+----+
    |    |    |    |
    v    v    v    v
  ML   Tranco  VT   DB
Model  API   API  (PostgreSQL/JSONL)
```

---

## Comparacion PDF vs Implementacion

| Requisito PDF | Estado | Notas |
|---------------|--------|-------|
| >=6k URLs dataset | 83% | Tenemos 5,000 URLs |
| XGBoost/LightGBM | Alternativo | LogisticRegression funciona igual |
| Features de contenido | Parcial | Solo features de URL |
| App movil funcional | OK | Flutter + Kotlin |
| API RESTful | OK | FastAPI completo |
| Prueba piloto | Pendiente | Documentacion lista |
| Documentacion | 80% | En progreso |

---

## Proximos Pasos

1. **Fase 5**: Prueba piloto con usuarios
   - Compilar APK de Flutter
   - Distribuir a 5-10 usuarios de prueba
   - Recopilar metricas de usabilidad

2. **Fase 6**: Documentacion final
   - Completar manual de usuario
   - Preparar presentacion

---

## Recursos

- **Dataset**: `datasets/splits/train.csv` (5,000 URLs)
- **Modelo ML**: `models/best_model.pkl`
- **Backend**: `backend/`
- **App Flutter**: `alerta_link_flutter/`
- **App Android Legacy**: `android-app/`
- **Documentacion**: `docs/`

---

## Autores

- Cristia Salazar
- Samuel Ortiz Ospina
- Juan Stiven Castro

**Universidad Manuela Beltran - Ingenieria de Software 2025**
