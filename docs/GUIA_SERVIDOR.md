# Guia de Ejecucion del Servidor ALERTA-LINK

> Guia paso a paso para iniciar el servidor backend y exponerlo a internet

---

## SISTEMA LISTO PARA USAR

> **La APK y el servidor ya estan configurados. Solo necesitas ejecutar 2 comandos.**

| Componente | Estado | Notas |
|------------|--------|-------|
| APK | ✅ Lista | `alerta_link_v2.apk` - URL permanente configurada |
| Modelo ML | ✅ Funcionando | GradientBoosting 98.75% accuracy |
| Named Tunnel | ✅ Configurado | `https://api.samuelortizospina.me` |
| APIs | ✅ Integradas | Tranco + VirusTotal |

---

## Inicio Rapido (TL;DR)

```bash
# Terminal 1: Iniciar Backend
cd "C:\Users\samuel Ortiz\Documents\proyecto de tesis\desarrollo\backend"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Iniciar Tunel (URL fija permanente)
cloudflared tunnel run alerta-link
```

**Verificar:** https://api.samuelortizospina.me/health

---

## Requisitos Previos

| Requisito | Version | Verificar con |
|-----------|---------|---------------|
| Python | 3.11+ | `python --version` |
| pip | cualquiera | `pip --version` |
| cloudflared | (opcional) | `cloudflared --version` |

### Instalar Cloudflared (opcional, para acceso remoto)

```bash
# Windows (con winget)
winget install Cloudflare.cloudflared

# O descargar de:
# https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/
```

---

## Paso 1: Configurar Variables de Entorno

Crear archivo `.env` en la carpeta `backend/`:

```bash
# backend/.env
VIRUSTOTAL_API_KEY=tu_api_key_aqui
```

**Obtener API key de VirusTotal:**
1. Ir a https://www.virustotal.com/
2. Crear cuenta gratuita
3. Ir a tu perfil > API Key
4. Copiar la key

---

## Paso 2: Instalar Dependencias

```bash
# Abrir terminal en la carpeta del proyecto
cd "C:\Users\samuel Ortiz\Documents\proyecto de tesis\desarrollo"

# Ir a la carpeta backend
cd backend

# Instalar dependencias
pip install -r requirements.txt
```

---

## Paso 3: Iniciar el Servidor

### Opcion A: Solo Red Local (tu casa/oficina)

```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Acceso:**
- Desde tu PC: http://localhost:8000
- Desde celular (misma WiFi): http://192.168.1.X:8000 (tu IP local)

### Opcion B: Acceso desde Internet (Named Tunnel - RECOMENDADO)

**Terminal 1 - Iniciar Backend:**
```bash
cd "C:\Users\samuel Ortiz\Documents\proyecto de tesis\desarrollo\backend"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Terminal 2 - Iniciar Named Tunnel:**
```bash
cloudflared tunnel run alerta-link
```

**Salida esperada:**
```
INF Starting tunnel tunnelID=e1cb11f8-1e7e-4fb2-9a9d-41aefebdfb78
INF Registered tunnel connection connIndex=0 location=bog04 protocol=quic
INF Registered tunnel connection connIndex=1 location=mia08 protocol=quic
```

**URL permanente:** `https://api.samuelortizospina.me`

**Ventaja:** La URL nunca cambia. No necesitas recompilar la APK.

---

## Paso 4: Verificar que Funciona

### Desde navegador:
- http://localhost:8000/health - Estado del servidor
- http://localhost:8000/docs - Documentacion API (Swagger)

### Desde terminal:
```bash
curl http://localhost:8000/health
```

**Respuesta esperada:**
```json
{
  "status": "ok",
  "version": "0.1.0",
  "model_loaded": true
}
```

---

## Diagrama: Como Funciona el Named Tunnel

```
┌─────────────────────────────────────────────────────────────────┐
│                    ARQUITECTURA CLOUDFLARE                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   CELULAR (cualquier red)                                       │
│        │                                                         │
│        ▼                                                         │
│   ┌─────────────────────────────────────────┐                   │
│   │ https://api.samuelortizospina.me        │ ← URL FIJA        │
│   └─────────────────────────────────────────┘                   │
│        │                                                         │
│        ▼ (HTTPS encriptado)                                     │
│   ┌─────────────────────────────────────────┐                   │
│   │       CLOUDFLARE EDGE NETWORK           │                   │
│   │       (servidores en la nube)           │                   │
│   └─────────────────────────────────────────┘                   │
│        │                                                         │
│        ▼ (conexion segura via Named Tunnel)                     │
│   ┌─────────────────────────────────────────┐                   │
│   │   TU PC                                 │                   │
│   │   ├── cloudflared tunnel run alerta-link│                   │
│   │   └── localhost:8000 (FastAPI)          │                   │
│   └─────────────────────────────────────────┘                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Ventajas del Named Tunnel:**
- URL FIJA permanente (no cambia al reiniciar)
- No necesitas abrir puertos en tu router
- HTTPS automatico (certificado gratis)
- Funciona desde cualquier red (WiFi, datos moviles)
- No necesitas recompilar la APK nunca mas

**Limitaciones:**
- Requiere tu PC encendida
- Requiere cloudflared corriendo

---

## Endpoints Disponibles

| Endpoint | Metodo | Descripcion |
|----------|--------|-------------|
| `/health` | GET | Estado del servidor |
| `/analyze` | POST | Analizar una URL |
| `/ingest` | POST | Ingresar URL al dataset |
| `/report` | POST | Reportar URL sospechosa |
| `/settings` | GET | Configuracion actual |
| `/docs` | GET | Documentacion Swagger |

### Ejemplo: Analizar URL

```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'
```

---

## Configurar la App Movil

> **LA APK YA ESTA CONFIGURADA - NO NECESITAS CAMBIAR NADA**

La APK `alerta_link_v2.apk` ya tiene la URL permanente configurada:

```dart
// lib/services/api_service.dart (YA CONFIGURADO)
static const String productionUrl = 'https://api.samuelortizospina.me';
```

### Solo para desarrollo local (opcional):
```dart
static const String developmentUrl = 'http://10.0.2.2:8000';  // Emulador
```

---

## Solucion de Problemas

### Error: "Port 8000 already in use"
```bash
# Ver que proceso usa el puerto
netstat -ano | findstr :8000

# Matar el proceso
taskkill /PID <numero_pid> /F
```

### Error: "Model not found"
```bash
# Verificar que existe el modelo
dir models\step1_baseline.pkl

# Si no existe, entrenar:
python scripts/train_step1.py
```

### Error: "VIRUSTOTAL_API_KEY not found"
Crear archivo `backend/.env` con tu API key (ver Paso 1).

### Error: "cloudflared not recognized"
Instalar cloudflared o reiniciar terminal despues de instalarlo.

### Tunel no conecta
```bash
# Verificar que el backend esta corriendo
curl http://localhost:8000/health

# Si falla, iniciar backend primero
```

---

## Scripts de Automatizacion

### Windows: iniciar_servidor.bat
```batch
@echo off
title ALERTA-LINK Servidor
cd /d "C:\Users\samuel Ortiz\Documents\proyecto de tesis\desarrollo\backend"
echo Iniciando servidor ALERTA-LINK...
echo Accede a: http://localhost:8000
echo Swagger UI: http://localhost:8000/docs
echo.
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
pause
```

### Windows: iniciar_con_tunel.bat
```batch
@echo off
title ALERTA-LINK + Cloudflare Named Tunnel
cd /d "C:\Users\samuel Ortiz\Documents\proyecto de tesis\desarrollo\backend"

echo Iniciando backend...
start /B cmd /c "python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"

timeout /t 3 /nobreak > nul

echo Iniciando Named Tunnel...
echo URL permanente: https://api.samuelortizospina.me
echo ========================================
cloudflared tunnel run alerta-link
```

---

## Opciones de Despliegue Permanente

| Opcion | Costo | Dificultad | URL Fija |
|--------|-------|------------|----------|
| Tu PC + Cloudflare Quick Tunnel | Gratis | Facil | No |
| Tu PC + Cloudflare Named Tunnel | Gratis | Media | Si |
| Render.com | Gratis* | Facil | Si |
| Railway.app | Gratis* | Facil | Si |
| VPS (DigitalOcean, etc) | $5/mes | Media | Si |

*Plan gratuito con limitaciones

### Para Render.com (recomendado):
Ver `backend/README_RENDER.md` para instrucciones detalladas.

---

## Contacto

Universidad Manuela Beltran - Ingenieria de Software 2025
- Cristian Salazar
- Samuel Ortiz Ospina
- Juan Stiven Castro

---

**Ultima actualizacion:** 2026-01-18

---

## Datos del Named Tunnel

| Dato | Valor |
|------|-------|
| URL Publica | `https://api.samuelortizospina.me` |
| Tunnel Name | `alerta-link` |
| Tunnel ID | `e1cb11f8-1e7e-4fb2-9a9d-41aefebdfb78` |
| Credenciales | `C:\Users\samuel Ortiz\.cloudflared\e1cb11f8-1e7e-4fb2-9a9d-41aefebdfb78.json` |
| Config | `C:\Users\samuel Ortiz\.cloudflared\config.yml` |
| Comando | `cloudflared tunnel run alerta-link` |
