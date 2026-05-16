# Guia de Instalacion - ALERTA-LINK

> Instalacion completa del sistema ALERTA-LINK desde cero, en una maquina nueva.

---

## Vision general

```
                          +-----------------------+
                          |   Cloudflare Tunnel   |
                          |  alerta.<tu-dominio>  |
                          +-----------+-----------+
                                      |
+----------+ HTTPS                    v
|  Movil   +-------------> +----------+----------+
| (Flutter |   APK         |  Backend FastAPI    |
|  APK)    |   --- analiza |  localhost:8000     |
+----------+               +----+--------+-------+
                                |        |
                          +-----v--+   +-v-----------+
                          |Postgres|   |Tranco/VT API|
                          | Docker |   |  externas   |
                          +--------+   +-------------+
```

El sistema tiene 4 componentes principales:

1. **Backend FastAPI** (Python) - motor de analisis
2. **Base de datos PostgreSQL** (Docker) - persistencia
3. **Cloudflare Tunnel** - puente publico hacia tu PC
4. **App movil Flutter** - cliente Android

---

## Pre-requisitos

| Software | Version minima | Donde se usa |
|----------|----------------|--------------|
| Python | 3.11+ | Backend |
| Docker Desktop | cualquiera reciente | PostgreSQL |
| Flutter | 3.16+ | App movil |
| Git | cualquiera | Clonar repo |
| cloudflared | 2025+ | Tunnel publico |
| Cuenta Cloudflare | gratuita | DNS |
| Cuenta VirusTotal | gratuita | API de reputacion |
| Cuenta Tranco | gratuita | Ranking de dominios |

Verificar instalaciones:

```powershell
python --version          # >= 3.11
docker --version          # cualquiera
flutter --version         # >= 3.16
git --version             # cualquiera
cloudflared --version     # >= 2025
```

---

## PASO 1: Clonar el repositorio

```powershell
cd "C:\Users\<tu-usuario>\Documents"
git clone https://github.com/SamuelOrtizOspina/ALERTA-LINK.git
cd ALERTA-LINK
```

---

## PASO 2: Crear entorno virtual de Python

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r backend/requirements.txt
```

Las dependencias principales son: `fastapi`, `uvicorn`, `pydantic-settings`, `requests`, `scikit-learn`, `slowapi`, `python-dotenv`.

---

## PASO 3: Configurar variables de entorno

### 3.1 Crear `backend/.env`

```powershell
Copy-Item .env.example backend\.env
```

### 3.2 Editar `backend/.env` con tus credenciales

```env
# API Keys Externas
VIRUSTOTAL_API_KEY=<tu_api_key_de_virustotal>
VIRUSTOTAL_THRESHOLD=3
VIRUSTOTAL_UNCERTAINTY_MIN=30
VIRUSTOTAL_UNCERTAINTY_MAX=70

# Tranco API
TRANCO_API_KEY=<tu_api_key_de_tranco>
TRANCO_API_EMAIL=<tu_email_de_tranco>
TRANCO_RANK_THRESHOLD=10000

# Base de Datos
DATABASE_URL=postgresql://alerta:alerta123@localhost:5432/alertalink

# Seguridad - generar con: python -c "import secrets; print(secrets.token_urlsafe(32))"
SECRET_KEY=<clave_aleatoria_segura>
```

### Como obtener las API keys

| Servicio | Donde | Limites gratuitos |
|----------|-------|-------------------|
| VirusTotal | https://www.virustotal.com/gui/my-apikey | 4 req/min, 500 req/dia |
| Tranco | https://tranco-list.eu/api_documentation | 1 query/segundo |

---

## PASO 4: Levantar PostgreSQL con Docker

```powershell
docker compose up -d postgres
```

Esperar 10-20 segundos hasta el healthcheck OK:

```powershell
docker ps --filter "name=alertalink-db"
```

Deberia mostrar `Status: Up X seconds (healthy)`.

### 4.1 Cargar el esquema relacional

```powershell
Get-Content database\schema.sql -Raw | docker exec -i alertalink-db psql -U alerta -d alertalink
```

Verificar las 6 tablas:

```powershell
docker exec alertalink-db psql -U alerta -d alertalink -c "\dt"
```

Resultado esperado:

```
analysis_results
analysis_signals
ingested_urls
reports
system_settings
urls
```

---

## PASO 5: Configurar el dominio (Cloudflare Tunnel)

> Si solo vas a usar el sistema en red local, **puedes saltar este paso** y la app movil apuntara a la IP local. Para acceso publico con HTTPS sigue leyendo.

### 5.1 Crear cuenta Cloudflare y agregar dominio

Ver guia detallada: [GUIA_CAMBIO_DOMINIO.md](GUIA_CAMBIO_DOMINIO.md) (pasos 1-3).

Resumen:
1. Crear cuenta en https://dash.cloudflare.com/sign-up
2. Add Site -> tu dominio -> plan Free
3. Cambiar nameservers en el registrador a los de Cloudflare
4. Esperar propagacion DNS (5-30 min)

### 5.2 Autenticar cloudflared

```powershell
cloudflared tunnel login
```

Se abre el navegador. Login y autoriza el dominio.

### 5.3 Crear el tunnel

```powershell
cloudflared tunnel create alerta-link
```

Anotar el `<TUNNEL_ID>` del output.

### 5.4 Crear `~/.cloudflared/config.yml`

```yaml
url: http://localhost:8000
tunnel: <TUNNEL_ID>
credentials-file: C:\Users\<tu-usuario>\.cloudflared\<TUNNEL_ID>.json
```

### 5.5 Crear el subdominio

```powershell
cloudflared tunnel route dns alerta-link alerta.<tu-dominio>
```

---

## PASO 6: Arrancar el backend

### Terminal 1 - Backend

```powershell
cd "C:\Users\<tu-usuario>\Documents\ALERTA-LINK\backend"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Esperar logs:
```
Modelo ML cargado exitosamente
Application startup complete
Uvicorn running on http://0.0.0.0:8000
```

### Terminal 2 - Tunnel

```powershell
cloudflared tunnel run alerta-link
```

Esperar:
```
Registered tunnel connection connIndex=0 ...
Registered tunnel connection connIndex=1 ...
```

### Verificar acceso publico

```powershell
curl https://alerta.<tu-dominio>/health
```

Respuesta esperada:
```json
{"status":"ok","version":"0.1.0","model_loaded":true,"apis":{"tranco":true,"virustotal":true}}
```

---

## PASO 7: Compilar la app movil Flutter

Si necesitas un APK con tu dominio personalizado:

```powershell
cd alerta_link_flutter
flutter clean
flutter pub get
flutter build apk --release
Copy-Item "build\app\outputs\flutter-apk\app-release.apk" "..\ALERTA-LINK-v1.2.1.apk"
```

Detalles completos en [GUIA_COMPILAR_APK.md](GUIA_COMPILAR_APK.md).

---

## PASO 8: Instalar APK en el celular

```powershell
adb install -r ALERTA-LINK-v1.2.1.apk
```

O transferir el archivo manualmente al celular y tocarlo para instalar.

---

## PASO 9: Probar el sistema

1. Abrir ALERTA-LINK en el celular
2. Verificar que el backend + tunnel siguen corriendo
3. Probar URL segura:
   ```
   https://www.google.com
   ```
   Esperado: semaforo VERDE
4. Probar typosquatting:
   ```
   https://gooogle.com
   ```
   Esperado: semaforo ROJO con senales `TYPOSQUATTING`, `BRAND_IMPERSONATION`, `DOMAIN_NOT_IN_TRANCO`

---

## Verificacion completa - Checklist

- [ ] Python 3.11+ instalado
- [ ] Docker Desktop corriendo
- [ ] Postgres container `alertalink-db` arriba y healthy
- [ ] Esquema `schema.sql` ejecutado (6 tablas presentes)
- [ ] `backend/.env` con API keys configuradas
- [ ] Backend responde `200` en `http://localhost:8000/health`
- [ ] Cloudflare DNS activo (`nslookup` muestra nameservers de Cloudflare)
- [ ] Tunnel corriendo con `connIndex=0..3 registered`
- [ ] `https://alerta.<dominio>/health` devuelve `200`
- [ ] APK compilado e instalado
- [ ] App detecta `google.com` como SAFE
- [ ] App detecta `gooogle.com` como HIGH (typosquat)

---

## Troubleshooting

### El backend no arranca: ImportError

Causa: faltan dependencias.
Solucion:
```powershell
.\venv\Scripts\activate
pip install -r backend/requirements.txt
```

### "Port 8000 already in use"

Causa: ya hay un backend corriendo.
Solucion:
```powershell
$procs = Get-NetTCPConnection -LocalPort 8000 -State Listen | Select-Object -ExpandProperty OwningProcess -Unique
foreach ($p in $procs) { Stop-Process -Id $p -Force }
```

### Docker postgres no esta healthy

Causa: contenedor todavia inicializando, o conflicto con otro postgres local.
Solucion:
```powershell
docker logs alertalink-db
docker compose restart postgres
```

### `cloudflared tunnel route dns` falla con "Tunnel not found"

Causa: el tunnel esta en otra cuenta Cloudflare.
Solucion:
```powershell
cloudflared tunnel list
# Si no aparece tu tunnel, crearlo:
cloudflared tunnel create alerta-link
# Y actualizar config.yml con el nuevo TUNNEL_ID
```

### "Authentication error" al crear DNS route

Causa: el cert.pem es para otro dominio.
Solucion:
```powershell
Rename-Item "$env:USERPROFILE\.cloudflared\cert.pem" "cert.pem.old.bak"
cloudflared tunnel login   # autorizar el nuevo dominio
```

### La app dice "Sin conexion al servidor"

Causa: backend o tunnel caidos, o URL en APK incorrecta.
Solucion:
1. Verifica `curl https://alerta.<dominio>/health` desde el PC
2. Si responde, abrir esa URL en el navegador del celular - debe responder lo mismo
3. Si tampoco responde en el celular, problema de DNS local
4. Si responde en el celular pero la app no, recompilar el APK (la URL queda quemada en el binario)

### "Cleartext HTTP traffic not permitted"

Causa: la app esta intentando usar `http://` (sin S) pero solo se permite HTTPS para tu dominio.
Solucion: usa siempre `https://alerta.<dominio>` desde el codigo.

---

## Operacion diaria - Comandos de uso frecuente

```powershell
# Arrancar todo en orden
docker compose up -d postgres
cd backend; python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# En otra terminal:
cloudflared tunnel run alerta-link

# Verificar salud
curl http://localhost:8000/health
curl https://alerta.<dominio>/health

# Logs en vivo del tunnel
# (los muestra el comando 'tunnel run' directamente)

# Detener postgres
docker compose stop postgres

# Apagar todo
docker compose down
# Ctrl+C en las terminales de backend y tunnel
```

---

## Estructura del proyecto

```
ALERTA-LINK/
+-- backend/                    Backend FastAPI
|   +-- app/
|   |   +-- main.py             Entry point
|   |   +-- api/routes/         Endpoints REST
|   |   +-- services/           Logica de negocio
|   |   |   +-- predictor.py    Modelo ML
|   |   |   +-- heuristic_predictor.py  Motor heuristico
|   |   |   +-- tranco_service.py       Cliente Tranco
|   |   |   +-- virustotal_service.py   Cliente VT
|   |   +-- core/config.py      Config global
|   |   +-- models/             SQLAlchemy ORM
|   |   +-- schemas/            Pydantic schemas
|   +-- requirements.txt
|   +-- .env                    Secretos (NO subir a git)
+-- alerta_link_flutter/        App movil Flutter
|   +-- lib/
|   |   +-- services/api_service.dart   Cliente HTTP
|   |   +-- screens/                    UI
|   +-- android/                Codigo nativo Android
|   +-- pubspec.yaml            Dependencias Flutter
+-- database/
|   +-- schema.sql              Esquema PostgreSQL completo
|   +-- migrations/             Migraciones Alembic
+-- docs/
|   +-- INDEX.md                Indice de documentos
|   +-- GUIA_INSTALACION.md     Esta guia
|   +-- GUIA_COMPILAR_APK.md    Como compilar el APK
|   +-- GUIA_CAMBIO_DOMINIO.md  Como cambiar de dominio
|   +-- DOCUMENTACION_MAESTRA.md  Doc tecnica completa
+-- models/                     Modelos ML entrenados
+-- datasets/                   Datasets de URLs
+-- docker-compose.yml          PostgreSQL en Docker
+-- ALERTA-LINK-v*.apk          APKs versionados
```

---

## Soporte y enlaces

- Repositorio: https://github.com/SamuelOrtizOspina/ALERTA-LINK
- Issues: https://github.com/SamuelOrtizOspina/ALERTA-LINK/issues
- Releases: https://github.com/SamuelOrtizOspina/ALERTA-LINK/releases

---

**Universidad Manuela Beltran - Ingenieria de Software 2025**
*Cristian Salazar - Samuel Ortiz Ospina - Juan Stiven Castro*

**Ultima actualizacion:** 2026-05-16
