# Guia: Cambiar de Dominio y Configurar el Tunnel

> Guia paso a paso para cuando cambies de dominio en el futuro o quieras configurar el sistema en uno nuevo.
> Basada en la migracion real de `samuelortizospina.me` a `mirrorhub.tech` (2026-05-16).

---

## Arquitectura

```
TU PC (backend localhost:8000) --> Cloudflare Tunnel --> https://<sub>.<dominio>
```

El dominio es solo el "puente". Tu PC sigue siendo el servidor. Si cambias de dominio, no cambias el codigo del modelo ni la BD, solo el "puente publico".

---

## Pre-requisitos

Antes de empezar verifica:

- [ ] Tienes acceso al registrador del dominio (donde se compro: get.tech, Namecheap, GoDaddy, etc.)
- [ ] Si el dominio es de otra persona, tu amigo/duenio puede entrar al panel del registrador
- [ ] Tienes una cuenta de Cloudflare (gratis: https://dash.cloudflare.com/sign-up)
- [ ] Tienes `cloudflared` instalado (`cloudflared --version`)
- [ ] Tu backend corre localmente sin errores (`uvicorn app.main:app --port 8000`)

---

## Variables que vas a usar

Reemplaza estos valores en TODOS los comandos de la guia:

| Variable | Ejemplo | Tu valor |
|----------|---------|----------|
| `<DOMINIO>` | `mirrorhub.tech` | _ _ _ _ _ |
| `<SUBDOMINIO>` | `alerta` | _ _ _ _ _ |
| `<URL_COMPLETA>` | `alerta.mirrorhub.tech` | _ _ _ _ _ |
| `<TUNNEL_NAME>` | `alerta-link` | _ _ _ _ _ |

---

## PASO 1: Agregar el dominio en Cloudflare

1. Entra a https://dash.cloudflare.com/
2. Click en **"+ Add"** -> **"Connect a domain"**
3. Escribe el dominio (sin `https://`, sin `www`): `<DOMINIO>`
4. Plan **Free** -> **Continue**
5. Cloudflare escanea los DNS actuales y muestra los registros existentes. **Dejalos como estan** (no los borres aunque no los reconozcas, pueden ser de otros servicios).
6. Click **"Continue to activation"**

Cloudflare te muestra **2 nameservers** (estilo `xxxxx.ns.cloudflare.com`). Anotalos.

---

## PASO 2: Cambiar nameservers en el registrador

Esto se hace **una sola vez** y desde el panel del registrador del dominio.

### Si el dominio es tuyo

1. Entra al panel del registrador (get.tech, Namecheap, etc.)
2. Busca tu dominio -> **Manage Domain** o **DNS Settings**
3. Busca la opcion **"Nameservers"** (NO es lo mismo que "DNS Records")
4. Elige **"Custom nameservers"** y reemplaza los actuales por los **2 de Cloudflare**
   - **IMPORTANTE:** Uno en cada campo, NO los dos juntos en un mismo campo
5. **Save**

### Si el dominio es de un amigo

Mandale este mensaje (reemplaza los nameservers por los tuyos):

```
Por favor entra al registrador del dominio <DOMINIO> -> Manage Domain -> Nameservers.
Cambia los actuales por estos 2 de Cloudflare:

  alec.ns.cloudflare.com
  frida.ns.cloudflare.com

Uno en cada campo. Guarda. Es 1 sola vez, despues yo manejo todo desde Cloudflare.
```

### Volver a Cloudflare

Despues de guardar, click en **"I updated my nameservers"** en Cloudflare.

---

## PASO 3: Verificar propagacion DNS

La propagacion puede tardar de **5 minutos a 24 horas** (normalmente <1 hora).

```powershell
nslookup -type=NS <DOMINIO> 8.8.8.8
```

> Usar `8.8.8.8` (Google DNS) evita el cache de tu ISP.

**Listo cuando responde:**
```
<DOMINIO>  nameserver = alec.ns.cloudflare.com
<DOMINIO>  nameserver = frida.ns.cloudflare.com
```

**Aun no si responde con:**
- Nameservers del registrador viejo (`orderbox-dns.com`, `namify.io`, etc.)

Cuando este listo, te llega un email de Cloudflare:
```
Subject: <DOMINIO> is now active on Cloudflare
```

---

## PASO 4: Re-autenticar cloudflared (si cambias de cuenta Cloudflare)

Si el dominio nuevo esta en una **cuenta de Cloudflare distinta** a la del dominio viejo, hay que re-autenticar.

### 4.1 Respaldar el cert.pem viejo

```powershell
Rename-Item "$env:USERPROFILE\.cloudflared\cert.pem" "cert.pem.old.bak" -Force
```

### 4.2 Hacer login nuevo

```powershell
cloudflared tunnel login
```

Se abrira el navegador:
1. Login con tu cuenta de Cloudflare (la que tiene `<DOMINIO>`)
2. Selecciona el dominio `<DOMINIO>` en la lista
3. Click **Authorize**

Mensaje esperado:
```
You have successfully logged in.
```

---

## PASO 5: Crear el tunnel

Verifica primero si ya existe un tunnel con ese nombre en la cuenta actual:

```powershell
cloudflared tunnel list
```

### Si NO existe

Crea uno nuevo:

```powershell
cloudflared tunnel create <TUNNEL_NAME>
```

Output esperado:
```
Tunnel credentials written to C:\Users\<user>\.cloudflared\<TUNNEL_ID>.json
Created tunnel <TUNNEL_NAME> with id <TUNNEL_ID>
```

**Anota el `<TUNNEL_ID>`** que sale ahi (es un UUID tipo `e1753651-584b-4d70-9769-20bcd2b3c5f2`).

### Si SI existe

Toma nota del ID con `cloudflared tunnel info <TUNNEL_NAME>` y salta al paso 6.

---

## PASO 6: Actualizar config.yml

Archivo: `C:\Users\<tu-usuario>\.cloudflared\config.yml`

```yaml
url: http://localhost:8000
tunnel: <TUNNEL_ID>
credentials-file: C:\Users\<tu-usuario>\.cloudflared\<TUNNEL_ID>.json
```

Reemplaza `<TUNNEL_ID>` por el UUID del paso anterior.

---

## PASO 7: Crear el subdominio (CNAME)

```powershell
cloudflared tunnel route dns <TUNNEL_NAME> <URL_COMPLETA>
```

Ejemplo:
```powershell
cloudflared tunnel route dns alerta-link alerta.mirrorhub.tech
```

Output esperado:
```
INF Added CNAME alerta.mirrorhub.tech which will route to this tunnel tunnelID=<TUNNEL_ID>
```

**NO crees el CNAME manualmente desde la web de Cloudflare**, este comando lo hace solo y sin errores.

---

## PASO 8: Actualizar el codigo del proyecto

Reemplaza el dominio viejo por el nuevo en estos archivos:

| Archivo | Que cambiar |
|---------|-------------|
| `.env.example` | `CORS_ORIGINS` |
| `backend/app/core/config.py` | `CORS_ORIGINS` |
| `alerta_link_flutter/lib/services/api_service.dart` | `productionUrl` |
| `alerta_link_flutter/android/app/src/main/kotlin/com/alertalink/alerta_link/SmsAnalyzer.kt` | `API_URL` |
| `alerta_link_flutter/android/app/src/main/res/xml/network_security_config.xml` | `<domain>` |
| `README.md` | `API Produccion` |
| `docs/GUIA_SERVIDOR.md` | URLs |
| `docs/DEPLOYMENT_GUIDE.md` | URLs |
| `docs/DOCUMENTACION_MAESTRA.md` | URLs |
| `docs/SECURITY_FIXES.md` | URLs |

Busqueda global util:

```powershell
# PowerShell - buscar todas las referencias al dominio viejo
Get-ChildItem -Recurse -Include *.dart,*.py,*.md,*.kt,*.xml,*.example -Exclude venv | Select-String "<DOMINIO_VIEJO>"
```

---

## PASO 9: Recompilar la APK

```powershell
cd alerta_link_flutter
flutter clean
flutter build apk --release
```

APK queda en: `build\app\outputs\flutter-apk\app-release.apk`

Instala en el celular para usar la nueva URL.

---

## PASO 10: Arrancar el sistema

### Terminal 1 - Backend

```powershell
cd "C:\Users\samuel Ortiz\Documents\proyecto de tesis\desarrollo\backend"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Terminal 2 - Tunnel

```powershell
cloudflared tunnel run <TUNNEL_NAME>
```

Espera 10-15 segundos hasta ver:
```
INF Registered tunnel connection connIndex=0 location=...
INF Registered tunnel connection connIndex=1 location=...
```

### Verificar

```powershell
curl https://<URL_COMPLETA>/health
```

Respuesta esperada:
```json
{"status": "ok", "version": "0.1.0", "model_loaded": true}
```

---

## Troubleshooting

### Error: "Failed to add route: code 10000, Authentication error"

**Causa:** `cert.pem` esta autorizado para otro dominio.
**Solucion:** Ver Paso 4 (re-autenticar).

### Error: "Failed to add route: code 1002, Tunnel not found"

**Causa:** El tunnel esta en otra cuenta de Cloudflare.
**Solucion:** Ver Paso 5 (crear un nuevo tunnel en la cuenta actual).

### Error: "Failed to modify the nameservers" (en get.tech/registrador)

**Causa:** Los 2 nameservers estan juntos en un mismo campo.
**Solucion:** Uno por campo. `alec.ns.cloudflare.com` en el campo 1, `frida.ns.cloudflare.com` en el campo 2.

### `nslookup` sigue mostrando nameservers viejos

**Causa:** Cache del ISP local.
**Solucion:**
```powershell
ipconfig /flushdns
nslookup -type=NS <DOMINIO> 8.8.8.8
```

Si tras 24h sigue mostrando los viejos, el cambio en el registrador no quedo guardado. Verifica con el duenio del dominio.

### Error: "cleartext HTTP traffic not permitted" en la APK

**Causa:** Falta el dominio nuevo en `network_security_config.xml`.
**Solucion:** Editar `alerta_link_flutter/android/app/src/main/res/xml/network_security_config.xml` y agregar el dominio:
```xml
<domain includeSubdomains="true"><DOMINIO></domain>
```

### El tunnel se conecta pero la URL responde 502 / 530

**Causa:** El backend no esta corriendo o esta en otro puerto.
**Solucion:** Verifica que `uvicorn` este escuchando en `localhost:8000` (mismo puerto que `url:` en `config.yml`).

### El subdominio no resuelve

**Causa:** El CNAME no se creo o el proxy esta apagado.
**Solucion:** Dashboard de Cloudflare -> DNS -> Records. Debe existir:
```
CNAME  <SUBDOMINIO>  <TUNNEL_ID>.cfargotunnel.com  Proxied
```

Si falta, vuelve a correr el paso 7.

---

## Checklist final

- [ ] Dominio agregado en Cloudflare
- [ ] Nameservers cambiados en registrador
- [ ] DNS propagado (`nslookup` muestra Cloudflare)
- [ ] `cloudflared` autenticado con cert.pem nuevo
- [ ] Tunnel creado en la cuenta correcta
- [ ] `config.yml` actualizado con nuevo tunnel ID
- [ ] CNAME del subdominio creado (`cloudflared tunnel route dns`)
- [ ] Codigo del proyecto actualizado (10 archivos)
- [ ] APK recompilada
- [ ] Backend corriendo en terminal 1
- [ ] Tunnel corriendo en terminal 2
- [ ] `curl /health` responde OK

---

## Datos del setup actual (2026-05-16)

| Dato | Valor |
|------|-------|
| Dominio | `mirrorhub.tech` |
| Registrador | get.tech (Namify) |
| Subdominio API | `alerta.mirrorhub.tech` |
| Cuenta Cloudflare | `Samuortiz1305@gmail.com` |
| Nameservers | `alec.ns.cloudflare.com`, `frida.ns.cloudflare.com` |
| Tunnel Name | `alerta-link` |
| Tunnel ID | `e1753651-584b-4d70-9769-20bcd2b3c5f2` |
| Credenciales | `C:\Users\samuel Ortiz\.cloudflared\e1753651-584b-4d70-9769-20bcd2b3c5f2.json` |
| Config | `C:\Users\samuel Ortiz\.cloudflared\config.yml` |

---

**Ultima actualizacion:** 2026-05-16
**Basada en:** Migracion real de `samuelortizospina.me` a `mirrorhub.tech`
