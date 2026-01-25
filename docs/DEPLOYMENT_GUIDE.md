# ALERTA-LINK - Guia de Despliegue

**Fecha:** 2026-01-09
**Dominio:** samuelortizospina.me

---

## Tabla de Contenido

1. [Opcion A: Prueba Local (Rapido)](#opcion-a-prueba-local-rapido)
2. [Opcion B: Despliegue en Servidor](#opcion-b-despliegue-en-servidor)
3. [Configurar Dominio](#configurar-dominio)
4. [Compilar APK para Dispositivo](#compilar-apk-para-dispositivo)
5. [Instalar en Dispositivo Movil](#instalar-en-dispositivo-movil)

---

## Opcion A: Prueba Local (Rapido)

### Ideal para probar en tu celular conectado a la misma red WiFi.

### Paso 1: Iniciar Backend en tu PC

```bash
# 1. Ir al directorio del proyecto
cd "C:\Users\samuel Ortiz\Documents\proyecto de tesis\desarrollo"

# 2. Activar entorno virtual
python -m venv venv
venv\Scripts\activate

# 3. Instalar dependencias
pip install -r backend/requirements.txt

# 4. Configurar .env (copiar de .env.example)
copy .env.example .env
# Editar .env con tus API keys

# 5. Iniciar servidor (escuchar en todas las IPs)
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Paso 2: Obtener IP de tu PC

```bash
# Windows
ipconfig
# Buscar "IPv4 Address" (ejemplo: 192.168.1.100)
```

### Paso 3: Compilar APK con tu IP

```bash
# En otra terminal
cd "C:\Users\samuel Ortiz\Documents\proyecto de tesis\desarrollo\alerta_link_flutter"

# Compilar APK de debug con tu IP
flutter build apk --debug --dart-define=API_URL=http://192.168.1.100:8000
```

### Paso 4: Instalar en Celular

```bash
# Conectar celular por USB y habilitar "Depuracion USB"
flutter install
```

### Paso 5: Probar

1. Abrir la app ALERTA-LINK en tu celular
2. Escribir una URL (ej: "google.com")
3. Ver el resultado del analisis

---

## Opcion B: Despliegue en Servidor

### Para produccion con tu dominio samuelortizospina.me

### Requisitos del Servidor

- VPS con Ubuntu 22.04+ (DigitalOcean, AWS, etc.)
- Minimo 1GB RAM, 1 CPU
- Python 3.11+
- Nginx
- Certbot (SSL)

### Paso 1: Preparar Servidor

```bash
# Conectar al servidor
ssh usuario@tu-servidor

# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar dependencias
sudo apt install python3.11 python3.11-venv python3-pip nginx certbot python3-certbot-nginx git -y
```

### Paso 2: Clonar Proyecto

```bash
# Crear directorio
sudo mkdir -p /var/www/alertalink
sudo chown $USER:$USER /var/www/alertalink

# Clonar (o subir archivos)
cd /var/www/alertalink
# git clone <tu-repo> .
# O subir con scp/sftp
```

### Paso 3: Configurar Backend

```bash
cd /var/www/alertalink

# Crear entorno virtual
python3.11 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r backend/requirements.txt

# Crear .env
cp .env.example .env
nano .env
```

**Contenido de .env para produccion:**
```bash
APP_NAME=ALERTA-LINK
APP_VERSION=0.1.0
DEBUG=false

# Generar con: python -c "import secrets; print(secrets.token_urlsafe(32))"
SECRET_KEY=TU_CLAVE_SEGURA_GENERADA_AQUI

# API Keys (las tuyas)
TRANCO_API_KEY=tu-api-key
TRANCO_API_EMAIL=tu-email
VIRUSTOTAL_API_KEY=tu-api-key

# CORS
CORS_ORIGINS=https://samuelortizospina.me,https://api.samuelortizospina.me
```

### Paso 4: Crear Servicio Systemd

```bash
sudo nano /etc/systemd/system/alertalink.service
```

**Contenido:**
```ini
[Unit]
Description=ALERTA-LINK Backend API
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/alertalink/backend
Environment="PATH=/var/www/alertalink/venv/bin"
ExecStart=/var/www/alertalink/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Habilitar e iniciar
sudo systemctl daemon-reload
sudo systemctl enable alertalink
sudo systemctl start alertalink
sudo systemctl status alertalink
```

### Paso 5: Configurar Nginx

```bash
sudo nano /etc/nginx/sites-available/alertalink
```

**Contenido:**
```nginx
server {
    listen 80;
    server_name api.samuelortizospina.me;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
# Habilitar sitio
sudo ln -s /etc/nginx/sites-available/alertalink /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Paso 6: Configurar SSL (HTTPS)

```bash
# Obtener certificado SSL gratuito con Let's Encrypt
sudo certbot --nginx -d api.samuelortizospina.me
```

---

## Configurar Dominio

### En tu proveedor de DNS (donde compraste samuelortizospina.me):

1. Crear registro **A**:
   - Nombre: `api`
   - Valor: `IP_DE_TU_SERVIDOR`
   - TTL: 3600

2. Esperar propagacion DNS (5-30 minutos)

3. Verificar:
```bash
nslookup api.samuelortizospina.me
# Debe mostrar la IP de tu servidor
```

---

## Compilar APK para Dispositivo

### APK de Produccion (HTTPS)

```bash
cd "C:\Users\samuel Ortiz\Documents\proyecto de tesis\desarrollo\alerta_link_flutter"

# Limpiar builds anteriores
flutter clean

# Compilar APK release
flutter build apk --release

# El APK estara en:
# build/app/outputs/flutter-apk/app-release.apk
```

### APK de Debug (para pruebas locales)

```bash
# Con IP de tu PC
flutter build apk --debug --dart-define=API_URL=http://192.168.1.100:8000
```

---

## Instalar en Dispositivo Movil

### Opcion 1: Cable USB

```bash
# Conectar celular con USB
# Habilitar "Depuracion USB" en el celular
adb install build/app/outputs/flutter-apk/app-release.apk
```

### Opcion 2: Transferir APK

1. Copiar el archivo `app-release.apk` a tu celular (USB, email, Drive, etc.)
2. En el celular, ir a **Configuracion > Seguridad > Instalar apps desconocidas**
3. Permitir la instalacion desde el explorador de archivos
4. Abrir el APK y tocar "Instalar"

### Opcion 3: QR Code / Link

1. Subir el APK a un servidor o Drive
2. Generar link de descarga
3. Escanear QR o abrir link en el celular

---

## Verificar Instalacion

### 1. Verificar Backend

```bash
# Desde cualquier navegador
curl https://api.samuelortizospina.me/health
# Debe retornar: {"status": "ok", ...}
```

### 2. Verificar App

1. Abrir ALERTA-LINK en el celular
2. Escribir: `google.com`
3. Tocar "Analizar"
4. Debe mostrar semaforo VERDE (sitio seguro)

5. Escribir: `secure-paypal-verify.xyz`
6. Debe mostrar semaforo ROJO (phishing detectado)

---

## Troubleshooting

### Error: "No se puede conectar al servidor"

**Causa:** La app no puede alcanzar el backend

**Solucion:**
1. Verificar que el servidor esta corriendo: `curl http://localhost:8000/health`
2. Verificar firewall: `sudo ufw allow 8000`
3. Verificar que la IP/dominio es correcto en la app

### Error: "Certificado SSL invalido"

**Causa:** HTTPS no configurado correctamente

**Solucion:**
```bash
sudo certbot renew --dry-run
sudo systemctl restart nginx
```

### Error: "Rate limit exceeded"

**Causa:** Demasiadas peticiones (>30/min)

**Solucion:** Esperar 1 minuto o aumentar limite en `analyze.py`

---

## Checklist de Produccion

- [ ] SECRET_KEY generada y configurada
- [ ] API keys de Tranco y VirusTotal configuradas
- [ ] SSL/HTTPS funcionando
- [ ] Firewall configurado (solo puertos 80, 443, 22)
- [ ] Logs habilitados
- [ ] Backups configurados
- [ ] Dominio apuntando al servidor
- [ ] APK compilado con URL de produccion

---

## Comandos Utiles

```bash
# Ver logs del backend
sudo journalctl -u alertalink -f

# Reiniciar backend
sudo systemctl restart alertalink

# Ver estado de nginx
sudo systemctl status nginx

# Renovar certificado SSL
sudo certbot renew
```

---

**Universidad Manuela Beltran - Ingenieria de Software 2025**
