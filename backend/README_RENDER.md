# Deploy en Render - ALERTA-LINK Backend

## Pasos para deploy en Render

### 1. Subir codigo a GitHub

```bash
cd backend
git init
git add .
git commit -m "Backend ALERTA-LINK para Render"
git remote add origin https://github.com/TU_USUARIO/alerta-link-backend.git
git push -u origin main
```

### 2. Crear cuenta en Render
- Ir a https://render.com
- Registrarse con GitHub

### 3. Crear nuevo Web Service
1. Click en "New" > "Web Service"
2. Conectar con tu repositorio de GitHub
3. Configurar:
   - **Name**: alerta-link-api
   - **Region**: Oregon (US West)
   - **Branch**: main
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Plan**: Free

### 4. Configurar Variables de Entorno
En la seccion "Environment", agregar:

| Variable | Valor |
|----------|-------|
| `VIRUSTOTAL_API_KEY` | Tu API key de VirusTotal |
| `PYTHON_VERSION` | 3.11 |

### 5. Deploy
Click en "Create Web Service" y esperar a que se complete el deploy.

### 6. Obtener URL
Una vez completado, Render te dara una URL como:
```
https://alerta-link-api.onrender.com
```

### 7. Probar
```bash
curl https://alerta-link-api.onrender.com/health
```

## Configurar la App Movil

En la app Flutter, cambiar la URL base a tu URL de Render:

```dart
// lib/services/api_service.dart
static const String baseUrl = 'https://alerta-link-api.onrender.com';
```

## Notas importantes

- **Plan gratuito**: El servidor se "duerme" despues de 15 minutos de inactividad. La primera request despues de dormir toma ~30 segundos.
- **Limitaciones**: 750 horas/mes de ejecucion en plan gratuito.
- **Modelo incluido**: El modelo ML esta incluido en `models/step1_baseline.pkl`.

## Estructura de archivos necesarios

```
backend/
├── app/
│   ├── main.py
│   ├── api/
│   ├── core/
│   ├── services/
│   └── ...
├── models/
│   └── step1_baseline.pkl  <-- Modelo ML
├── requirements.txt
├── Procfile
├── render.yaml
└── runtime.txt
```
