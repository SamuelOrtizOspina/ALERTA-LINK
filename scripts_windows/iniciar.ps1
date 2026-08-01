# Arranca los tres servicios de ALERTA-LINK en el orden correcto.
$ErrorActionPreference = 'SilentlyContinue'

$raiz   = Split-Path -Parent $PSScriptRoot
$py     = Join-Path $raiz 'backend\.venv\Scripts\python.exe'
$web    = Join-Path $raiz 'alerta_link_flutter\build\web'
$pgctl  = "C:\Program Files\PostgreSQL\17\bin\pg_ctl.exe"
$pgdata = "C:\Program Files\PostgreSQL\17\data"

function Puerto-Abierto($n) {
    (Test-NetConnection 127.0.0.1 -Port $n -WarningAction SilentlyContinue).TcpTestSucceeded
}

function Esperar-Puerto($n, $segundos) {
    for ($i = 0; $i -lt $segundos; $i++) {
        if (Puerto-Abierto $n) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

Write-Host ""
Write-Host "  ===============================================================" -ForegroundColor DarkGray
Write-Host "    ALERTA-LINK  -  arranque completo" -ForegroundColor White
Write-Host "  ===============================================================" -ForegroundColor DarkGray
Write-Host ""

# --- 1. Base de datos -------------------------------------------------
Write-Host "  [1/3] PostgreSQL..." -NoNewline
if (Puerto-Abierto 5432) {
    Write-Host "  ya estaba corriendo" -ForegroundColor DarkGray
} elseif (Test-Path $pgctl) {
    Start-Process -FilePath $pgctl -ArgumentList "-D", "`"$pgdata`"", "-w", "start" -WindowStyle Hidden
    if (Esperar-Puerto 5432 25) {
        Write-Host "  iniciada" -ForegroundColor Green
    } else {
        Write-Host "  no arranco; se usaran archivos JSONL" -ForegroundColor Yellow
    }
} else {
    Write-Host "  no instalada; se usaran archivos JSONL" -ForegroundColor Yellow
}

# --- 2. Backend --------------------------------------------------------
Write-Host "  [2/3] Backend..." -NoNewline
if (Puerto-Abierto 8000) {
    Write-Host "      ya estaba corriendo" -ForegroundColor DarkGray
} else {
    if (-not (Test-Path $py)) {
        Write-Host "      ERROR" -ForegroundColor Red
        Write-Host ""
        Write-Host "  No se encuentra el entorno virtual:" -ForegroundColor Red
        Write-Host "    $py"
        Write-Host "  Creelo e instale backend\requirements.txt"
        Write-Host ""
        return
    }
    Start-Process -FilePath $py `
        -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000" `
        -WorkingDirectory (Join-Path $raiz 'backend') -WindowStyle Hidden
    if (Esperar-Puerto 8000 30) {
        Write-Host "      iniciado" -ForegroundColor Green
    } else {
        Write-Host "      no respondio a tiempo" -ForegroundColor Yellow
    }
}

# --- 3. Aplicacion web --------------------------------------------------
Write-Host "  [3/3] Aplicacion web..." -NoNewline
if (-not (Test-Path (Join-Path $web 'index.html'))) {
    Write-Host " ERROR" -ForegroundColor Red
    Write-Host ""
    Write-Host "  No hay compilacion web. Ejecute COMPILAR_WEB.bat primero." -ForegroundColor Red
    Write-Host ""
    return
}
if (Puerto-Abierto 8080) {
    Write-Host " ya estaba corriendo" -ForegroundColor DarkGray
} else {
    Start-Process -FilePath $py `
        -ArgumentList "-m", "http.server", "8080", "--bind", "127.0.0.1" `
        -WorkingDirectory $web -WindowStyle Hidden
    if (Esperar-Puerto 8080 15) {
        Write-Host " sirviendo" -ForegroundColor Green
    } else {
        Write-Host " no respondio" -ForegroundColor Yellow
    }
}

# --- Estado -------------------------------------------------------------
Write-Host ""
Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
try {
    $r = Invoke-RestMethod 'http://127.0.0.1:8000/health' -TimeoutSec 12
    $bd = if ($r.database.available) { 'PostgreSQL' } else { 'archivos JSONL' }
    Write-Host "    modelo ML       " -NoNewline; Write-Host $(if ($r.model_loaded) { 'cargado' } else { 'NO cargado' }) -ForegroundColor $(if ($r.model_loaded) { 'Green' } else { 'Yellow' })
    Write-Host "    base de datos   " -NoNewline; Write-Host $bd -ForegroundColor $(if ($r.database.available) { 'Green' } else { 'Yellow' })
    Write-Host "    Tranco          " -NoNewline; Write-Host $(if ($r.apis.tranco) { 'activo' } else { 'sin clave' }) -ForegroundColor $(if ($r.apis.tranco) { 'Green' } else { 'DarkGray' })
    Write-Host "    VirusTotal      " -NoNewline; Write-Host $(if ($r.apis.virustotal) { 'activo' } else { 'sin clave' }) -ForegroundColor $(if ($r.apis.virustotal) { 'Green' } else { 'DarkGray' })
} catch {
    Write-Host "    El backend no responde todavia." -ForegroundColor Yellow
}
Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host "    Abra:  " -NoNewline; Write-Host "http://localhost:8080" -ForegroundColor Cyan
Write-Host "    La primera vez pulse Ctrl+Shift+R en el navegador."
Write-Host ""
Write-Host "    Para detener todo:      DETENER.bat"
Write-Host "    Para publicarlo online: PUBLICAR_INTERNET.bat"
Write-Host ""

Start-Process "http://localhost:8080"
