# Detiene todos los servicios de ALERTA-LINK.
$ErrorActionPreference = 'SilentlyContinue'

Write-Host ""
Write-Host "  ===============================================================" -ForegroundColor DarkGray
Write-Host "    ALERTA-LINK  -  detener servicios" -ForegroundColor White
Write-Host "  ===============================================================" -ForegroundColor DarkGray
Write-Host ""

# --- Tunel publico -------------------------------------------------
$cf = Get-Process -Name cloudflared -ErrorAction SilentlyContinue
if ($cf) {
    $cf | Stop-Process -Force
    Write-Host "    tunel publico    cerrado" -ForegroundColor Green
} else {
    Write-Host "    tunel publico    no estaba activo" -ForegroundColor DarkGray
}

# --- Aplicacion web y backend ---------------------------------------
foreach ($p in @(@{Puerto=8080; Nombre='aplicacion web'}, @{Puerto=8000; Nombre='backend       '})) {
    $con = Get-NetTCPConnection -LocalPort $p.Puerto -State Listen -ErrorAction SilentlyContinue
    if ($con) {
        $procId = ($con | Select-Object -First 1).OwningProcess
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 600
        Write-Host "    $($p.Nombre)   detenido" -ForegroundColor Green
    } else {
        Write-Host "    $($p.Nombre)   ya estaba libre" -ForegroundColor DarkGray
    }
}

# --- PostgreSQL ------------------------------------------------------
$pgctl = "C:\Program Files\PostgreSQL\17\bin\pg_ctl.exe"
$pgdata = "C:\Program Files\PostgreSQL\17\data"
$abierto = (Test-NetConnection 127.0.0.1 -Port 5432 -WarningAction SilentlyContinue).TcpTestSucceeded
if ($abierto -and (Test-Path $pgctl)) {
    & $pgctl -D $pgdata -m fast stop 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    $sigue = (Test-NetConnection 127.0.0.1 -Port 5432 -WarningAction SilentlyContinue).TcpTestSucceeded
    if ($sigue) {
        Get-Process -Name postgres -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2
        Write-Host "    base de datos    detenida" -ForegroundColor Green
    } else {
        Write-Host "    base de datos    detenida" -ForegroundColor Green
    }
} else {
    Write-Host "    base de datos    no estaba corriendo" -ForegroundColor DarkGray
}

# --- Comprobacion final ----------------------------------------------
Write-Host ""
$quedan = @()
foreach ($puerto in 5432, 8000, 8080) {
    if ((Test-NetConnection 127.0.0.1 -Port $puerto -WarningAction SilentlyContinue).TcpTestSucceeded) {
        $quedan += $puerto
    }
}
if ($quedan.Count -eq 0) {
    Write-Host "  Todo detenido." -ForegroundColor Green
} else {
    Write-Host "  Siguen ocupados los puertos: $($quedan -join ', ')" -ForegroundColor Yellow
}
Write-Host ""
