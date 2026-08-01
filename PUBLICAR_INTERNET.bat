@echo off
setlocal
chcp 65001 >nul
title ALERTA-LINK - Publicar en internet
cd /d "%~dp0"

echo.
echo  ===============================================================
echo    ALERTA-LINK  ·  tunel publico
echo  ===============================================================
echo.
echo    Publica el backend local en:
echo        https://alerta.mirrorhub.tech
echo.
echo    ATENCION: mientras esta ventana siga abierta, su equipo queda
echo    accesible desde internet. Cierrela al terminar.
echo.

set "CF=C:\Program Files (x86)\cloudflared\cloudflared.exe"

if not exist "%CF%" (
    echo    ERROR: cloudflared no esta instalado.
    echo    Instalelo con:  winget install Cloudflare.cloudflared
    pause
    exit /b 1
)

REM El tunel no sirve de nada si el backend no esta arriba
powershell -NoProfile -Command "if ((Test-NetConnection 127.0.0.1 -Port 8000 -WarningAction SilentlyContinue).TcpTestSucceeded) { exit 0 } else { exit 1 }" >nul 2>&1
if errorlevel 1 (
    echo    El backend no esta corriendo. Ejecute INICIAR.bat primero.
    echo.
    pause
    exit /b 1
)

echo    Backend detectado. Abriendo el tunel...
echo    Pulse Ctrl+C para cerrarlo.
echo.

"%CF%" tunnel run alertalink
