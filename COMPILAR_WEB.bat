@echo off
setlocal
chcp 65001 >nul
title ALERTA-LINK - Compilar la aplicacion web
cd /d "%~dp0"

echo.
echo  ===============================================================
echo    ALERTA-LINK  ·  compilar la aplicacion web
echo  ===============================================================
echo.
echo    Ejecute esto solo despues de modificar codigo de Flutter
echo    (la carpeta alerta_link_flutter\lib).
echo.
echo    Tarda unos dos minutos.
echo.

set "FLUTTER=C:\Users\SamuelOrtiz\flutter\bin\flutter.bat"

if not exist "%FLUTTER%" (
    echo    ERROR: no se encuentra Flutter en %FLUTTER%
    pause
    exit /b 1
)

cd /d "%~dp0alerta_link_flutter"

REM API_URL apunta al backend local. Para compilar una version que use
REM el dominio publico, cambie la URL por https://alerta.mirrorhub.tech
"%FLUTTER%" build web --release --dart-define=API_URL=http://127.0.0.1:8000

if errorlevel 1 (
    echo.
    echo    La compilacion fallo. Revise los mensajes de arriba.
    pause
    exit /b 1
)

echo.
echo  ---------------------------------------------------------------
echo    Compilacion terminada.
echo    Reinicie con INICIAR.bat y pulse Ctrl+Shift+R en el navegador
echo    para que el navegador no siga usando la version anterior.
echo  ---------------------------------------------------------------
echo.
pause
