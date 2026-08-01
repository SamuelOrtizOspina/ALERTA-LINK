@echo off
title ALERTA-LINK - Detener
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts_windows\detener.ps1"
pause
