@echo off
title CBOM ^& PQC Lab para Banca
cd /d "%~dp0"
where py >nul 2>nul && (py -3 serve.py %*) || (python serve.py %*)
if errorlevel 1 (
  echo.
  echo No se encontro Python 3. Instalalo desde https://www.python.org/downloads/ y vuelve a ejecutar Iniciar.bat
  pause
)
