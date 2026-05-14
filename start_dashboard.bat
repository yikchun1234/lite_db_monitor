@echo off
title Database Admin Portal Server
echo Starting the DBA Dashboard...

:: This line makes sure it runs in the exact folder where the bat file is located
cd /d "%~dp0"

:: Run the Python app
python app.py

pause
