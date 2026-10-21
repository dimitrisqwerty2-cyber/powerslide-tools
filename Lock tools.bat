@echo off
rem Powerslide Tools: sets (or changes) the password of the protected tools, encrypts them and uploads the site.
cd /d "%~dp0"
python lock_tools.py
pause
