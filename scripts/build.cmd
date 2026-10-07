@echo off
setlocal
cd /d "%~dp0.."
if not exist build mkdir build
"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:exe /out:build\LayaLauncher.exe .\scripts\AppContainerLauncher.cs
exit /b %errorlevel%
