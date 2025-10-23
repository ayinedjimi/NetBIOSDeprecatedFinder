@echo off
REM Script de compilation pour NetBIOSDeprecatedFinder
REM Auteur: Ayi NEDJIMI

echo ========================================
echo Compilation de NetBIOSDeprecatedFinder
echo ========================================

REM Verifier la presence de cl.exe
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERREUR: cl.exe non trouve. Veuillez executer ce script depuis un "Developer Command Prompt for VS"
    pause
    exit /b 1
)

REM Compiler
echo Compilation en cours...
cl.exe /EHsc /W4 /O2 /D UNICODE /D _UNICODE ^
    NetBIOSDeprecatedFinder.cpp ^
    /link ^
    comctl32.lib ws2_32.lib iphlpapi.lib netapi32.lib user32.lib gdi32.lib ^
    /OUT:NetBIOSDeprecatedFinder.exe

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Compilation reussie!
    echo Executable: NetBIOSDeprecatedFinder.exe
    echo ========================================

    REM Nettoyer les fichiers intermediaires
    if exist NetBIOSDeprecatedFinder.obj del NetBIOSDeprecatedFinder.obj

    echo.
    echo Lancement de l'application...
    start NetBIOSDeprecatedFinder.exe
) else (
    echo.
    echo ========================================
    echo ERREUR: La compilation a echoue
    echo ========================================
    pause
    exit /b 1
)
