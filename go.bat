@echo off
REM Compilation script for UserAssistDecoder
REM WinToolsSuite Serie 3 - Forensics Tool #21

echo ========================================
echo Building UserAssistDecoder
echo ========================================

cl.exe /nologo /W4 /EHsc /O2 /DUNICODE /D_UNICODE ^
    /Fe:UserAssistDecoder.exe ^
    UserAssistDecoder.cpp ^
    /link ^
    comctl32.lib shlwapi.lib advapi32.lib user32.lib gdi32.lib shell32.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Build successful!
    echo Executable: UserAssistDecoder.exe
    echo ========================================
    if exist UserAssistDecoder.obj del UserAssistDecoder.obj
) else (
    echo.
    echo ========================================
    echo Build FAILED!
    echo ========================================
    exit /b 1
)
