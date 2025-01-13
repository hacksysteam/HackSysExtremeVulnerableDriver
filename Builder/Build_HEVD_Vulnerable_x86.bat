@echo off
echo.
echo  #     #                       #####               #######                     
echo  #     #   ##    ####  #    # #     # #   #  ####     #    ######   ##   #    #
echo  #     #  #  #  #    # #   #  #        # #  #         #    #       #  #  ##  ##
echo  ####### #    # #      ####    #####    #    ####     #    #####  #    # # ## #
echo  #     # ###### #      #  #         #   #        #    #    #      ###### #    #
echo  #     # #    # #    # #   #  #     #   #   #    #    #    #      #    # #    #
echo  #     # #    #  ####  #    #  #####    #    ####     #    ###### #    # #    #
echo.
echo                  HackSys Extreme Vulnerable Driver Build Utility
echo.

rem Store the current directory path
set BUILD_ARCH=x86
set CURRENT_DIR=%cd%
set PROJECT_NAME=HEVD
set PROJECT_DIR=%CURRENT_DIR%\..\Driver\

rem Get the normalized path 
for %%i in ("%PROJECT_DIR%") do SET "PROJECT_DIR=%%~fi"

set BUILD_DIR=%PROJECT_DIR%..\build\driver\windows\vulnerable\%BUILD_ARCH%

rem VS2017U2 contains vswhere.exe
if "%VSWHERE%"=="" (
    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath`) do (
    set VS_INSTALL_DIR=%%i
)

echo [+] Visual Studio Path: %VS_INSTALL_DIR%

set VSDEVCMD_PATH=%VS_INSTALL_DIR%\Common7\Tools\VsDevCmd.bat

echo [+] Executing: %VSDEVCMD_PATH%

echo.
@call "%VSDEVCMD_PATH%" -arch=%BUILD_ARCH%
echo.

echo [+] Build target architecture: %BUILD_ARCH%
echo [+] Host Architecture: %PROCESSOR_ARCHITECTURE%
echo [+] Build directory: %BUILD_DIR%
echo [+] Removing build directory

if exist %BUILD_DIR% (
    rmdir /S /Q "%BUILD_DIR%"
)

echo [+] Creating build directory

mkdir "%BUILD_DIR%"
cd %BUILD_DIR%

echo [+] Generating build configuration files

cmake.exe -G "Ninja" -DCMAKE_INSTALL_PREFIX:PATH="%BUILD_DIR%" -DCMAKE_BUILD_TYPE="Release" "%PROJECT_DIR%"

echo.
echo [+] Building vulnerable HackSys Extreme Vulnerable Driver
echo.

CMake.exe --build "%BUILD_DIR%" --config Release --clean-first -- "-v"
echo.

echo [+] Copying built files

echo [*] %PROJECT_NAME%.sys
move /Y "%BUILD_DIR%\%PROJECT_NAME%\Windows\%PROJECT_NAME%.sys" "%BUILD_DIR%"

echo [*] %PROJECT_NAME%.pdb
move /Y "%BUILD_DIR%\%PROJECT_NAME%\Windows\%PROJECT_NAME%.pdb" "%BUILD_DIR%"

echo [*] %PROJECT_NAME%.cat
move /Y "%BUILD_DIR%\%PROJECT_NAME%\Windows\%PROJECT_NAME%.cat" "%BUILD_DIR%"

echo [*] %PROJECT_NAME%.inf
move /Y "%BUILD_DIR%\%PROJECT_NAME%\Windows\%PROJECT_NAME%.inf" "%BUILD_DIR%"
echo.


echo [+] Cleaning build directory
for /r "%BUILD_DIR%" %%a in (*) do (
    if not %%~xa==.sys (
        if not %%~xa==.pdb (
            if not %%~xa==.inf (
                if not %%~xa==.cat (
                    del /f /q "%%a"
                )
            )
        )
    )
)

rmdir /S /Q "%BUILD_DIR%\%PROJECT_NAME%"
rmdir /S /Q "%BUILD_DIR%\CMakeFiles"
echo.

echo [+] Built vulnerable HackSys Extreme Vulnerable Driver successfully
cd %CURRENT_DIR%
echo.
