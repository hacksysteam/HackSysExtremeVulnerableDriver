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

REM store the current directory path
set currentDir=%cd%

REM store the local symbol server path
set localSymbolServerPath=C:\Xtra\Symbols\Custom\

REM set the environment variable
echo.
echo.
echo ******************************************
@call %WDKPATH%\bin\setenv.bat %WDKPATH%\ fre x86 WIN7
echo ******************************************

cd %currentDir%

echo.
echo ******************************************
echo Building HackSys Extreme Vulnerable Driver
echo                Vulnerable
echo ******************************************
echo.
rmdir /S /Q drv
build /cCzg
echo ******************************************
echo.
echo ******************************************
echo Cleaning The Build Directory
echo ******************************************
echo.
echo Deleting obj%BUILD_ALT_DIR% folder
rmdir /S /Q obj%BUILD_ALT_DIR%

if exist build%BUILD_ALT_DIR%.log (
	echo Deleting build%BUILD_ALT_DIR%.log
	del /F build%BUILD_ALT_DIR%.log
)
if exist build%BUILD_ALT_DIR%.wrn (
	echo Deleting build%BUILD_ALT_DIR%.wrn
	del /F build%BUILD_ALT_DIR%.wrn
)
if exist build%BUILD_ALT_DIR%.err (
	echo Deleting build%BUILD_ALT_DIR%.err
	del /F build%BUILD_ALT_DIR%.err
)
echo ******************************************

echo.
echo ******************************************
echo Transferring Driver Symbols to Symbol Store
echo ******************************************
cd "C:\Program Files\Debugging Tools for Windows (x86)"
echo.
symstore.exe add /r /f %currentDir%\drv\i386\ /s %localSymbolServerPath% /t "DriverSymbols" /v "1.0"
echo ******************************************
echo.
echo ******************************************
echo HackSys Extreme Vulnerable Driver Built
echo              Successfully
echo ******************************************
echo.
cd %currentDir%
pause