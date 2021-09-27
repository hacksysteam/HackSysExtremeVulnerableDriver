@echo off

%COMSPEC% /c Build_HEVD_Secure_x64.bat
%COMSPEC% /c Build_HEVD_Secure_x86.bat
%COMSPEC% /c Build_HEVD_Secure_arm64.bat
%COMSPEC% /c Build_HEVD_Vulnerable_x64.bat
%COMSPEC% /c Build_HEVD_Vulnerable_x86.bat
%COMSPEC% /c Build_HEVD_Vulnerable_arm64.bat
