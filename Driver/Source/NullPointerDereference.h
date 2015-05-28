/*++

 /$$   /$$                     /$$        /$$$$$$                     
| $$  | $$                    | $$       /$$__  $$                    
| $$  | $$  /$$$$$$   /$$$$$$$| $$   /$$| $$  \__/ /$$   /$$  /$$$$$$$
| $$$$$$$$ |____  $$ /$$_____/| $$  /$$/|  $$$$$$ | $$  | $$ /$$_____/
| $$__  $$  /$$$$$$$| $$      | $$$$$$/  \____  $$| $$  | $$|  $$$$$$ 
| $$  | $$ /$$__  $$| $$      | $$_  $$  /$$  \ $$| $$  | $$ \____  $$
| $$  | $$|  $$$$$$$|  $$$$$$$| $$ \  $$|  $$$$$$/|  $$$$$$$ /$$$$$$$/
|__/  |__/ \_______/ \_______/|__/  \__/ \______/  \____  $$|_______/ 
                                                   /$$  | $$          
                                                  |  $$$$$$/          
                                                   \______/           


Copyright (C) 2010-2015 HackSys Team. All rights reserved.

This file is part of HackSys Extreme Vulnerable Driver.

See the file 'LICENSE' for copying permission.

Author : Ashfaq Ansari
Contact: ashfaq_ansari1989[at]hotmail.com
Website: http://hacksys.vfreaks.com

Project Name:
    HackSys Extreme Vulnerable Driver

Module Name:
    NullPointerDereference.h

Abstract:
    This module implements the data structures for
    Null Pointer Dereference module.

--*/

#ifndef __NULL_POINTER_DEREFERENCE_H__
    #define __NULL_POINTER_DEREFERENCE_H__

    #pragma once

    #include "Common.h"

    typedef struct _NULL_POINTER_DEREFERENCE {
        ULONG value;
        FunctionPointer pCallback;
    } NULL_POINTER_DEREFERENCE, *PNULL_POINTER_DEREFERENCE;

    VOID        NullPointerDereferenceObjectCallback();
    NTSTATUS    TriggerNullPointerDereference(IN PVOID pUserModeBuffer); 

#endif  //__NULL_POINTER_DEREFERENCE_H__
