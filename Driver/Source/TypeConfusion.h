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
    TypeConfusion.h

Abstract:
    This module implements the data structures for
    Type Confusion module.

--*/

#ifndef __TYPE_CONFUSION_H__
    #define __TYPE_CONFUSION_H__

    #pragma once

    #include "Common.h"

    typedef struct _TYPE_CONFUSION_USER_OBJECT {
        ULONG objectID;
        ULONG objectType;
    } TYPE_CONFUSION_USER_OBJECT, *PTYPE_CONFUSION_USER_OBJECT;

    typedef struct _TYPE_CONFUSION_KERNEL_OBJECT {
        ULONG objectID;
        union {
            ULONG objectType;
            FunctionPointer pCallback;
        };
    } TYPE_CONFUSION_KERNEL_OBJECT, *PTYPE_CONFUSION_KERNEL_OBJECT;

    VOID        TypeConfusionObjectCallback();
    NTSTATUS    TriggerTypeConfusion(IN PTYPE_CONFUSION_USER_OBJECT pTypeConfusionUserObject);
    NTSTATUS    TypeConfusionObjectInitializer(IN PTYPE_CONFUSION_KERNEL_OBJECT pTypeConfusionKernelObject);

#endif  //__TYPE_CONFUSION_H__
