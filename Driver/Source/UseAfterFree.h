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
    UseAfterFree.h

Abstract:
    This module implements the data structures for
    Use After Free module.

--*/

#ifndef __USE_AFTER_FREE_H__
    #define __USE_AFTER_FREE_H__

    #pragma once

    #include "Common.h"

    typedef struct _USE_AFTER_FREE {
        FunctionPointer pCallback;
        CHAR buffer[0x54];
    } USE_AFTER_FREE, *PUSE_AFTER_FREE;

    typedef struct _FAKE_OBJECT {
        CHAR buffer[0x58];
    } FAKE_OBJECT, *PFAKE_OBJECT;

    NTSTATUS    UseUaFObject();
    NTSTATUS    FreeUaFObject();
    NTSTATUS    CreateUaFObject();
    VOID        UaFObjectCallback();
    NTSTATUS    CreateFakeObject(IN PFAKE_OBJECT pFakeObject);

#endif  //__USE_AFTER_FREE_H__
