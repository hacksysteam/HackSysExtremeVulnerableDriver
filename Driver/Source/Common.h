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
    Common.h

Abstract:
    This module implements the data structures which
    are common to the driver modules.

--*/

#ifndef __COMMON_H__
    #define __COMMON_H__

    #pragma once

    #include <ntddk.h>

    #define POOL_TAG 'kcaH'
    #define BUFFER_SIZE 512

    #define _STRINGIFY(value) #value
    #define STRINGIFY(value) _STRINGIFY(value)

    typedef void (*FunctionPointer)();

    NTSTATUS    StackOverflowIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp);
    NTSTATUS    StackOverflowGSIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp);
    NTSTATUS    ArbitraryOverwriteIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp);
    NTSTATUS    PoolOverflowIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp);
    NTSTATUS    CreateUaFObjectIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp);
    NTSTATUS    UseUaFObjectIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp);
    NTSTATUS    FreeUaFObjectIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp);
    NTSTATUS    CreateFakeObjectIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp);
    NTSTATUS    TypeConfusionIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp);
    NTSTATUS    IntegerOverflowIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp);
    NTSTATUS    NullPointerDereferenceIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp);

#endif //__COMMON_H__
