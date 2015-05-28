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
    HackSys.h

Abstract:
    This module implements the data structures for main
    driver module.

--*/

#ifndef __HACKSYS_H__
    #define __HACKSYS_H__

    #pragma once

    #include "Common.h"

    #define HACKSYS_EVD_IOCTL_STACK_OVERFLOW              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_STACK_OVERFLOW_GS           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_POOL_OVERFLOW               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_CREATE_UAF_OBJECT           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_USE_UAF_OBJECT              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_CREATE_FAKE_OBJECT          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_TYPE_CONFUSION              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

    #define BANNER \
        ("#     #   ##    ####  #    #  ####  #   #  #### ##### ######   ##   #    #\n" \
         "#     #  #  #  #    # #   #  #       # #  #       #   #       #  #  ##  ##\n" \
         "####### #    # #      ####    #####   #    ####   #   #####  #    # # ## #\n" \
         "#     # ###### #    # #   #        #  #        #  #   #      ###### #    #\n" \
         "#     # #    #  ####  #    #  ####    #    ####   #   ###### #    # #    #\n" \
         "                    HackSys Extreme Vulnerable Driver                     \n")

    DRIVER_INITIALIZE    DriverEntry;
    DRIVER_UNLOAD        IrpUnloadHandler;
    DRIVER_DISPATCH      IrpNotImplementedHandler;

    __drv_dispatchType(IRP_MJ_CREATE)            DRIVER_DISPATCH    IrpCreateHandler;
    __drv_dispatchType(IRP_MJ_CLOSE)             DRIVER_DISPATCH    IrpCloseHandler;
    __drv_dispatchType(IRP_MJ_DEVICE_CONTROL)    DRIVER_DISPATCH    IrpDeviceIoCtlHandler;

    VOID        IrpUnloadHandler(IN PDRIVER_OBJECT pDriverObject);
    NTSTATUS    IrpCloseHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
    NTSTATUS    IrpCreateHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
    NTSTATUS    IrpDeviceIoCtlHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
    NTSTATUS    IrpNotImplementedHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
    NTSTATUS    DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath);

#endif  //__HACKSYS_H__
