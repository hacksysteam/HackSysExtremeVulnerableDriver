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
    HackSysExtremeVulnerableDriver.c

Abstract:
    This module implements the main kernel driver
    of HackSys Extreme Vulnerable Driver.

--*/

#include "HackSysExtremeVulnerableDriver.h"

#ifdef ALLOC_PRAGMA
    #pragma alloc_text (INIT, DriverEntry)
    #pragma alloc_text (PAGE, IrpCloseHandler)
    #pragma alloc_text (PAGE, IrpUnloadHandler)
    #pragma alloc_text (PAGE, IrpCreateHandler)
    #pragma alloc_text (PAGE, IrpDeviceIoCtlHandler)
    #pragma alloc_text (PAGE, IrpNotImplementedHandler)
#endif // ALLOC_PRAGMA

/// <summary>
/// Driver Entry Point
/// </summary>
/// <param name="pDriverObject">The pointer to DRIVER_OBJECT</param>
/// <param name="pRegistryPath">The pointer registry path</param>
/// <returns>NTSTATUS</returns>
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath) {
    UNICODE_STRING DeviceName, Win32Device;
    PDEVICE_OBJECT pDeviceObject = NULL;
    NTSTATUS status;
    UINT32 i = 0;

    UNREFERENCED_PARAMETER(pRegistryPath);
    PAGED_CODE();

    RtlInitUnicodeString(&DeviceName, L"\\Device\\HackSysExtremeVulnerableDriver");
    RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\HackSysExtremeVulnerableDriver");

    // Create the device
    status = IoCreateDevice(pDriverObject,
                            0,
                            &DeviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &pDeviceObject);

    if (status != STATUS_SUCCESS) {
        // Delete the device
        IoDeleteDevice(pDriverObject->DeviceObject);

        DbgPrint("[-] Error Initializing HackSys Extreme Vulnerable Driver\n");
        return status;
    }

    // Assign the IRP handlers
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        // Disable the Compiler Warning: 28169
        #pragma warning(push)
        #pragma warning(disable : 28169)
        pDriverObject->MajorFunction[i] = IrpNotImplementedHandler;
        #pragma warning(pop)
    }

    // Assign the IRP handlers for Create, Close and Device Control
    pDriverObject->MajorFunction[IRP_MJ_CREATE]         = IrpCreateHandler;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE]          = IrpCloseHandler;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;

    // Assign the driver Unload routine
    pDriverObject->DriverUnload = IrpUnloadHandler;

    // Set the flags
    pDeviceObject->Flags |= DO_DIRECT_IO;
    pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    // Create the symbolic link
    status = IoCreateSymbolicLink(&Win32Device, &DeviceName);

    // Show the banner
    DbgPrint("%s", BANNER);
    DbgPrint("[+] HackSys Extreme Vulnerable Driver Loaded\n");

    return status;
}

/// <summary>
/// IRP Create Handler
/// </summary>
/// <param name="pDeviceObject">The pointer to DEVICE_OBJECT</param>
/// <param name="pIrp">The pointer to IRP</param>
/// <returns>NTSTATUS</returns>
NTSTATUS IrpCreateHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;

    UNREFERENCED_PARAMETER(pDeviceObject);
    PAGED_CODE();

    // Complete the request
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/// <summary>
/// IRP Close Handler
/// </summary>
/// <param name="pDeviceObject">The pointer to DEVICE_OBJECT</param>
/// <param name="pIrp">The pointer to IRP</param>
/// <returns>NTSTATUS</returns>
NTSTATUS IrpCloseHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;

    UNREFERENCED_PARAMETER(pDeviceObject);
    PAGED_CODE();

    // Complete the request
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/// <summary>
/// IRP Unload Handler
/// </summary>
/// <param name="pDeviceObject">The pointer to DEVICE_OBJECT</param>
/// <param name="pIrp">The pointer to IRP</param>
/// <returns>NTSTATUS</returns>
VOID IrpUnloadHandler(IN PDRIVER_OBJECT pDriverObject) {
    UNICODE_STRING Win32Device;

    PAGED_CODE();

    RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\HackSysExtremeVulnerableDriver");

    // Delete the symbolic link
    IoDeleteSymbolicLink(&Win32Device);

    // Delete the device
    IoDeleteDevice(pDriverObject->DeviceObject);

    DbgPrint("[-] HackSys Extreme Vulnerable Driver Unloaded\n");
}

/// <summary>
/// IRP Not Implemented Handler
/// </summary>
/// <param name="pDeviceObject">The pointer to DEVICE_OBJECT</param>
/// <param name="pIrp">The pointer to IRP</param>
/// <returns>NTSTATUS</returns>
NTSTATUS IrpNotImplementedHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {
    pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    pIrp->IoStatus.Information = 0;

    UNREFERENCED_PARAMETER(pDeviceObject);
    PAGED_CODE();

    // Complete the request
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_NOT_SUPPORTED;
}

/// <summary>
/// IRP Device IoCtl Handler
/// </summary>
/// <param name="pDeviceObject">The pointer to DEVICE_OBJECT</param>
/// <param name="pIrp">The pointer to IRP</param>
/// <returns>NTSTATUS</returns>
NTSTATUS IrpDeviceIoCtlHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    PIO_STACK_LOCATION pIoStackIRP = NULL;
    ULONG ioControlCode = 0;

    UNREFERENCED_PARAMETER(pDeviceObject);
    PAGED_CODE();

    pIoStackIRP = IoGetCurrentIrpStackLocation(pIrp);
    ioControlCode = pIoStackIRP->Parameters.DeviceIoControl.IoControlCode;

    if (pIoStackIRP) {
        switch (ioControlCode) {
            case HACKSYS_EVD_IOCTL_STACK_OVERFLOW:
                DbgPrint("****** HACKSYS_EVD_STACKOVERFLOW ******\n");
                status = StackOverflowIoctlHandler(pIrp, pIoStackIRP);
                DbgPrint("****** HACKSYS_EVD_STACKOVERFLOW ******\n");
                break;
            case HACKSYS_EVD_IOCTL_STACK_OVERFLOW_GS:
                DbgPrint("****** HACKSYS_EVD_IOCTL_STACK_OVERFLOW_GS ******\n");
                status = StackOverflowGSIoctlHandler(pIrp, pIoStackIRP);
                DbgPrint("****** HACKSYS_EVD_IOCTL_STACK_OVERFLOW_GS ******\n");
                break;
            case HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE:
                DbgPrint("****** HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE ******\n");
                status = ArbitraryOverwriteIoctlHandler(pIrp, pIoStackIRP);
                DbgPrint("****** HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE ******\n");
                break;
            case HACKSYS_EVD_IOCTL_POOL_OVERFLOW:
                DbgPrint("****** HACKSYS_EVD_IOCTL_POOL_OVERFLOW ******\n");
                status = PoolOverflowIoctlHandler(pIrp, pIoStackIRP);
                DbgPrint("****** HACKSYS_EVD_IOCTL_POOL_OVERFLOW ******\n");
                break;
            case HACKSYS_EVD_IOCTL_CREATE_UAF_OBJECT:
                DbgPrint("****** HACKSYS_EVD_IOCTL_CREATE_UAF_OBJECT ******\n");
                status = CreateUaFObjectIoctlHandler(pIrp, pIoStackIRP);
                DbgPrint("****** HACKSYS_EVD_IOCTL_CREATE_UAF_OBJECT ******\n");
                break;
            case HACKSYS_EVD_IOCTL_USE_UAF_OBJECT:
                DbgPrint("****** HACKSYS_EVD_IOCTL_USE_UAF_OBJECT ******\n");
                status = UseUaFObjectIoctlHandler(pIrp, pIoStackIRP);
                DbgPrint("****** HACKSYS_EVD_IOCTL_USE_UAF_OBJECT ******\n");
                break;
            case HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT:
                DbgPrint("****** HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT ******\n");
                status = FreeUaFObjectIoctlHandler(pIrp, pIoStackIRP);
                DbgPrint("****** HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT ******\n");
                break;
            case HACKSYS_EVD_IOCTL_CREATE_FAKE_OBJECT:
                DbgPrint("****** HACKSYS_EVD_IOCTL_CREATE_FAKE_OBJECT ******\n");
                status = CreateFakeObjectIoctlHandler(pIrp, pIoStackIRP);
                DbgPrint("****** HACKSYS_EVD_IOCTL_CREATE_FAKE_OBJECT ******\n");
                break;
            case HACKSYS_EVD_IOCTL_TYPE_CONFUSION:
                DbgPrint("****** HACKSYS_EVD_IOCTL_TYPE_CONFUSION ******\n");
                status = TypeConfusionIoctlHandler(pIrp, pIoStackIRP);
                DbgPrint("****** HACKSYS_EVD_IOCTL_TYPE_CONFUSION ******\n");
                break;
            case HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW:
                DbgPrint("****** HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW ******\n");
                status = IntegerOverflowIoctlHandler(pIrp, pIoStackIRP);
                DbgPrint("****** HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW ******\n");
                break;
            case HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE:
                DbgPrint("****** HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE ******\n");
                status = NullPointerDereferenceIoctlHandler(pIrp, pIoStackIRP);
                DbgPrint("****** HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE ******\n");
                break;
            default:
                DbgPrint("[-] Invalid IOCTL Code: 0x%X\n", ioControlCode);
                status = STATUS_INVALID_DEVICE_REQUEST;
                break;
        }
    }

    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = 0;

    // Complete the request
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}
