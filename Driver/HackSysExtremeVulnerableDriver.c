/*++

          ##     ## ######## ##     ## ########  
          ##     ## ##       ##     ## ##     ## 
          ##     ## ##       ##     ## ##     ## 
          ######### ######   ##     ## ##     ## 
          ##     ## ##        ##   ##  ##     ## 
          ##     ## ##         ## ##   ##     ## 
          ##     ## ########    ###    ########  

            HackSys Extreme Vulnerable Driver

Author : Ashfaq Ansari
Contact: ashfaq[at]payatu[dot]com
Website: http://www.payatu.com/

Copyright (C) 2011-2016 Payatu Technologies Pvt. Ltd. All rights reserved.

This program is free software: you can redistribute it and/or modify it under the terms of
the GNU General Public License as published by the Free Software Foundation, either version
3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.
If not, see <http://www.gnu.org/licenses/>.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

See the file 'LICENSE' for complete copying permission.

Module Name:
    HackSysExtremeVulnerableDriver.c

Abstract:
    This module implements the main kernel driver
    of HackSys Extreme Vulnerable Driver.

--*/

#include "HackSysExtremeVulnerableDriver.h"

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, DriverEntry)
    #pragma alloc_text(PAGE, IrpUnloadHandler)
    #pragma alloc_text(PAGE, IrpCreateCloseHandler)
    #pragma alloc_text(PAGE, IrpDeviceIoCtlHandler)
    #pragma alloc_text(PAGE, IrpNotImplementedHandler)
#endif // ALLOC_PRAGMA

/// <summary>
/// Driver Entry Point
/// </summary>
/// <param name="DriverObject">The pointer to DRIVER_OBJECT</param>
/// <param name="RegistryPath">The pointer to Unicode string specifying registry path</param>
/// <returns>NTSTATUS</returns>
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
    UINT32 i = 0;
    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING DeviceName, DosDeviceName = {0};

    UNREFERENCED_PARAMETER(RegistryPath);
    PAGED_CODE();

    RtlInitUnicodeString(&DeviceName, L"\\Device\\HackSysExtremeVulnerableDriver");
    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\HackSysExtremeVulnerableDriver");

    // Create the device
    Status = IoCreateDevice(DriverObject,
                            0,
                            &DeviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &DeviceObject);

    if (!NT_SUCCESS(Status)) {
        if (DeviceObject) {
            // Delete the device
            IoDeleteDevice(DeviceObject);
        }

        DbgPrint("[-] Error Initializing HackSys Extreme Vulnerable Driver\n");
        return Status;
    }

    // Assign the IRP handlers
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        // Disable the Compiler Warning: 28169
        #pragma warning(push)
        #pragma warning(disable : 28169)
        DriverObject->MajorFunction[i] = IrpNotImplementedHandler;
        #pragma warning(pop)
    }

    // Assign the IRP handlers for Create, Close and Device Control
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;

    // Assign the driver Unload routine
    DriverObject->DriverUnload = IrpUnloadHandler;

    // Set the flags
    DeviceObject->Flags |= DO_DIRECT_IO;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    // Create the symbolic link
    Status = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);

    // Show the banner
    DbgPrint("%s", BANNER);
    DbgPrint("[+] HackSys Extreme Vulnerable Driver Loaded\n");

    return Status;
}

/// <summary>
/// IRP Create Close Handler
/// </summary>
/// <param name="DeviceObject">The pointer to DEVICE_OBJECT</param>
/// <param name="Irp">The pointer to IRP</param>
/// <returns>NTSTATUS</returns>
NTSTATUS IrpCreateCloseHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    // Complete the request
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/// <summary>
/// IRP Unload Handler
/// </summary>
/// <param name="DeviceObject">The pointer to DEVICE_OBJECT</param>
/// <returns>NTSTATUS</returns>
VOID IrpUnloadHandler(IN PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING DosDeviceName = {0};

    PAGED_CODE();

    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\HackSysExtremeVulnerableDriver");

    // Delete the symbolic link
    IoDeleteSymbolicLink(&DosDeviceName);

    // Delete the device
    IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrint("[-] HackSys Extreme Vulnerable Driver Unloaded\n");
}

/// <summary>
/// IRP Not Implemented Handler
/// </summary>
/// <param name="DeviceObject">The pointer to DEVICE_OBJECT</param>
/// <param name="Irp">The pointer to IRP</param>
/// <returns>NTSTATUS</returns>
NTSTATUS IrpNotImplementedHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    // Complete the request
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_NOT_SUPPORTED;
}

/// <summary>
/// IRP Device IoCtl Handler
/// </summary>
/// <param name="DeviceObject">The pointer to DEVICE_OBJECT</param>
/// <param name="Irp">The pointer to IRP</param>
/// <returns>NTSTATUS</returns>
NTSTATUS IrpDeviceIoCtlHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ULONG IoControlCode = 0;
    PIO_STACK_LOCATION IrpSp = NULL;
    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

    if (IrpSp) {
        switch (IoControlCode) {
            case HACKSYS_EVD_IOCTL_STACK_OVERFLOW:
                DbgPrint("****** HACKSYS_EVD_STACKOVERFLOW ******\n");
                Status = StackOverflowIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_STACKOVERFLOW ******\n");
                break;
            case HACKSYS_EVD_IOCTL_STACK_OVERFLOW_GS:
                DbgPrint("****** HACKSYS_EVD_IOCTL_STACK_OVERFLOW_GS ******\n");
                Status = StackOverflowGSIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_STACK_OVERFLOW_GS ******\n");
                break;
            case HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE:
                DbgPrint("****** HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE ******\n");
                Status = ArbitraryOverwriteIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE ******\n");
                break;
            case HACKSYS_EVD_IOCTL_NON_PAGED_POOL_OVERFLOW:
                DbgPrint("****** HACKSYS_EVD_IOCTL_NON_PAGED_POOL_OVERFLOW ******\n");
                Status = NonPagedPoolOverflowIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_NON_PAGED_POOL_OVERFLOW ******\n");
                break;
            case HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT:
                DbgPrint("****** HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT ******\n");
                Status = AllocateUaFObjectIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT ******\n");
                break;
            case HACKSYS_EVD_IOCTL_USE_UAF_OBJECT:
                DbgPrint("****** HACKSYS_EVD_IOCTL_USE_UAF_OBJECT ******\n");
                Status = UseUaFObjectIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_USE_UAF_OBJECT ******\n");
                break;
            case HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT:
                DbgPrint("****** HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT ******\n");
                Status = FreeUaFObjectIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT ******\n");
                break;
            case HACKSYS_EVD_IOCTL_ALLOCATE_FAKE_OBJECT:
                DbgPrint("****** HACKSYS_EVD_IOCTL_ALLOCATE_FAKE_OBJECT ******\n");
                Status = AllocateFakeObjectIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_ALLOCATE_FAKE_OBJECT ******\n");
                break;
            case HACKSYS_EVD_IOCTL_TYPE_CONFUSION:
                DbgPrint("****** HACKSYS_EVD_IOCTL_TYPE_CONFUSION ******\n");
                Status = TypeConfusionIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_TYPE_CONFUSION ******\n");
                break;
            case HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW:
                DbgPrint("****** HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW ******\n");
                Status = IntegerOverflowIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW ******\n");
                break;
            case HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE:
                DbgPrint("****** HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE ******\n");
                Status = NullPointerDereferenceIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE ******\n");
                break;
            case HACKSYS_EVD_IOCTL_UNINITIALIZED_STACK_VARIABLE:
                DbgPrint("****** HACKSYS_EVD_IOCTL_UNINITIALIZED_STACK_VARIABLE ******\n");
                Status = UninitializedStackVariableIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_UNINITIALIZED_STACK_VARIABLE ******\n");
                break;
            case HACKSYS_EVD_IOCTL_UNINITIALIZED_HEAP_VARIABLE:
                DbgPrint("****** HACKSYS_EVD_IOCTL_UNINITIALIZED_HEAP_VARIABLE ******\n");
                Status = UninitializedHeapVariableIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_UNINITIALIZED_HEAP_VARIABLE ******\n");
                break;
            case HACKSYS_EVD_IOCTL_DOUBLE_FETCH:
                DbgPrint("****** HACKSYS_EVD_IOCTL_DOUBLE_FETCH ******\n");
                Status = DoubleFetchIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_DOUBLE_FETCH ******\n");
                break;
            case HACKSYS_EVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS:
                DbgPrint("****** HACKSYS_EVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS ******\n");
                Status = InsecureKernelFileAccessIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS ******\n");
                break;
            case HACKSYS_EVD_IOCTL_MEMORY_DISCLOSURE:
                DbgPrint("****** HACKSYS_EVD_IOCTL_MEMORY_DISCLOSURE ******\n");
                Status = MemoryDisclosureIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_MEMORY_DISCLOSURE ******\n");
                break;
            case HACKSYS_EVD_IOCTL_PAGED_POOL_SESSION:
                DbgPrint("****** HACKSYS_EVD_IOCTL_PAGED_POOL_SESSION ******\n");
                Status = PagedPoolSessionOverflowIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_PAGED_POOL_SESSION ******\n");
                break;
            case HACKSYS_EVD_IOCTL_WRITE_NULL:
                DbgPrint("****** HACKSYS_EVD_IOCTL_WRITE_NULL ******\n");
                Status = WriteNULLIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HACKSYS_EVD_IOCTL_WRITE_NULL ******\n");
                break;
            default:
                DbgPrint("[-] Invalid IOCTL Code: 0x%X\n", IoControlCode);
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;
        }
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;

    // Complete the request
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}
