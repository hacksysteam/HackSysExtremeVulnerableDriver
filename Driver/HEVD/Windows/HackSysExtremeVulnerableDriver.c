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
Contact: ashfaq[at]hacksys[dot]io
Website: https://hacksys.io/

Copyright (C) 2021-2023 HackSys Inc. All rights reserved.
Copyright (C) 2015-2020 Payatu Software Labs LLP. All rights reserved.

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
#pragma alloc_text(PAGE, DriverUnloadHandler)
#pragma alloc_text(PAGE, IrpCreateCloseHandler)
#pragma alloc_text(PAGE, IrpDeviceIoCtlHandler)
#pragma alloc_text(PAGE, IrpNotImplementedHandler)
#endif // ALLOC_PRAGMA


/// <summary>
/// HackSys Extreme Vulnerable Driver Entry Point
/// </summary>
/// <param name="DriverObject">The pointer to DRIVER_OBJECT</param>
/// <param name="RegistryPath">The pointer to Unicode string specifying registry path</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UINT32 i = 0;
    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING DeviceName, DosDeviceName = { 0 };

    UNREFERENCED_PARAMETER(RegistryPath);
    PAGED_CODE();

    RtlInitUnicodeString(&DeviceName, L"\\Device\\HackSysExtremeVulnerableDriver");
    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\HackSysExtremeVulnerableDriver");

    //
    // Create the device
    //

    Status = IoCreateDevice(
        DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &DeviceObject
    );

    if (!NT_SUCCESS(Status))
    {
        if (DeviceObject)
        {
            //
            // Delete the device
            //

            IoDeleteDevice(DeviceObject);
        }

        DbgPrint("[-] Error Initializing HackSys Extreme Vulnerable Driver\n");
        return Status;
    }

    //
    // Assign the IRP handlers
    //

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        DriverObject->MajorFunction[i] = IrpNotImplementedHandler;
    }

    //
    // Assign the IRP handlers for Create, Close and Device Control
    //

    DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;

    //
    // Assign the driver Unload routine
    //

    DriverObject->DriverUnload = DriverUnloadHandler;

    //
    // Set the flags
    //

    DeviceObject->Flags |= DO_DIRECT_IO;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    //
    // Create the symbolic link
    //

    Status = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);

    //
    // Show the banner
    //

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
NTSTATUS
IrpCreateCloseHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    //
    // Complete the request
    //

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


/// <summary>
/// Driver Unload Handler
/// </summary>
/// <param name="DeviceObject">The pointer to DEVICE_OBJECT</param>
/// <returns>NTSTATUS</returns>
VOID
DriverUnloadHandler(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING DosDeviceName = { 0 };

    PAGED_CODE();

    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\HackSysExtremeVulnerableDriver");

    //
    // Delete the symbolic link
    //

    IoDeleteSymbolicLink(&DosDeviceName);

    //
    // Delete the device
    //

    IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrint("[-] HackSys Extreme Vulnerable Driver Unloaded\n");
}


/// <summary>
/// IRP Not Implemented Handler
/// </summary>
/// <param name="DeviceObject">The pointer to DEVICE_OBJECT</param>
/// <param name="Irp">The pointer to IRP</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
IrpNotImplementedHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    //
    // Complete the request
    //

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_NOT_SUPPORTED;
}


/// <summary>
/// IRP Device IoCtl Handler
/// </summary>
/// <param name="DeviceObject">The pointer to DEVICE_OBJECT</param>
/// <param name="Irp">The pointer to IRP</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
IrpDeviceIoCtlHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    ULONG IoControlCode = 0;
    PIO_STACK_LOCATION IrpSp = NULL;
    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp)
    {
        IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

        switch (IoControlCode)
        {
        case HEVD_IOCTL_BUFFER_OVERFLOW_STACK:
            DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK ******\n");
            Status = BufferOverflowStackIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK ******\n");
            break;
        case HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS:
            DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS ******\n");
            Status = BufferOverflowStackGSIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS ******\n");
            break;
        case HEVD_IOCTL_ARBITRARY_WRITE:
            DbgPrint("****** HEVD_IOCTL_ARBITRARY_WRITE ******\n");
            Status = ArbitraryWriteIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_ARBITRARY_WRITE ******\n");
            break;
        case HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL:
            DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL ******\n");
            Status = BufferOverflowNonPagedPoolIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL ******\n");
            break;
        case HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL:
            DbgPrint("****** HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL ******\n");
            Status = AllocateUaFObjectNonPagedPoolIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL ******\n");
            break;
        case HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL:
            DbgPrint("****** HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL ******\n");
            Status = UseUaFObjectNonPagedPoolIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL ******\n");
            break;
        case HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL:
            DbgPrint("****** HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL ******\n");
            Status = FreeUaFObjectNonPagedPoolIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL ******\n");
            break;
        case HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL:
            DbgPrint("****** HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL ******\n");
            Status = AllocateFakeObjectNonPagedPoolIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL ******\n");
            break;
        case HEVD_IOCTL_TYPE_CONFUSION:
            DbgPrint("****** HEVD_IOCTL_TYPE_CONFUSION ******\n");
            Status = TypeConfusionIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_TYPE_CONFUSION ******\n");
            break;
        case HEVD_IOCTL_INTEGER_OVERFLOW:
            DbgPrint("****** HEVD_IOCTL_INTEGER_OVERFLOW ******\n");
            Status = IntegerOverflowIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_INTEGER_OVERFLOW ******\n");
            break;
        case HEVD_IOCTL_NULL_POINTER_DEREFERENCE:
            DbgPrint("****** HEVD_IOCTL_NULL_POINTER_DEREFERENCE ******\n");
            Status = NullPointerDereferenceIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_NULL_POINTER_DEREFERENCE ******\n");
            break;
        case HEVD_IOCTL_UNINITIALIZED_MEMORY_STACK:
            DbgPrint("****** HEVD_IOCTL_UNINITIALIZED_MEMORY_STACK ******\n");
            Status = UninitializedMemoryStackIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_UNINITIALIZED_MEMORY_STACK ******\n");
            break;
        case HEVD_IOCTL_UNINITIALIZED_MEMORY_PAGED_POOL:
            DbgPrint("****** HEVD_IOCTL_UNINITIALIZED_MEMORY_PAGED_POOL ******\n");
            Status = UninitializedMemoryPagedPoolIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_UNINITIALIZED_MEMORY_PAGED_POOL ******\n");
            break;
        case HEVD_IOCTL_DOUBLE_FETCH:
            DbgPrint("****** HEVD_IOCTL_DOUBLE_FETCH ******\n");
            Status = DoubleFetchIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_DOUBLE_FETCH ******\n");
            break;
        case HEVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS:
            DbgPrint("****** HEVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS ******\n");
            Status = InsecureKernelFileAccessIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS ******\n");
            break;
        case HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL:
            DbgPrint("****** HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL ******\n");
            Status = MemoryDisclosureNonPagedPoolIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL ******\n");
            break;
        case HEVD_IOCTL_BUFFER_OVERFLOW_PAGED_POOL_SESSION:
            DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_PAGED_POOL_SESSION ******\n");
            Status = BufferOverflowPagedPoolSessionIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_PAGED_POOL_SESSION ******\n");
            break;
        case HEVD_IOCTL_WRITE_NULL:
            DbgPrint("****** HEVD_IOCTL_WRITE_NULL ******\n");
            Status = WriteNULLIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_WRITE_NULL ******\n");
            break;
        case HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL_NX:
            DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL_NX ******\n");
            Status = BufferOverflowNonPagedPoolNxIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL_NX ******\n");
            break;
        case HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL_NX:
            DbgPrint("****** HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL_NX ******\n");
            Status = MemoryDisclosureNonPagedPoolNxIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL_NX ******\n");
            break;
        case HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL_NX:
            DbgPrint("****** HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL_NX ******\n");
            Status = AllocateUaFObjectNonPagedPoolNxIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL_NX ******\n");
            break;
        case HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL_NX:
            DbgPrint("****** HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL_NX ******\n");
            Status = UseUaFObjectNonPagedPoolNxIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL_NX ******\n");
            break;
        case HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL_NX:
            DbgPrint("****** HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL_NX ******\n");
            Status = FreeUaFObjectNonPagedPoolNxIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL_NX ******\n");
            break;
        case HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL_NX:
            DbgPrint("****** HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL_NX ******\n");
            Status = AllocateFakeObjectNonPagedPoolNxIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL_NX ******\n");
            break;
        case HEVD_IOCTL_CREATE_ARW_HELPER_OBJECT_NON_PAGED_POOL_NX:
            DbgPrint("****** HEVD_IOCTL_CREATE_ARW_HELPER_OBJECT_NON_PAGED_POOL_NX ******\n");
            Status = CreateArbitraryReadWriteHelperObjectNonPagedPoolNxIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_CREATE_ARW_HELPER_OBJECT_NON_PAGED_POOL_NX ******\n");
            break;
        case HEVD_IOCTL_SET_ARW_HELPER_OBJECT_NAME_NON_PAGED_POOL_NX:
            DbgPrint("****** HEVD_IOCTL_SET_ARW_HELPER_OBJECT_NAME_NON_PAGED_POOL_NX ******\n");
            Status = SetArbitraryReadWriteHelperObjecNameNonPagedPoolNxIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_SET_ARW_HELPER_OBJECT_NAME_NON_PAGED_POOL_NX ******\n");
            break;
        case HEVD_IOCTL_GET_ARW_HELPER_OBJECT_NAME_NON_PAGED_POOL_NX:
            DbgPrint("****** HEVD_IOCTL_GET_ARW_HELPER_OBJECT_NAME_NON_PAGED_POOL_NX ******\n");
            Status = GetArbitraryReadWriteHelperObjecNameNonPagedPoolNxIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_GET_ARW_HELPER_OBJECT_NAME_NON_PAGED_POOL_NX ******\n");
            break;
        case HEVD_IOCTL_DELETE_ARW_HELPER_OBJECT_NON_PAGED_POOL_NX:
            DbgPrint("****** HEVD_IOCTL_DELETE_ARW_HELPER_OBJECT_NON_PAGED_POOL_NX ******\n");
            Status = DeleteArbitraryReadWriteHelperObjecNonPagedPoolNxIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_DELETE_ARW_HELPER_OBJECT_NON_PAGED_POOL_NX ******\n");
            break;
        case HEVD_IOCTL_ARBITRARY_INCREMENT:
            DbgPrint("****** HEVD_IOCTL_ARBITRARY_INCREMENT ******\n");
            Status = ArbitraryIncrementIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_ARBITRARY_INCREMENT ******\n");
            break;
        default:
            DbgPrint("[-] Invalid IOCTL Code: 0x%X\n", IoControlCode);
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    //
    // Update the IoStatus information
    //

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;

    //
    // Complete the request
    //

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}
