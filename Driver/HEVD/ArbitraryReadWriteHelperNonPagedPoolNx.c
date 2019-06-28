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
    ArbitraryReadWriteHelperNonPagedPoolNx.c

Abstract:
    This module implements the helper functions to
    achieve arbitrary read write primitive in NonPagedPoolNx.

--*/

#include "ArbitraryReadWriteHelperNonPagedPoolNx.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, GetFreeIndex)
#pragma alloc_text(PAGE, GetIndexFromPointer)
#pragma alloc_text(PAGE, DeleteArbitraryReadWriteHelperObjecNonPagedPoolNx)
#pragma alloc_text(PAGE, CreateArbitraryReadWriteHelperObjectNonPagedPoolNx)
#pragma alloc_text(PAGE, SetArbitraryReadWriteHelperObjecNameNonPagedPoolNx)
#pragma alloc_text(PAGE, GetArbitraryReadWriteHelperObjecNameNonPagedPoolNx)
#pragma alloc_text(PAGE, DeleteArbitraryReadWriteHelperObjecNonPagedPoolNxIoctlHandler)
#pragma alloc_text(PAGE, CreateArbitraryReadWriteHelperObjectNonPagedPoolNxIoctlHandler)
#pragma alloc_text(PAGE, SetArbitraryReadWriteHelperObjecNameNonPagedPoolNxIoctlHandler)
#pragma alloc_text(PAGE, GetArbitraryReadWriteHelperObjecNameNonPagedPoolNxIoctlHandler)
#endif // ALLOC_PRAGMA


PARW_HELPER_OBJECT_NON_PAGED_POOL_NX g_ARWHelperObjectNonPagedPoolNx[MAX_OBJECT_COUNT] = { 0 };


/// <summary>
/// Get Free Index in g_ARWHelperObjectNonPagedPoolNx
/// </summary>
/// <returns>INT</returns>
INT
GetFreeIndex(
    VOID
)
{
    INT i = 0;
    INT FreeIndex = STATUS_INVALID_INDEX;

    for (i = 0; i < MAX_OBJECT_COUNT; i++)
    {
        if (!g_ARWHelperObjectNonPagedPoolNx[i])
        {
            FreeIndex = i;
            break;
        }
    }

    return FreeIndex;
}


/// <summary>
/// Get Index in g_ARWHelperObjectNonPagedPoolNx From Pointer 
/// </summary>
/// <param name="Pointer">Pointer</param>
/// <returns>INT</returns>
INT
GetIndexFromPointer(
    _In_ PVOID Pointer
)
{
    INT i = 0;
    INT FreeIndex = STATUS_INVALID_INDEX;

    if (!Pointer)
    {
        return FreeIndex;
    }

    for (i = 0; i < MAX_OBJECT_COUNT; i++)
    {
        if (g_ARWHelperObjectNonPagedPoolNx[i] == Pointer)
        {
            FreeIndex = i;
            break;
        }
    }

    return FreeIndex;
}


/// <summary>
/// Create Arbitrary Read Write Helper Object in NonPagedPoolNx
/// </summary>
/// <param name="HelperObjectIo">The pointer to ARW_HELPER_OBJECT_IO structure</param>
/// <returns>INT</returns>
NTSTATUS
CreateArbitraryReadWriteHelperObjectNonPagedPoolNx(
    _In_ PARW_HELPER_OBJECT_IO HelperObjectIo
)
{
    PVOID Name = NULL;
    SIZE_T Length = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    INT FreeIndex = STATUS_INVALID_INDEX;
    PARW_HELPER_OBJECT_NON_PAGED_POOL_NX ARWHelperObject = NULL;

    __try
    {
        //
        // Verify if the buffer resides in user mode
        //

        ProbeForRead(HelperObjectIo, sizeof(ARW_HELPER_OBJECT_IO), (ULONG)__alignof(UCHAR));

        //
        // Make a local copy of the data structure to avoid race conditions
        //

        Length = HelperObjectIo->Length;

        DbgPrint("[+] Name Length: 0x%X\n", Length);

        //
        // Get a free index
        //

        FreeIndex = GetFreeIndex();

        if (FreeIndex == STATUS_INVALID_INDEX)
        {
            //
            // Failed to get a free index
            //

            Status = STATUS_INVALID_INDEX;
            DbgPrint("[-] Unable to find FreeIndex: 0x%X\n", Status);

            return Status;
        }
        else
        {
            DbgPrint("[+] FreeIndex: 0x%X\n", FreeIndex);
        }

        DbgPrint("[+] Allocating Pool chunk for ARWHelperObject\n");

        //
        // Allocate Pool chunk for ARWHelperObject
        //

        ARWHelperObject = (PARW_HELPER_OBJECT_NON_PAGED_POOL_NX)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(ARW_HELPER_OBJECT_NON_PAGED_POOL_NX),
            POOL_TAG
        );

        if (!ARWHelperObject)
        {
            //
            // Unable to allocate Pool chunk for ARWHelperObject
            //

            DbgPrint("[-] Unable to allocate Pool chunk for ARWHelperObject\n");

            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else
        {
            DbgPrint("[+] ARWHelperObject Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] ARWHelperObject Pool Type: %s\n", STRINGIFY(NonPagedPoolNx));
            DbgPrint("[+] ARWHelperObject Pool Size: 0x%X\n", sizeof(ARW_HELPER_OBJECT_NON_PAGED_POOL_NX));
            DbgPrint("[+] ARWHelperObject Pool Chunk: 0x%p\n", ARWHelperObject);
        }

        DbgPrint("[+] Allocating Pool chunk for Name\n");

        //
        // Allocate Pool chunk for Name
        //

        Name = ExAllocatePoolWithTag(NonPagedPoolNx, Length, POOL_TAG);

        if (!Name)
        {
            //
            // Unable to allocate Pool chunk for Name
            //

            DbgPrint("[-] Unable to allocate Pool chunk for Name\n");

            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else
        {
            DbgPrint("[+] Name Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Name Pool Type: %s\n", STRINGIFY(NonPagedPoolNx));
            DbgPrint("[+] Name Pool Size: 0x%X\n", Length);
            DbgPrint("[+] Name Pool Chunk: 0x%p\n", Name);
        }

        //
        // Initialize the kernel buffer
        //

        RtlFillMemory(Name, (SIZE_T)Length, 0);

        //
        // Initialize the kernel structure
        //

        ARWHelperObject->Name = Name;
        ARWHelperObject->Length = Length;

        DbgPrint("[+] ARWHelperObject->Name: 0x%p\n", ARWHelperObject->Name);
        DbgPrint("[+] ARWHelperObject->Length: 0x%X\n", ARWHelperObject->Length);

        g_ARWHelperObjectNonPagedPoolNx[FreeIndex] = ARWHelperObject;

        //
        // Verify if the buffer resides in user mode
        //

        ProbeForWrite(HelperObjectIo, sizeof(ARW_HELPER_OBJECT_IO), (ULONG)__alignof(UCHAR));

        //
        // Write the object address to user mode for book keeping
        //

        HelperObjectIo->HelperObjectAddress = ARWHelperObject;

        DbgPrint("[+] HelperObjectIo->HelperObjectAddress: 0x%p\n", HelperObjectIo->HelperObjectAddress);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}


/// <summary>
/// Set Arbitrary Read Write Helper Object Name in NonPagedPoolNx
/// </summary>
/// <param name="HelperObjectIo">The pointer to ARW_HELPER_OBJECT_IO structure</param>
/// <returns>INT</returns>
NTSTATUS
SetArbitraryReadWriteHelperObjecNameNonPagedPoolNx(
    _In_ PARW_HELPER_OBJECT_IO HelperObjectIo
)
{
    PVOID Name = NULL;
    PVOID HelperObjectAddress = NULL;
    INT Index = STATUS_INVALID_INDEX;
    NTSTATUS Status = STATUS_SUCCESS;

    __try
    {
        //
        // Verify if the buffer resides in user mode
        //

        ProbeForRead(HelperObjectIo, sizeof(ARW_HELPER_OBJECT_IO), (ULONG)__alignof(UCHAR));

        //
        // Make a local copy of the data structure to avoid race conditions
        //

        Name = HelperObjectIo->Name;
        HelperObjectAddress = HelperObjectIo->HelperObjectAddress;

        DbgPrint("[+] HelperObjectIo->Name: 0x%p\n", Name);
        DbgPrint("[+] HelperObjectIo->HelperObjectAddress: 0x%p\n", HelperObjectAddress);

        //
        // Get index by pointer
        //

        Index = GetIndexFromPointer(HelperObjectAddress);

        if (Index == STATUS_INVALID_INDEX)
        {
            //
            // Failed to find index from pointer
            //

            DbgPrint("[-] Unable to find index from pointer: 0x%p\n", HelperObjectAddress);

            Status = STATUS_INVALID_INDEX;
            return Status;
        }
        else
        {
            DbgPrint("[+] Index: 0x%X Pointer: 0x%p\n", Index, HelperObjectAddress);
        }

        if (Name && g_ARWHelperObjectNonPagedPoolNx[Index]->Length)
        {
            //
            // Verify if the buffer resides in user mode
            //

            ProbeForRead(
                Name,
                g_ARWHelperObjectNonPagedPoolNx[Index]->Length,
                (ULONG)__alignof(UCHAR)
            );

            //
            // Copy the name from user buffer to kernel object name buffer
            //

            DbgPrint(
                "[+] Copying src: 0x%p dst: 0x%p len: 0x%X\n",
                Name,
                g_ARWHelperObjectNonPagedPoolNx[Index]->Name,
                g_ARWHelperObjectNonPagedPoolNx[Index]->Length
            );

            RtlCopyMemory(
                g_ARWHelperObjectNonPagedPoolNx[Index]->Name,
                Name,
                g_ARWHelperObjectNonPagedPoolNx[Index]->Length
            );
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}


/// <summary>
/// Get Arbitrary Read Write Helper Object Name in NonPagedPoolNx
/// </summary>
/// <param name="HelperObjectIo">The pointer to ARW_HELPER_OBJECT_IO structure</param>
/// <returns>INT</returns>
NTSTATUS
GetArbitraryReadWriteHelperObjecNameNonPagedPoolNx(
    _In_ PARW_HELPER_OBJECT_IO HelperObjectIo
)
{
    PVOID Name = NULL;
    PVOID HelperObjectAddress = NULL;
    INT Index = STATUS_INVALID_INDEX;
    NTSTATUS Status = STATUS_SUCCESS;

    __try
    {
        //
        // Verify if the buffer resides in user mode
        //

        ProbeForRead(HelperObjectIo, sizeof(ARW_HELPER_OBJECT_IO), (ULONG)__alignof(UCHAR));

        //
        // Make a local copy of the data structure to avoid race conditions
        //

        Name = HelperObjectIo->Name;
        HelperObjectAddress = HelperObjectIo->HelperObjectAddress;

        DbgPrint("[+] HelperObjectIo->Name: 0x%p\n", Name);
        DbgPrint("[+] HelperObjectIo->HelperObjectAddress: 0x%p\n", HelperObjectAddress);

        //
        // Get index by pointer
        //

        Index = GetIndexFromPointer(HelperObjectAddress);

        if (Index == STATUS_INVALID_INDEX)
        {
            //
            // Failed to find index from pointer
            //

            DbgPrint("[-] Unable to find index from pointer: 0x%p\n", HelperObjectAddress);

            Status = STATUS_INVALID_INDEX;
            return Status;
        }
        else
        {
            DbgPrint("[+] Index: 0x%X Pointer: 0x%p\n", Index, HelperObjectAddress);
        }

        if (g_ARWHelperObjectNonPagedPoolNx[Index]->Name && g_ARWHelperObjectNonPagedPoolNx[Index]->Length)
        {
            //
            // Verify if the buffer resides in user mode
            //

            ProbeForWrite(
                Name,
                g_ARWHelperObjectNonPagedPoolNx[Index]->Length,
                (ULONG)__alignof(UCHAR)
            );

            //
            // Copy the name from object name buffer to user buffer
            //

            DbgPrint(
                "[+] Copying src: 0x%p dst: 0x%p len: 0x%X\n",
                g_ARWHelperObjectNonPagedPoolNx[Index]->Name,
                Name,
                g_ARWHelperObjectNonPagedPoolNx[Index]->Length
            );

            RtlCopyMemory(
                Name,
                g_ARWHelperObjectNonPagedPoolNx[Index]->Name,
                g_ARWHelperObjectNonPagedPoolNx[Index]->Length
            );
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}


/// <summary>
/// Delete Arbitrary Read Write Helper Object in NonPagedPoolNx
/// </summary>
/// <param name="HelperObjectIo">The pointer to ARW_HELPER_OBJECT_IO structure</param>
/// <returns>INT</returns>
NTSTATUS
DeleteArbitraryReadWriteHelperObjecNonPagedPoolNx(
    _In_ PARW_HELPER_OBJECT_IO HelperObjectIo
)
{
    PVOID HelperObjectAddress = NULL;
    INT Index = STATUS_INVALID_INDEX;
    NTSTATUS Status = STATUS_SUCCESS;

    __try
    {
        //
        // Verify if the buffer resides in user mode
        //

        ProbeForRead(HelperObjectIo, sizeof(ARW_HELPER_OBJECT_IO), (ULONG)__alignof(UCHAR));

        //
        // Make a local copy of the data structure to avoid race conditions
        //

        HelperObjectAddress = HelperObjectIo->HelperObjectAddress;

        DbgPrint("[+] HelperObjectIo->HelperObjectAddress: 0x%p\n", HelperObjectAddress);

        //
        // Get index by pointer
        //

        Index = GetIndexFromPointer(HelperObjectAddress);

        if (Index == STATUS_INVALID_INDEX)
        {
            //
            // Failed to find index from pointer
            //

            DbgPrint("[-] Unable to find index from pointer: 0x%p\n", HelperObjectAddress);

            Status = STATUS_INVALID_INDEX;
            return Status;
        }
        else
        {
            DbgPrint("[+] Index: 0x%X Pointer: 0x%p\n", Index, HelperObjectAddress);
        }

        if (g_ARWHelperObjectNonPagedPoolNx[Index]->Name)
        {
            //
            // Free the pool memory for name buffer
            //

            ExFreePoolWithTag(g_ARWHelperObjectNonPagedPoolNx[Index]->Name, POOL_TAG);
        }

        //
        // Free up the object at index
        //

        ExFreePoolWithTag(g_ARWHelperObjectNonPagedPoolNx[Index], POOL_TAG);

        //
        // Set to NULL to avoid dangling pointer
        //

        g_ARWHelperObjectNonPagedPoolNx[Index] = NULL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}


/// <summary>
/// Create Arbitrary Read Write Helper Object Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
CreateArbitraryReadWriteHelperObjectNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PARW_HELPER_OBJECT_IO HelperObjectIo = NULL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    HelperObjectIo = (PARW_HELPER_OBJECT_IO)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (HelperObjectIo)
    {
        Status = CreateArbitraryReadWriteHelperObjectNonPagedPoolNx(HelperObjectIo);
    }

    return Status;
}


/// <summary>
/// Set Arbitrary Read Write Helper Object Name Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
SetArbitraryReadWriteHelperObjecNameNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PARW_HELPER_OBJECT_IO HelperObjectIo = NULL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    HelperObjectIo = (PARW_HELPER_OBJECT_IO)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (HelperObjectIo)
    {
        Status = SetArbitraryReadWriteHelperObjecNameNonPagedPoolNx(HelperObjectIo);
    }

    return Status;
}


/// <summary>
/// Get Arbitrary Read Write Helper Object Name Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
GetArbitraryReadWriteHelperObjecNameNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PARW_HELPER_OBJECT_IO HelperObjectIo = NULL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    HelperObjectIo = (PARW_HELPER_OBJECT_IO)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (HelperObjectIo)
    {
        Status = GetArbitraryReadWriteHelperObjecNameNonPagedPoolNx(HelperObjectIo);
    }

    return Status;
}


/// <summary>
/// Delete Arbitrary Read Write Helper Object Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
DeleteArbitraryReadWriteHelperObjecNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PARW_HELPER_OBJECT_IO HelperObjectIo = NULL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    HelperObjectIo = (PARW_HELPER_OBJECT_IO)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (HelperObjectIo)
    {
        Status = DeleteArbitraryReadWriteHelperObjecNonPagedPoolNx(HelperObjectIo);
    }

    return Status;
}
