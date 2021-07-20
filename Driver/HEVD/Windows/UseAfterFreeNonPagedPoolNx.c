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
    UseAfterFreeNonPagedPoolNx.c

Abstract:
    This module implements the functions to demonstrate
    Use After Free in NonPagedPoolNx vulnerability.

--*/

#include "UseAfterFreeNonPagedPoolNx.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, UseUaFObjectNonPagedPoolNx)
#pragma alloc_text(PAGE, FreeUaFObjectNonPagedPoolNx)
#pragma alloc_text(PAGE, AllocateUaFObjectNonPagedPoolNx)
#pragma alloc_text(PAGE, UaFObjectCallbackNonPagedPoolNx)
#pragma alloc_text(PAGE, AllocateFakeObjectNonPagedPoolNx)
#pragma alloc_text(PAGE, UseUaFObjectNonPagedPoolNxIoctlHandler)
#pragma alloc_text(PAGE, FreeUaFObjectNonPagedPoolNxIoctlHandler)
#pragma alloc_text(PAGE, AllocateUaFObjectNonPagedPoolNxIoctlHandler)
#pragma alloc_text(PAGE, AllocateFakeObjectNonPagedPoolNxIoctlHandler)
#endif // ALLOC_PRAGMA


PUSE_AFTER_FREE_NON_PAGED_POOL_NX g_UseAfterFreeObjectNonPagedPoolNx = NULL;


/// <summary>
/// Use After Free Object Callback NonPagedPoolNx
/// </summary>
VOID
UaFObjectCallbackNonPagedPoolNx(
    VOID
)
{
    PAGED_CODE();

    DbgPrint("[+] UseAfter Free Object Callback NonPagedPoolNx\n");
}


/// <summary>
/// Allocate the UaF object in NonPagedPoolNx
/// </summary>
/// <returns>NTSTATUS</returns>
NTSTATUS
AllocateUaFObjectNonPagedPoolNx(
    VOID
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PUSE_AFTER_FREE_NON_PAGED_POOL_NX UseAfterFree = NULL;

    PAGED_CODE();

    __try
    {
        DbgPrint("[+] Allocating UaF Object\n");

        //
        // Allocate Pool chunk
        //

        UseAfterFree = (PUSE_AFTER_FREE_NON_PAGED_POOL_NX)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(USE_AFTER_FREE_NON_PAGED_POOL_NX),
            (ULONG)POOL_TAG
        );

        if (!UseAfterFree)
        {
            //
            // Unable to allocate Pool chunk
            //

            DbgPrint("[-] Unable to allocate Pool chunk\n");

            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else
        {
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPoolNx));
            DbgPrint("[+] Pool Size: 0x%zX\n", sizeof(USE_AFTER_FREE_NON_PAGED_POOL_NX));
            DbgPrint("[+] Pool Chunk: 0x%p\n", UseAfterFree);
        }

        //
        // Fill the buffer with ASCII 'A'
        //

        RtlFillMemory((PVOID)UseAfterFree->Buffer, sizeof(UseAfterFree->Buffer), 0x41);

        //
        // Null terminate the char buffer
        //

        UseAfterFree->Buffer[sizeof(UseAfterFree->Buffer) - 1] = '\0';

        //
        // Set the object Callback function
        //

        UseAfterFree->Callback = &UaFObjectCallbackNonPagedPoolNx;

        //
        // Assign the address of UseAfterFree to a global variable
        //

        g_UseAfterFreeObjectNonPagedPoolNx = UseAfterFree;

        DbgPrint("[+] UseAfterFree Object: 0x%p\n", UseAfterFree);
        DbgPrint("[+] g_UseAfterFreeObjectNonPagedPoolNx: 0x%p\n", g_UseAfterFreeObjectNonPagedPoolNx);
        DbgPrint("[+] UseAfterFree->Callback: 0x%p\n", UseAfterFree->Callback);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}


/// <summary>
/// Use the UaF object NonPagedPoolNx
/// </summary>
/// <returns>NTSTATUS</returns>
NTSTATUS
UseUaFObjectNonPagedPoolNx(
    VOID
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PAGED_CODE();

    __try
    {
        if (g_UseAfterFreeObjectNonPagedPoolNx)
        {
            DbgPrint("[+] Using UaF Object\n");
            DbgPrint("[+] g_UseAfterFreeObjectNonPagedPoolNx: 0x%p\n", g_UseAfterFreeObjectNonPagedPoolNx);
            DbgPrint("[+] g_UseAfterFreeObjectNonPagedPoolNx->Callback: 0x%p\n", g_UseAfterFreeObjectNonPagedPoolNx->Callback);
            DbgPrint("[+] Calling Callback\n");

            if (g_UseAfterFreeObjectNonPagedPoolNx->Callback)
            {
                g_UseAfterFreeObjectNonPagedPoolNx->Callback();
            }

            Status = STATUS_SUCCESS;
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
/// Free the UaF object NonPagedPoolNx
/// </summary>
/// <returns>NTSTATUS</returns>
NTSTATUS
FreeUaFObjectNonPagedPoolNx(
    VOID
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PAGED_CODE();

    __try
    {
        if (g_UseAfterFreeObjectNonPagedPoolNx)
        {
            DbgPrint("[+] Freeing UaF Object\n");
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Chunk: 0x%p\n", g_UseAfterFreeObjectNonPagedPoolNx);

#ifdef SECURE
            //
            // Secure Note: This is secure because the developer is setting
            // 'g_UseAfterFreeObjectNonPagedPoolNx' to NULL once the Pool chunk is being freed
            //

            ExFreePoolWithTag((PVOID)g_UseAfterFreeObjectNonPagedPoolNx, (ULONG)POOL_TAG);

            //
            // Set to NULL to avoid dangling pointer
            //

            g_UseAfterFreeObjectNonPagedPoolNx = NULL;
#else
            //
            // Vulnerability Note: This is a vanilla Use After Free vulnerability
            // because the developer is not setting 'g_UseAfterFreeObjectNonPagedPoolNx' to NULL.
            // Hence, g_UseAfterFreeObjectNonPagedPoolNx still holds the reference to stale pointer
            // (dangling pointer)
            //

            ExFreePoolWithTag((PVOID)g_UseAfterFreeObjectNonPagedPoolNx, (ULONG)POOL_TAG);
#endif

            Status = STATUS_SUCCESS;
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
/// Allocate the Fake object NonPagedPoolNx
/// </summary>
/// <param name="UserFakeObject">The pointer to FAKE_OBJECT_NON_PAGED_POOL structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
AllocateFakeObjectNonPagedPoolNx(
    _In_ PFAKE_OBJECT_NON_PAGED_POOL_NX UserFakeObject
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PFAKE_OBJECT_NON_PAGED_POOL_NX KernelFakeObject = NULL;

    PAGED_CODE();

    __try
    {
        DbgPrint("[+] Creating Fake Object\n");

        //
        // Allocate Pool chunk
        //

        KernelFakeObject = (PFAKE_OBJECT_NON_PAGED_POOL_NX)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(FAKE_OBJECT_NON_PAGED_POOL_NX),
            (ULONG)POOL_TAG
        );

        if (!KernelFakeObject)
        {
            //
            // Unable to allocate Pool chunk
            //

            DbgPrint("[-] Unable to allocate Pool chunk\n");

            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else
        {
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPoolNx));
            DbgPrint("[+] Pool Size: 0x%zX\n", sizeof(FAKE_OBJECT_NON_PAGED_POOL_NX));
            DbgPrint("[+] Pool Chunk: 0x%p\n", KernelFakeObject);
        }

        //
        // Verify if the buffer resides in user mode
        //

        ProbeForRead(
            (PVOID)UserFakeObject,
            sizeof(FAKE_OBJECT_NON_PAGED_POOL_NX),
            (ULONG)__alignof(UCHAR)
        );

        //
        // Copy the Fake structure to Pool chunk
        //

        RtlCopyMemory(
            (PVOID)KernelFakeObject,
            (PVOID)UserFakeObject,
            sizeof(FAKE_OBJECT_NON_PAGED_POOL_NX)
        );

        //
        // Null terminate the char buffer
        //

        KernelFakeObject->Buffer[sizeof(KernelFakeObject->Buffer) - 1] = '\0';

        DbgPrint("[+] Fake Object: 0x%p\n", KernelFakeObject);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}


/// <summary>
/// Allocate UaF Object NonPagedPoolNx Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP.</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
AllocateUaFObjectNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IrpSp);
    PAGED_CODE();

    Status = AllocateUaFObjectNonPagedPoolNx();

    return Status;
}


/// <summary>
/// Use UaF Object NonPagedPoolNx Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
UseUaFObjectNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IrpSp);
    PAGED_CODE();

    Status = UseUaFObjectNonPagedPoolNx();

    return Status;
}


/// <summary>
/// Free UaF Object NonPagedPoolNx Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
FreeUaFObjectNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IrpSp);
    PAGED_CODE();

    Status = FreeUaFObjectNonPagedPoolNx();

    return Status;
}


/// <summary>
/// Allocate Fake Object NonPagedPoolNx Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
AllocateFakeObjectNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PFAKE_OBJECT_NON_PAGED_POOL_NX UserFakeObject = NULL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    UserFakeObject = (PFAKE_OBJECT_NON_PAGED_POOL_NX)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (UserFakeObject)
    {
        Status = AllocateFakeObjectNonPagedPoolNx(UserFakeObject);
    }

    return Status;
}
