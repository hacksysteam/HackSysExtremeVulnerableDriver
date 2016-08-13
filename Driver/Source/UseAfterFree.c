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
    UseAfterFree.c

Abstract:
    This module implements the functions to demonstrate
    Use After Free vulnerability.

--*/

#include "UseAfterFree.h"

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, UseUaFObject)
    #pragma alloc_text(PAGE, FreeUaFObject)
    #pragma alloc_text(PAGE, UaFObjectCallback)
    #pragma alloc_text(PAGE, AllocateUaFObject)
    #pragma alloc_text(PAGE, AllocateFakeObject)
    #pragma alloc_text(PAGE, UseUaFObjectIoctlHandler)
    #pragma alloc_text(PAGE, FreeUaFObjectIoctlHandler)
    #pragma alloc_text(PAGE, AllocateUaFObjectIoctlHandler)
    #pragma alloc_text(PAGE, AllocateFakeObjectIoctlHandler)
#endif // ALLOC_PRAGMA

#pragma auto_inline(off)

PUSE_AFTER_FREE g_UseAfterFreeObject = NULL;

/// <summary>
/// Use After Free Object Callback
/// </summary>
VOID UaFObjectCallback() {
    PAGED_CODE();

    DbgPrint("[+] UseAfter Free Object Callback\n");
}

/// <summary>
/// Allocate the UaF object
/// </summary>
/// <returns>NTSTATUS</returns>
NTSTATUS AllocateUaFObject() {
    NTSTATUS Status = STATUS_SUCCESS;
    PUSE_AFTER_FREE UseAfterFree = NULL;

    PAGED_CODE();

    __try {
        DbgPrint("[+] Allocating UaF Object\n");

        // Allocate Pool chunk
        UseAfterFree = (PUSE_AFTER_FREE)ExAllocatePoolWithTag(NonPagedPool,
                                                              sizeof(USE_AFTER_FREE),
                                                              (ULONG)POOL_TAG);

        if (!UseAfterFree) {
            // Unable to allocate Pool chunk
            DbgPrint("[-] Unable to allocate Pool chunk\n");

            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else {
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%X\n", sizeof(USE_AFTER_FREE));
            DbgPrint("[+] Pool Chunk: 0x%p\n", UseAfterFree);
        }

        // Fill the buffer with ASCII 'A'
        RtlFillMemory((PVOID)UseAfterFree->Buffer, sizeof(UseAfterFree->Buffer), 0x41);

        // Null terminate the char buffer
        UseAfterFree->Buffer[sizeof(UseAfterFree->Buffer) - 1] = '\0';

        // Set the object Callback function
        UseAfterFree->Callback = &UaFObjectCallback;

        // Assign the address of UseAfterFree to a global variable
        g_UseAfterFreeObject = UseAfterFree;

        DbgPrint("[+] UseAfterFree Object: 0x%p\n", UseAfterFree);
        DbgPrint("[+] g_UseAfterFreeObject: 0x%p\n", g_UseAfterFreeObject);
        DbgPrint("[+] UseAfterFree->Callback: 0x%p\n", UseAfterFree->Callback);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}

/// <summary>
/// Use the UaF object
/// </summary>
/// <returns>NTSTATUS</returns>
NTSTATUS UseUaFObject() {
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PAGED_CODE();

    __try {
        if (g_UseAfterFreeObject) {
            DbgPrint("[+] Using UaF Object\n");
            DbgPrint("[+] g_UseAfterFreeObject: 0x%p\n", g_UseAfterFreeObject);
            DbgPrint("[+] g_UseAfterFreeObject->Callback: 0x%p\n", g_UseAfterFreeObject->Callback);
            DbgPrint("[+] Calling Callback\n");

            if (g_UseAfterFreeObject->Callback) {
                g_UseAfterFreeObject->Callback();
            }

            Status = STATUS_SUCCESS;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}

/// <summary>
/// Free the UaF object
/// </summary>
/// <returns>NTSTATUS</returns>
NTSTATUS FreeUaFObject() {
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PAGED_CODE();

    __try {
        if (g_UseAfterFreeObject) {
            DbgPrint("[+] Freeing UaF Object\n");
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Chunk: 0x%p\n", g_UseAfterFreeObject);

#ifdef SECURE
            // Secure Note: This is secure because the developer is setting
            // 'g_UseAfterFreeObject' to NULL once the Pool chunk is being freed
            ExFreePoolWithTag((PVOID)g_UseAfterFreeObject, (ULONG)POOL_TAG);

            g_UseAfterFreeObject = NULL;
#else
            // Vulnerability Note: This is a vanilla Use After Free vulnerability
            // because the developer is not setting 'g_UseAfterFreeObject' to NULL.
            // Hence, g_UseAfterFreeObject still holds the reference to stale pointer
            // (dangling pointer)
            ExFreePoolWithTag((PVOID)g_UseAfterFreeObject, (ULONG)POOL_TAG);
#endif

            Status = STATUS_SUCCESS;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}

/// <summary>
/// Allocate the Fake object
/// </summary>
/// <param name="UserFakeObject">The pointer to FAKE_OBJECT structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS AllocateFakeObject(IN PFAKE_OBJECT UserFakeObject) {
    NTSTATUS Status = STATUS_SUCCESS;
    PFAKE_OBJECT KernelFakeObject = NULL;

    PAGED_CODE();

    __try {
        DbgPrint("[+] Creating Fake Object\n");

        // Allocate Pool chunk
        KernelFakeObject = (PFAKE_OBJECT)ExAllocatePoolWithTag(NonPagedPool,
                                                               sizeof(FAKE_OBJECT),
                                                               (ULONG)POOL_TAG);

        if (!KernelFakeObject) {
            // Unable to allocate Pool chunk
            DbgPrint("[-] Unable to allocate Pool chunk\n");

            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else {
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%X\n", sizeof(FAKE_OBJECT));
            DbgPrint("[+] Pool Chunk: 0x%p\n", KernelFakeObject);
        }

        // Verify if the buffer resides in user mode
        ProbeForRead((PVOID)UserFakeObject, sizeof(FAKE_OBJECT), (ULONG)__alignof(FAKE_OBJECT));

        // Copy the Fake structure to Pool chunk
        RtlCopyMemory((PVOID)KernelFakeObject, (PVOID)UserFakeObject, sizeof(FAKE_OBJECT));

        // Null terminate the char buffer
        KernelFakeObject->Buffer[sizeof(KernelFakeObject->Buffer) - 1] = '\0';

        DbgPrint("[+] Fake Object: 0x%p\n", KernelFakeObject);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}

/// <summary>
/// Allocate UaF Object Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP.</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS AllocateUaFObjectIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp) {
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IrpSp);
    PAGED_CODE();

    Status = AllocateUaFObject();

    return Status;
}

/// <summary>
/// Use UaF Object Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS UseUaFObjectIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp) {
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IrpSp);
    PAGED_CODE();

    Status = UseUaFObject();

    return Status;
}

/// <summary>
/// Free UaF Object Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS FreeUaFObjectIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp) {
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IrpSp);
    PAGED_CODE();

    Status = FreeUaFObject();

    return Status;
}

/// <summary>
/// Allocate Fake Object Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS AllocateFakeObjectIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp) {
    PFAKE_OBJECT UserFakeObject = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    UserFakeObject = (PFAKE_OBJECT)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (UserFakeObject) {
        Status = AllocateFakeObject(UserFakeObject);
    }

    return Status;
}

#pragma auto_inline()
