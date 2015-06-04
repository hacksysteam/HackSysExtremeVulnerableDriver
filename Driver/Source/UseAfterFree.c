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

Copyright (C) 2011-2015 Payatu Technologies. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS
OR COPYRIGHT HOLDERS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
    #pragma alloc_text(PAGE, CreateUaFObject)
    #pragma alloc_text(PAGE, CreateFakeObject)
    #pragma alloc_text(PAGE, UaFObjectCallback)
    #pragma alloc_text(PAGE, UseUaFObjectIoctlHandler)
    #pragma alloc_text(PAGE, FreeUaFObjectIoctlHandler)
    #pragma alloc_text(PAGE, CreateUaFObjectIoctlHandler)
    #pragma alloc_text(PAGE, CreateFakeObjectIoctlHandler)
#endif // ALLOC_PRAGMA

#pragma auto_inline(off)

PUSE_AFTER_FREE g_UseAfterFreeObject = NULL;

/// <summary>
/// Use After Free Object Callback
/// </summary>
VOID UaFObjectCallback() {
    PAGED_CODE();

    DbgPrint("[+] UseAfter Free Callback called\n");
}

/// <summary>
/// Create and store the UaF object
/// </summary>
/// <returns>NTSTATUS</returns>
NTSTATUS CreateUaFObject() {
    NTSTATUS status = STATUS_SUCCESS;
    PUSE_AFTER_FREE pUseAfterFree = NULL;

    PAGED_CODE();

    __try {
        DbgPrint("[+] Creating UaF Object\n");

        // Allocate Pool Memory
        pUseAfterFree = (PUSE_AFTER_FREE)ExAllocatePoolWithTag(NonPagedPool,
                                                               sizeof(USE_AFTER_FREE),
                                                               (ULONG)POOL_TAG);

        if (!pUseAfterFree) {
            // Unable to allocate Pool Memory with Tag
            DbgPrint("[-] Unable To Allocate Pool Memory\n");

            status = STATUS_NO_MEMORY;
            return status;
        }
        else {
            DbgPrint("[+] Pool Address: 0x%p\n", pUseAfterFree);
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%X\n", sizeof(USE_AFTER_FREE));
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
        }

        // Fill the buffer with ASCII 'A'
        RtlFillMemory((PVOID)pUseAfterFree->buffer, sizeof(pUseAfterFree->buffer), 0x41);

        // Null terminate the char buffer
        pUseAfterFree->buffer[sizeof(pUseAfterFree->buffer) - 1] = '\0';

        // Set the Object Callback function
        pUseAfterFree->pCallback = &UaFObjectCallback;

        // Assign the address of pUseAfterFree to a global variable
        g_UseAfterFreeObject = pUseAfterFree;

        DbgPrint("[+] UaF Object: 0x%p\n", pUseAfterFree);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", status);
    }

    return status;
}

/// <summary>
/// Use the UaF object
/// </summary>
/// <returns>NTSTATUS</returns>
NTSTATUS UseUaFObject() {
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    PAGED_CODE();

    __try {
        if (g_UseAfterFreeObject) {
            DbgPrint("[+] Using UaF Object\n");
            DbgPrint("[+] g_UseAfterFreeObject: 0x%p\n", g_UseAfterFreeObject);
            DbgPrint("[+] g_UseAfterFreeObject->pCallback: 0x%p\n", g_UseAfterFreeObject->pCallback);
            DbgPrint("[+] Calling Callback\n");

            if (g_UseAfterFreeObject->pCallback) {
                g_UseAfterFreeObject->pCallback();
            }

            status = STATUS_SUCCESS;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", status);
    }

    return status;
}

/// <summary>
/// Free the UaF object
/// </summary>
/// <returns>NTSTATUS</returns>
NTSTATUS FreeUaFObject() {
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    PAGED_CODE();

    __try {
        if (g_UseAfterFreeObject) {
            DbgPrint("[+] Freeing UaF Object\n");
            DbgPrint("[+] Pool Address: 0x%p\n", g_UseAfterFreeObject);
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));

            #ifdef SECURE
                // Secure Note: This is secure because the developer is setting the 
                // 'pNullPointerDereference' to NULL
                ExFreePoolWithTag((PVOID)g_UseAfterFreeObject, (ULONG)POOL_TAG);

                g_UseAfterFreeObject = NULL;
            #else
                // Vulnerability Note: This is a vanilla Null Pointer Dereference vulnerability 
                // because the developer is not setting the 'pNullPointerDereference' to NULL
                ExFreePoolWithTag((PVOID)g_UseAfterFreeObject, (ULONG)POOL_TAG);
            #endif

            status = STATUS_SUCCESS;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", status);
    }

    return status;
}

/// <summary>
/// Create and store the Fake object
/// </summary>
/// <param name="pFakeObject">The pointer to user FAKE_OBJECT structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS CreateFakeObject(IN PFAKE_OBJECT pFakeObject) {
    NTSTATUS status = STATUS_SUCCESS;
    PFAKE_OBJECT pKernelFakeObject = NULL;

    PAGED_CODE();

    __try {
        DbgPrint("[+] Creating Fake Object\n");

        // Allocate Pool Memory
        pKernelFakeObject = (PFAKE_OBJECT)ExAllocatePoolWithTag(NonPagedPool,
                                                                sizeof(FAKE_OBJECT),
                                                                (ULONG)POOL_TAG);

        if (!pKernelFakeObject) {
            // Unable to allocate Pool Memory with Tag
            DbgPrint("[-] Unable To Allocate Pool Memory\n");

            status = STATUS_NO_MEMORY;
            return status;
        }
        else {
            DbgPrint("[+] Pool Address: 0x%p\n", pKernelFakeObject);
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%X\n", sizeof(FAKE_OBJECT));
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
        }

        // Verify if the buffer resides in User Mode
        ProbeForRead((PVOID)pFakeObject, sizeof(FAKE_OBJECT), (ULONG)__alignof(FAKE_OBJECT));

        // Copy the Fake structure to Pool memory
        RtlCopyMemory((PVOID)pKernelFakeObject, (PVOID)pFakeObject, sizeof(FAKE_OBJECT));

        // Null terminate the char buffer
        pKernelFakeObject->buffer[sizeof(pKernelFakeObject->buffer) - 1] = '\0';

        DbgPrint("[+] Fake Object: 0x%p\n", pKernelFakeObject);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", status);
    }

    return status;
}

/// <summary>
/// Create UaF Object Ioctl Handler
/// </summary>
/// <param name="pIrp">The pointer to IRP.</param>
/// <param name="pIoStackIrp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS CreateUaFObjectIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(pIrp);
    UNREFERENCED_PARAMETER(pIoStackIrp);
    PAGED_CODE();

    status = CreateUaFObject();

    return status;
}

/// <summary>
/// Use UaF Object Ioctl Handler
/// </summary>
/// <param name="pIrp">The pointer to IRP</param>
/// <param name="pIoStackIrp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS UseUaFObjectIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(pIrp);
    UNREFERENCED_PARAMETER(pIoStackIrp);
    PAGED_CODE();

    status = UseUaFObject();

    return status;
}

/// <summary>
/// Free UaF Object Ioctl Handler
/// </summary>
/// <param name="pIrp">The pointer to IRP</param>
/// <param name="pIoStackIrp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS FreeUaFObjectIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(pIrp);
    UNREFERENCED_PARAMETER(pIoStackIrp);
    PAGED_CODE();

    status = FreeUaFObject();

    return status;
}

/// <summary>
/// Create Fake Object Ioctl Handler
/// </summary>
/// <param name="pIrp">The pointer to IRP</param>
/// <param name="pIoStackIrp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS CreateFakeObjectIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp) {
    PFAKE_OBJECT pFakeObject = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(pIrp);
    PAGED_CODE();

    pFakeObject = (PFAKE_OBJECT)pIoStackIrp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (pFakeObject) {
        status = CreateFakeObject(pFakeObject);
    }

    return status;
}

#pragma auto_inline()
