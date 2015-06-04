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
    NullPointerDereference.c

Abstract:
    This module implements the functions to demonstrate
    Null Pointer Dereference vulnerability.

--*/

#include "NullPointerDereference.h"

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, TriggerNullPointerDereference)
    #pragma alloc_text(PAGE, NullPointerDereferenceIoctlHandler)
    #pragma alloc_text(PAGE, NullPointerDereferenceObjectCallback)
#endif // ALLOC_PRAGMA

#pragma auto_inline(off)

/// <summary>
/// Null Pointer Dereference Object Callback
/// </summary>
VOID NullPointerDereferenceObjectCallback() {
    PAGED_CODE();

    DbgPrint("[+] Null Pointer Dereference Object Callback called\n");
}

/// <summary>
/// Trigger the Null Pointer Dereference Vulnerability
/// </summary>
/// <param name="pUserModeBuffer">The pointer to user mode buffer</param>
/// <returns>NTSTATUS</returns>
NTSTATUS TriggerNullPointerDereference(IN PVOID pUserModeBuffer) {
    ULONG userValue = 0;
    ULONG magicValue = 0xBAD0B0B0;
    NTSTATUS status = STATUS_SUCCESS;
    PNULL_POINTER_DEREFERENCE pNullPointerDereference = NULL;

    PAGED_CODE();

    __try {
        // Verify if the buffer resides in User Mode
        ProbeForRead(pUserModeBuffer,
                     sizeof(NULL_POINTER_DEREFERENCE),
                     (ULONG)__alignof(NULL_POINTER_DEREFERENCE));

        // Allocate Pool Memory
        pNullPointerDereference = (PNULL_POINTER_DEREFERENCE)
                                   ExAllocatePoolWithTag(NonPagedPool,
                                                         sizeof(NULL_POINTER_DEREFERENCE),
                                                         (ULONG)POOL_TAG);

        if (!pNullPointerDereference) {
            // Unable to allocate Pool Memory with Tag
            DbgPrint("[-] Unable To Allocate Pool Memory\n");

            status = STATUS_NO_MEMORY;
            return status;
        }
        else {
            DbgPrint("[+] Pool Address: 0x%p\n", pNullPointerDereference);
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%X\n", sizeof(NULL_POINTER_DEREFERENCE));
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
        }

        // Get the value from user mode
        userValue = *(PULONG)pUserModeBuffer;

        DbgPrint("[+] userValue: 0x%p\n", userValue);
        DbgPrint("[+] pNullPointerDereference: 0x%p\n", pNullPointerDereference);

        // Validate the value
        if (userValue == magicValue) {
            pNullPointerDereference->value = userValue;
            pNullPointerDereference->pCallback = &NullPointerDereferenceObjectCallback;

            DbgPrint("[+] pNullPointerDereference->value: 0x%p\n", pNullPointerDereference->value);
            DbgPrint("[+] pNullPointerDereference->pCallback: 0x%p\n", pNullPointerDereference->pCallback);
        }
        else {
            DbgPrint("[+] Freeing pNullPointerDereference Object\n");
            DbgPrint("[+] Pool Address: 0x%p\n", pNullPointerDereference);
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));

            // Free the allocated Pool Memory
            ExFreePoolWithTag((PVOID)pNullPointerDereference, (ULONG)POOL_TAG);
            pNullPointerDereference = NULL;
        }

        #ifdef SECURE
            // Secure Note: This is secure because the developer is checking if 
            // 'pNullPointerDereference' is not NULL before calling the callback
            // function
            if (pNullPointerDereference) {
                pNullPointerDereference->pCallback();
            }
        #else
            DbgPrint("[+] Triggering Null Pointer Dereference\n");

            // Vulnerability Note: This is a vanilla Null Pointer Dereference vulnerability 
            // because the developer is not validating if 'pNullPointerDereference' is NULL 
            // before calling the callback function
            pNullPointerDereference->pCallback();
        #endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", status);
    }

    return status;
}

/// <summary>
/// Null Pointer Dereference Ioctl Handler
/// </summary>
/// <param name="pIrp">The pointer to IRP</param>
/// <param name="pIoStackIrp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS NullPointerDereferenceIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp) {
    PVOID pUserModeBuffer = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(pIrp);
    PAGED_CODE();

    pUserModeBuffer = pIoStackIrp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (pUserModeBuffer) {
        status = TriggerNullPointerDereference(pUserModeBuffer);
    }

    return status;
}

#pragma auto_inline()
