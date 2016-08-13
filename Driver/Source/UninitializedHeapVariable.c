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
    UninitializedHeapVariable.c

Abstract:
    This module implements the functions to demonstrate
    use of Uninitialized Heap Variable vulnerability.

--*/

#include "UninitializedHeapVariable.h"

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, TriggerUninitializedHeapVariable)
    #pragma alloc_text(PAGE, UninitializedHeapVariableIoctlHandler)
    #pragma alloc_text(PAGE, UninitializedHeapVariableObjectCallback)
#endif // ALLOC_PRAGMA

#pragma auto_inline(off)

/// <summary>
/// Uninitialized Heap Variable Object Callback
/// </summary>
VOID UninitializedHeapVariableObjectCallback() {
    PAGED_CODE();

    DbgPrint("[+] Uninitialized Heap Variable Object Callback\n");
}

/// <summary>
/// Trigger the Uninitialized Heap Variable Vulnerability
/// </summary>
/// <param name="UserBuffer">The pointer to user mode buffer</param>
/// <returns>NTSTATUS</returns>
NTSTATUS TriggerUninitializedHeapVariable(IN PVOID UserBuffer) {
    ULONG UserValue = 0;
    ULONG MagicValue = 0xBAD0B0B0;
    NTSTATUS Status = STATUS_SUCCESS;
    PUNINITIALIZED_HEAP_VARIABLE UninitializedHeapVariable = NULL;

    PAGED_CODE();

    __try {
        // Verify if the buffer resides in user mode
        ProbeForRead(UserBuffer,
                     sizeof(UNINITIALIZED_HEAP_VARIABLE),
                     (ULONG)__alignof(UNINITIALIZED_HEAP_VARIABLE));

        // Allocate Pool chunk
        UninitializedHeapVariable = (PUNINITIALIZED_HEAP_VARIABLE)
                                     ExAllocatePoolWithTag(PagedPool,
                                                           sizeof(UNINITIALIZED_HEAP_VARIABLE),
                                                           (ULONG)POOL_TAG);

        if (!UninitializedHeapVariable) {
            // Unable to allocate Pool chunk
            DbgPrint("[-] Unable to allocate Pool chunk\n");

            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else {
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%X\n", sizeof(UNINITIALIZED_HEAP_VARIABLE));
            DbgPrint("[+] Pool Chunk: 0x%p\n", UninitializedHeapVariable);
        }

        // Get the value from user mode
        UserValue = *(PULONG)UserBuffer;

        DbgPrint("[+] UserValue: 0x%p\n", UserValue);
        DbgPrint("[+] UninitializedHeapVariable Address: 0x%p\n", &UninitializedHeapVariable);

        // Validate the magic value
        if (UserValue == MagicValue) {
            UninitializedHeapVariable->Value = UserValue;
            UninitializedHeapVariable->Callback = &UninitializedHeapVariableObjectCallback;

            // Fill the buffer with ASCII 'A'
            RtlFillMemory((PVOID)UninitializedHeapVariable->Buffer, sizeof(UninitializedHeapVariable->Buffer), 0x41);

            // Null terminate the char buffer
            UninitializedHeapVariable->Buffer[(sizeof(UninitializedHeapVariable->Buffer) / sizeof(ULONG)) - 1] = '\0';
        }
#ifdef SECURE
        else {
            DbgPrint("[+] Freeing UninitializedHeapVariable Object\n");
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Chunk: 0x%p\n", UninitializedHeapVariable);

            // Free the allocated Pool chunk
            ExFreePoolWithTag((PVOID)UninitializedHeapVariable, (ULONG)POOL_TAG);

            // Secure Note: This is secure because the developer is setting 'UninitializedHeapVariable'
            // to NULL and checks for NULL pointer before calling the callback

            // Set to NULL to avoid dangling pointer
            UninitializedHeapVariable = NULL;
        }
#else
            // Vulnerability Note: This is a vanilla Uninitialized Heap Variable vulnerability
            // because the developer is not setting 'Value' & 'Callback' to definite known value
            // before calling the 'Callback'
            DbgPrint("[+] Triggering Uninitialized Heap Variable Vulnerability\n");
#endif

        // Call the callback function
        if (UninitializedHeapVariable) {
            DbgPrint("[+] UninitializedHeapVariable->Value: 0x%p\n", UninitializedHeapVariable->Value);
            DbgPrint("[+] UninitializedHeapVariable->Callback: 0x%p\n", UninitializedHeapVariable->Callback);

            UninitializedHeapVariable->Callback();
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}

/// <summary>
/// Uninitialized Heap Variable Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS UninitializedHeapVariableIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp) {
    PVOID UserBuffer = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    UserBuffer = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (UserBuffer) {
        Status = TriggerUninitializedHeapVariable(UserBuffer);
    }

    return Status;
}

#pragma auto_inline()
