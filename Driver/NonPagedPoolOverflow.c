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
    NonPagedPoolOverflow.c

Abstract:
    This module implements the functions to demonstrate
    buffer overflow vulnerability in Non-Paged Pool.

--*/

#include "NonPagedPoolOverflow.h"

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, TriggerNonPagedPoolOverflow)
    #pragma alloc_text(PAGE, NonPagedPoolOverflowIoctlHandler)
#endif // ALLOC_PRAGMA

#pragma auto_inline(off)

/// <summary>
/// Trigger the Non-Paged Pool Overflow Vulnerability
/// </summary>
/// <param name="UserBuffer">The pointer to user mode buffer</param>
/// <param name="Size">Size of the user mode buffer</param>
/// <returns>NTSTATUS</returns>
NTSTATUS TriggerNonPagedPoolOverflow(IN PVOID UserBuffer, IN SIZE_T Size) {
    PVOID KernelBuffer = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    __try {
        DbgPrint("[+] Allocating Pool chunk\n");

        // Allocate Pool chunk
        KernelBuffer = ExAllocatePoolWithTag(NonPagedPool,
                                             (SIZE_T)POOL_BUFFER_SIZE,
                                             (ULONG)POOL_TAG);

        if (!KernelBuffer) {
            // Unable to allocate Pool chunk
            DbgPrint("[-] Unable to allocate Pool chunk\n");

            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else {
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%X\n", (SIZE_T)POOL_BUFFER_SIZE);
            DbgPrint("[+] Pool Chunk: 0x%p\n", KernelBuffer);
        }

        // Verify if the buffer resides in user mode
        ProbeForRead(UserBuffer, (SIZE_T)POOL_BUFFER_SIZE, (ULONG)__alignof(UCHAR));

        DbgPrint("[+] UserBuffer: 0x%p\n", UserBuffer);
        DbgPrint("[+] UserBuffer Size: 0x%X\n", Size);
        DbgPrint("[+] KernelBuffer: 0x%p\n", KernelBuffer);
        DbgPrint("[+] KernelBuffer Size: 0x%X\n", (SIZE_T)POOL_BUFFER_SIZE);

#ifdef SECURE
        // Secure Note: This is secure because the developer is passing a size
        // equal to size of the allocated pool chunk to RtlCopyMemory()/memcpy().
        // Hence, there will be no overflow
        RtlCopyMemory(KernelBuffer, UserBuffer, (SIZE_T)POOL_BUFFER_SIZE);
#else
        DbgPrint("[+] Triggering Non Paged Pool Overflow\n");

        // Vulnerability Note: This is a vanilla pool buffer overflow vulnerability
        // because the developer is passing the user supplied value directly to
        // RtlCopyMemory()/memcpy() without validating if the size is greater or
        // equal to the size of the allocated Pool chunk
        RtlCopyMemory(KernelBuffer, UserBuffer, Size);
#endif

        if (KernelBuffer) {
            DbgPrint("[+] Freeing Pool chunk\n");
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Chunk: 0x%p\n", KernelBuffer);

            // Free the allocated Pool chunk
            ExFreePoolWithTag(KernelBuffer, (ULONG)POOL_TAG);
            KernelBuffer = NULL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}

/// <summary>
/// Non-Paged Pool Overflow Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS NonPagedPoolOverflowIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp) {
    SIZE_T Size = 0;
    PVOID UserBuffer = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    UserBuffer = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
    Size = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

    if (UserBuffer) {
        Status = TriggerNonPagedPoolOverflow(UserBuffer, Size);
    }

    return Status;
}

#pragma auto_inline()
