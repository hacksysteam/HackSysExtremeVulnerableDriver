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
    UninitializedMemoryPagedPool.c

Abstract:
    This module implements the functions to demonstrate
    use of uninitialized memory in PagedPool vulnerability.

--*/

#include "UninitializedMemoryPagedPool.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, TriggerUninitializedMemoryPagedPool)
#pragma alloc_text(PAGE, UninitializedMemoryPagedPoolIoctlHandler)
#pragma alloc_text(PAGE, UninitializedMemoryPagedPoolObjectCallback)
#endif // ALLOC_PRAGMA


/// <summary>
/// Uninitialized Memory PagedPool Object Callback
/// </summary>
VOID
UninitializedMemoryPagedPoolObjectCallback(
    VOID
)
{
    PAGED_CODE();

    DbgPrint("[+] Uninitialized Memory PagedPool Object Callback\n");
}


/// <summary>
/// Trigger the uninitialized memory in PagedPool Vulnerability
/// </summary>
/// <param name="UserBuffer">The pointer to user mode buffer</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
TriggerUninitializedMemoryPagedPool(
    _In_ PVOID UserBuffer
)
{
    ULONG_PTR UserValue = 0;
    ULONG_PTR MagicValue = 0xBAD0B0B0;
    NTSTATUS Status = STATUS_SUCCESS;
    PUNINITIALIZED_MEMORY_POOL UninitializedMemory = NULL;

    PAGED_CODE();

    __try
    {
        //
        // Verify if the buffer resides in user mode
        //

        ProbeForRead(UserBuffer, sizeof(UNINITIALIZED_MEMORY_POOL), (ULONG)__alignof(UCHAR));

        //
        // Allocate Pool chunk
        //

        UninitializedMemory = (PUNINITIALIZED_MEMORY_POOL)ExAllocatePoolWithTag(
            PagedPool,
            sizeof(UNINITIALIZED_MEMORY_POOL),
            (ULONG)POOL_TAG
        );

        if (!UninitializedMemory)
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
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(PagedPool));
            DbgPrint("[+] Pool Size: 0x%zX\n", sizeof(UNINITIALIZED_MEMORY_POOL));
            DbgPrint("[+] Pool Chunk: 0x%p\n", UninitializedMemory);
        }

        //
        // Get the value from user mode
        //

        UserValue = *(PULONG_PTR)UserBuffer;

        DbgPrint("[+] UserValue: 0x%p\n", UserValue);
        DbgPrint("[+] UninitializedMemory Address: 0x%p\n", &UninitializedMemory);

        //
        // Validate the magic value
        //

        if (UserValue == MagicValue) {
            UninitializedMemory->Value = UserValue;
            UninitializedMemory->Callback = &UninitializedMemoryPagedPoolObjectCallback;

            //
            // Fill the buffer with ASCII 'A'
            //

            RtlFillMemory(
                (PVOID)UninitializedMemory->Buffer,
                sizeof(UninitializedMemory->Buffer),
                0x41
            );

            //
            // Null terminate the char buffer
            //

            UninitializedMemory->Buffer[(sizeof(UninitializedMemory->Buffer) / sizeof(ULONG_PTR)) - 1] = '\0';
        }
#ifdef SECURE
        else {
            DbgPrint("[+] Freeing UninitializedMemory Object\n");
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Chunk: 0x%p\n", UninitializedMemory);

            //
            // Free the allocated Pool chunk
            //

            ExFreePoolWithTag((PVOID)UninitializedMemory, (ULONG)POOL_TAG);

            //
            // Secure Note: This is secure because the developer is setting 'UninitializedMemory'
            // to NULL and checks for NULL pointer before calling the callback
            //

            //
            // Set to NULL to avoid dangling pointer
            //

            UninitializedMemory = NULL;
        }
#else
        //
        // Vulnerability Note: This is a vanilla Uninitialized Heap Variable vulnerability
        // because the developer is not setting 'Value' & 'Callback' to definite known value
        // before calling the 'Callback'
        //

        DbgPrint("[+] Triggering Uninitialized Memory in PagedPool\n");
#endif

        //
        // Call the callback function
        //

        if (UninitializedMemory)
        {
            DbgPrint("[+] UninitializedMemory->Value: 0x%p\n", UninitializedMemory->Value);
            DbgPrint("[+] UninitializedMemory->Callback: 0x%p\n", UninitializedMemory->Callback);

            UninitializedMemory->Callback();
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
/// Uninitialized Memory PagedPool Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
UninitializedMemoryPagedPoolIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    PVOID UserBuffer = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    UserBuffer = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (UserBuffer)
    {
        Status = TriggerUninitializedMemoryPagedPool(UserBuffer);
    }

    return Status;
}
