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
    UninitializedMemoryStack.c

Abstract:
    This module implements the functions to demonstrate
    use of uninitialized memory in Stack vulnerability.

--*/

#include "UninitializedMemoryStack.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, TriggerUninitializedMemoryStack)
#pragma alloc_text(PAGE, UninitializedMemoryStackIoctlHandler)
#pragma alloc_text(PAGE, UninitializedMemoryStackObjectCallback)
#endif // ALLOC_PRAGMA


/// <summary>
/// Uninitialized Memory Stack Object Callback
/// </summary>
VOID
UninitializedMemoryStackObjectCallback(
    VOID
)
{
    PAGED_CODE();

    DbgPrint("[+] Uninitialized Memory Stack Object Callback\n");
}


/// <summary>
/// Trigger the uninitialized memory in Stack Vulnerability
/// </summary>
/// <param name="UserBuffer">The pointer to user mode buffer</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
TriggerUninitializedMemoryStack(
    _In_ PVOID UserBuffer
)
{
    ULONG UserValue = 0;
    ULONG MagicValue = 0xBAD0B0B0;
    NTSTATUS Status = STATUS_SUCCESS;

#ifdef SECURE
    //
    // Secure Note: This is secure because the developer is properly initializing
    // UNINITIALIZED_MEMORY_STACK to NULL and checks for NULL pointer before calling
    // the callback
    //

    UNINITIALIZED_MEMORY_STACK UninitializedMemory = { 0 };
#else
    //
    // Vulnerability Note: This is a vanilla Uninitialized Memory in Stack vulnerability
    // because the developer is not initializing 'UNINITIALIZED_MEMORY_STACK' structure
    // before calling the callback when 'MagicValue' does not match 'UserValue'
    //

    UNINITIALIZED_MEMORY_STACK UninitializedMemory;
#endif

    PAGED_CODE();

    __try
    {
        //
        // Verify if the buffer resides in user mode
        //

        ProbeForRead(UserBuffer, sizeof(UNINITIALIZED_MEMORY_STACK), (ULONG)__alignof(UCHAR));

        //
        // Get the value from user mode
        //

        UserValue = *(PULONG)UserBuffer;

        DbgPrint("[+] UserValue: 0x%p\n", UserValue);
        DbgPrint("[+] UninitializedMemory Address: 0x%p\n", &UninitializedMemory);

        //
        // Validate the magic value
        //

        if (UserValue == MagicValue) {
            UninitializedMemory.Value = UserValue;
            UninitializedMemory.Callback = &UninitializedMemoryStackObjectCallback;
        }

        DbgPrint("[+] UninitializedMemory.Value: 0x%p\n", UninitializedMemory.Value);
        DbgPrint("[+] UninitializedMemory.Callback: 0x%p\n", UninitializedMemory.Callback);

#ifndef SECURE
        DbgPrint("[+] Triggering Uninitialized Memory in Stack\n");
#endif

        //
        // Call the callback function
        //

        if (UninitializedMemory.Callback)
        {
            UninitializedMemory.Callback();
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
/// Uninitialized Memory Stack Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
UninitializedMemoryStackIoctlHandler(
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
        Status = TriggerUninitializedMemoryStack(UserBuffer);
    }

    return Status;
}
