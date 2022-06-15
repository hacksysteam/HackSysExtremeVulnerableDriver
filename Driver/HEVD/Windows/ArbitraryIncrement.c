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
    ArbitraryIncrement.c

Abstract:
    This module implements the functions to demonstrate
    Arbitrary Increment vulnerability.

--*/

#include "ArbitraryIncrement.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, TriggerArbitraryIncrement)
#pragma alloc_text(PAGE, ArbitraryIncrementIoctlHandler)
#endif // ALLOC_PRAGMA


/// <summary>
/// Trigger the Arbitrary Increment Vulnerability
/// </summary>
/// <param name="UserBuffer">The pointer to user mode buffer</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
TriggerArbitraryIncrement(
    _In_ PVOID UserBuffer
)
{
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    __try
    {
        //
        // Verify if the buffer resides in user mode
        //

        ProbeForRead(UserBuffer, sizeof(PULONG_PTR), (ULONG)__alignof(PULONG_PTR));

        //
        // Grab the user pointer
        //

        PCHAR UserPointerToIncrementValue = *(PCHAR*)UserBuffer;

        DbgPrint("[+] UserBuffer: 0x%p\n", UserBuffer);
        DbgPrint("[+] UserPointerToIncrementValue: 0x%p\n", UserPointerToIncrementValue);
        DbgPrint("[+] Value before increment: 0x%zX\n", *UserPointerToIncrementValue);

#ifdef SECURE

        //
        // Secure Note: This is secure because the developer is properly validating if 
        // 'UserPointerToIncrementValue' resides in User mode by calling ProbeForWrite() routine before
        // performing the increment operation
        //

        ProbeForWrite(UserPointerToIncrementValue, sizeof(PCHAR), (ULONG)__alignof(CHAR));

        (*(PCHAR)UserPointerToIncrementValue)++;
#else
        DbgPrint("[+] Triggering Arbitrary Increment\n");

        //
        // Vulnerability Note: This is a vanilla Arbitrary Increment vulnerability
        // because the developer is incrementing value pointed by 'UserPointerToIncrementValue'
        // without properly validating if it resides in User mode
        //

        (*(PCHAR)UserPointerToIncrementValue)++;
#endif

        DbgPrint("[+] Value after increment: 0x%zX\n", *UserPointerToIncrementValue);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}


/// <summary>
/// Arbitrary Increment Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
ArbitraryIncrementIoctlHandler(
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
        Status = TriggerArbitraryIncrement(UserBuffer);
    }

    return Status;
}
