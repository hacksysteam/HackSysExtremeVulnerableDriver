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
Contact: ashfaq[at]hacksys[dot]io
Website: https://hacksys.io/

Copyright (C) 2021-2023 HackSys Inc. All rights reserved.
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
    IntegerOverflow.c

Abstract:
    This module implements the functions to demonstrate
    integer overflow (arithmetic overflow) vulnerability.

--*/

#include "IntegerOverflow.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, TriggerIntegerOverflow)
#pragma alloc_text(PAGE, IntegerOverflowIoctlHandler)
#endif // ALLOC_PRAGMA


/// <summary>
/// Trigger the Integer Overflow Vulnerability
/// </summary>
/// <param name="UserBuffer">The pointer to user mode buffer</param>
/// <param name="Size">Size of the user mode buffer</param>
/// <returns>NTSTATUS</returns>
__declspec(safebuffers)
NTSTATUS
TriggerIntegerOverflow(
    _In_ PVOID UserBuffer,
    _In_ ULONG Size
)
{
    ULONG Count = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG BufferTerminator = 0xBAD0B0B0;
    ULONG KernelBuffer[BUFFER_SIZE] = { 0 };
    ULONG TerminatorSize = sizeof(BufferTerminator);

    PAGED_CODE();

    __try
    {
        //
        // Verify if the buffer resides in user mode
        //

        ProbeForRead(UserBuffer, sizeof(KernelBuffer), (ULONG)__alignof(UCHAR));

        DbgPrint("[+] UserBuffer: 0x%p\n", UserBuffer);
        DbgPrint("[+] UserBuffer Size: 0x%X\n", Size);
        DbgPrint("[+] KernelBuffer: 0x%p\n", &KernelBuffer);
        DbgPrint("[+] KernelBuffer Size: 0x%zX\n", sizeof(KernelBuffer));

#ifdef SECURE
        //
        // Secure Note: This is secure because the developer is not doing any arithmetic
        // on the user supplied value. Instead, the developer is subtracting the size of
        // ULONG i.e. 4 on x86 from the size of KernelBuffer. Hence, integer overflow will
        // not occur and this check will not fail
        //

        if (Size > (sizeof(KernelBuffer) - TerminatorSize))
        {
            DbgPrint("[-] Invalid UserBuffer Size: 0x%X\n", Size);

            Status = STATUS_INVALID_BUFFER_SIZE;
            return Status;
        }
#else
        DbgPrint("[+] Triggering Integer Overflow (Arithmetic Overflow)\n");

        //
        // Vulnerability Note: This is a vanilla Integer Overflow vulnerability because if
        // 'Size' is 0xFFFFFFFF and we do an addition with size of ULONG i.e. 4 on x86, the
        // integer will wrap down and will finally cause this check to fail
        //

        if ((Size + TerminatorSize) > (ULONG)sizeof(KernelBuffer))
        {
            DbgPrint("[-] Invalid UserBuffer Size: 0x%X\n", Size);

            Status = STATUS_INVALID_BUFFER_SIZE;
            return Status;
        }
#endif

        //
        // Perform the copy operation
        //

        while (Count < (Size / sizeof(ULONG)))
        {
            if (*(PULONG)UserBuffer != BufferTerminator)
            {
                KernelBuffer[Count] = *(PULONG)UserBuffer;
                UserBuffer = (PULONG)UserBuffer + 1;
                Count++;
            }
            else
            {
                break;
            }
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
/// Integer Overflow Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
IntegerOverflowIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    PVOID UserBuffer = NULL;
    ULONG Size = 0;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    UserBuffer = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
    Size = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

    if (UserBuffer)
    {
        Status = TriggerIntegerOverflow(UserBuffer, Size);
    }

    return Status;
}
