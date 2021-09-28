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
    DoubleFetch.c

Abstract:
    This module implements the functions to demonstrate
    double fetch vulnerability.

--*/

#include "DoubleFetch.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, TriggerDoubleFetch)
#pragma alloc_text(PAGE, DoubleFetchIoctlHandler)
#endif // ALLOC_PRAGMA


/// <summary>
/// Trigger the Double Fetch Vulnerability
/// </summary>
/// <param name="UserDoubleFetch">The pointer to user mode buffer</param>
/// <returns>NTSTATUS</returns>
__declspec(safebuffers)
NTSTATUS
TriggerDoubleFetch(
    _In_ PDOUBLE_FETCH UserDoubleFetch
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG KernelBuffer[BUFFER_SIZE] = { 0 };

#ifdef SECURE
    PVOID UserBuffer = NULL;
    SIZE_T UserBufferSize = 0;
#endif

    PAGED_CODE();

    __try
    {
        //
        // Verify if the buffer resides in user mode
        //

        ProbeForRead(UserDoubleFetch, sizeof(DOUBLE_FETCH), (ULONG)__alignof(UCHAR));

        DbgPrint("[+] UserDoubleFetch: 0x%p\n", UserDoubleFetch);
        DbgPrint("[+] KernelBuffer: 0x%p\n", &KernelBuffer);
        DbgPrint("[+] KernelBuffer Size: 0x%X\n", sizeof(KernelBuffer));

#ifdef SECURE
        UserBuffer = UserDoubleFetch->Buffer;
        UserBufferSize = UserDoubleFetch->Size;

        DbgPrint("[+] UserDoubleFetch->Buffer: 0x%p\n", UserBuffer);
        DbgPrint("[+] UserDoubleFetch->Size: 0x%X\n", UserBufferSize);

        if (UserBufferSize > sizeof(KernelBuffer))
        {
            DbgPrint("[-] Invalid Buffer Size: 0x%X\n", UserBufferSize);

            Status = STATUS_INVALID_PARAMETER;
            return Status;
        }

        //
        // Secure Note: This is secure because the developer is fetching
        // 'UserDoubleFetch->Buffer' and 'UserDoubleFetch->Size' from user
        // mode just once and storing it in a temporary variable. Later, this
        // stored values are passed to RtlCopyMemory()/memcpy(). Hence, there
        // will be no race condition
        //

        RtlCopyMemory((PVOID)KernelBuffer, UserBuffer, UserBufferSize);
#else
        DbgPrint("[+] UserDoubleFetch->Buffer: 0x%p\n", UserDoubleFetch->Buffer);
        DbgPrint("[+] UserDoubleFetch->Size: 0x%X\n", UserDoubleFetch->Size);

        if (UserDoubleFetch->Size > sizeof(KernelBuffer))
        {
            DbgPrint("[-] Invalid Buffer Size: 0x%X\n", UserDoubleFetch->Size);

            Status = STATUS_INVALID_PARAMETER;
            return Status;
        }

        DbgPrint("[+] Triggering Double Fetch\n");

        //
        // Vulnerability Note: This is a vanilla Double Fetch vulnerability because the
        // developer is fetching 'UserDoubleFetch->Buffer' and 'UserDoubleFetch->Size'
        // from user mode twice and the double fetched values are passed to RtlCopyMemory()/memcpy().
        // This creates a race condition and the size check could be bypassed which will later
        // cause stack based buffer overflow
        //

        RtlCopyMemory((PVOID)KernelBuffer, UserDoubleFetch->Buffer, UserDoubleFetch->Size);
#endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}


/// <summary>
/// Double Fetch Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
DoubleFetchIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    PDOUBLE_FETCH UserDoubleFetch = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    UserDoubleFetch = (PDOUBLE_FETCH)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (UserDoubleFetch)
    {
        Status = TriggerDoubleFetch(UserDoubleFetch);
    }

    return Status;
}
