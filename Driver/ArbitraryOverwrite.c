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
    ArbitraryOverwrite.c

Abstract:
    This module implements the functions to demonstrate
    Arbitrary Memory Overwrite vulnerability.

--*/

#include "ArbitraryOverwrite.h"

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, TriggerArbitraryOverwrite)
    #pragma alloc_text(PAGE, ArbitraryOverwriteIoctlHandler)
#endif // ALLOC_PRAGMA

#pragma auto_inline(off)

/// <summary>
/// Trigger the Arbitrary Overwrite Vulnerability
/// </summary>
/// <param name="UserWriteWhatWhere">The pointer to WRITE_WHAT_WHERE structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS TriggerArbitraryOverwrite(IN PWRITE_WHAT_WHERE UserWriteWhatWhere) {
    PULONG_PTR What = NULL;
    PULONG_PTR Where = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    __try {
        // Verify if the buffer resides in user mode
        ProbeForRead((PVOID)UserWriteWhatWhere,
                     sizeof(WRITE_WHAT_WHERE),
                     (ULONG)__alignof(WRITE_WHAT_WHERE));

        What = UserWriteWhatWhere->What;
        Where = UserWriteWhatWhere->Where;

        DbgPrint("[+] UserWriteWhatWhere: 0x%p\n", UserWriteWhatWhere);
        DbgPrint("[+] WRITE_WHAT_WHERE Size: 0x%X\n", sizeof(WRITE_WHAT_WHERE));
        DbgPrint("[+] UserWriteWhatWhere->What: 0x%p\n", What);
        DbgPrint("[+] UserWriteWhatWhere->Where: 0x%p\n", Where);

#ifdef SECURE
        // Secure Note: This is secure because the developer is properly validating if address
        // pointed by 'Where' and 'What' value resides in User mode by calling ProbeForRead()
        // routine before performing the write operation
        ProbeForRead((PVOID)Where, sizeof(PULONG_PTR), (ULONG)__alignof(PULONG_PTR));
        ProbeForRead((PVOID)What, sizeof(PULONG_PTR), (ULONG)__alignof(PULONG_PTR));

        *(Where) = *(What);
#else
        DbgPrint("[+] Triggering Arbitrary Overwrite\n");

        // Vulnerability Note: This is a vanilla Arbitrary Memory Overwrite vulnerability
        // because the developer is writing the value pointed by 'What' to memory location
        // pointed by 'Where' without properly validating if the values pointed by 'Where'
        // and 'What' resides in User mode
        *(Where) = *(What);
#endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}

/// <summary>
/// Arbitrary Overwrite Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS ArbitraryOverwriteIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp) {
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PWRITE_WHAT_WHERE UserWriteWhatWhere = NULL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    UserWriteWhatWhere = (PWRITE_WHAT_WHERE)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (UserWriteWhatWhere) {
        Status = TriggerArbitraryOverwrite(UserWriteWhatWhere);
    }

    return Status;
}

#pragma auto_inline()
