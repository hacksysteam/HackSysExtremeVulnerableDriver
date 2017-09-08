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
    InsecureKernelResourceAccess.c

Abstract:
    This module implements the functions to demonstrate
    Insecure Kernel Resource Access vulnerability.

References:
    https://github.com/tyranid/windows-logical-eop-workshop

--*/

#include "InsecureKernelResourceAccess.h"

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, TriggerInsecureKernelFileAccess)
    #pragma alloc_text(PAGE, InsecureKernelFileAccessIoctlHandler)
#endif // ALLOC_PRAGMA

#pragma auto_inline(off)

/// <summary>
/// Trigger the Insecure Kernel File Access Vulnerability
/// </summary>
/// <returns>NTSTATUS</returns>
NTSTATUS TriggerInsecureKernelFileAccess() {
    HANDLE FileHandle = NULL;
    UNICODE_STRING Log = { 0 };
    IO_STATUS_BLOCK IoStatus = { 0 };
    NTSTATUS Status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttribures = { 0 };
    PCWSTR LogPath = L"\\??\\C:\\Windows\\System32\\HEVD.log";
    UCHAR Message[] = "HackSys Extreme Vulnerable Driver Log";
    ULONG AttributeFlags = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
    ULONG CreateOptions = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;

#ifdef SECURE
    AttributeFlags |= OBJ_FORCE_ACCESS_CHECK;
#endif

    PAGED_CODE();

    __try {
        RtlInitUnicodeString(&Log, LogPath);
        InitializeObjectAttributes(&ObjectAttribures, &Log, AttributeFlags, NULL, NULL);

        DbgPrint("[+] Log Path: %ws\n", LogPath);
        DbgPrint("[+] Log Content: %s\n", Message);

#ifndef SECURE
        DbgPrint("[+] Triggering Insecure Kernel File Access\n");
#endif

        Status = ZwCreateFile(&FileHandle,
                              MAXIMUM_ALLOWED,
                              &ObjectAttribures,
                              &IoStatus,
                              NULL,
                              FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_READ | FILE_SHARE_DELETE,
                              FILE_OPEN_IF,
                              CreateOptions,
                              NULL,
                              0);

        if (NT_SUCCESS(Status)) {
            ZwWriteFile(FileHandle,
                        NULL,
                        NULL,
                        NULL,
                        &IoStatus,
                        &Message,
                        sizeof(Message),
                        NULL,
                        NULL);
        }

        if (FileHandle) {
            ZwClose(FileHandle);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}

/// <summary>
/// Insecure Kernel File Access Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS InsecureKernelFileAccessIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp) {
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IrpSp);
    PAGED_CODE();

    Status = TriggerInsecureKernelFileAccess();

    return Status;
}

#pragma auto_inline()
