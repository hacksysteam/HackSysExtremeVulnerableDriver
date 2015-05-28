/*++

 /$$   /$$                     /$$        /$$$$$$                     
| $$  | $$                    | $$       /$$__  $$                    
| $$  | $$  /$$$$$$   /$$$$$$$| $$   /$$| $$  \__/ /$$   /$$  /$$$$$$$
| $$$$$$$$ |____  $$ /$$_____/| $$  /$$/|  $$$$$$ | $$  | $$ /$$_____/
| $$__  $$  /$$$$$$$| $$      | $$$$$$/  \____  $$| $$  | $$|  $$$$$$ 
| $$  | $$ /$$__  $$| $$      | $$_  $$  /$$  \ $$| $$  | $$ \____  $$
| $$  | $$|  $$$$$$$|  $$$$$$$| $$ \  $$|  $$$$$$/|  $$$$$$$ /$$$$$$$/
|__/  |__/ \_______/ \_______/|__/  \__/ \______/  \____  $$|_______/ 
                                                   /$$  | $$          
                                                  |  $$$$$$/          
                                                   \______/           


Copyright (C) 2010-2015 HackSys Team. All rights reserved.

This file is part of HackSys Extreme Vulnerable Driver.

See the file 'LICENSE' for copying permission.

Author : Ashfaq Ansari
Contact: ashfaq_ansari1989[at]hotmail.com
Website: http://hacksys.vfreaks.com

Project Name:
    HackSys Extreme Vulnerable Driver

Module Name:
    StackOverflowGS.c

Abstract:
    This module implements the functions to demonstrate
    Stack Guard bypass scenario.

--*/

#include "StackOverflowGS.h"

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, TriggerStackOverflowGS)
    #pragma alloc_text(PAGE, StackOverflowGSIoctlHandler)
#endif // ALLOC_PRAGMA

#pragma auto_inline(off)

/// <summary>
/// Trigger the Stack Overflow Protected by GS Cookie
/// </summary>
/// <param name="pUserModeBuffer">The pointer to user mode buffer</param>
/// <param name="userModeBufferSize">Size of the user mode buffer</param>
/// <returns>NTSTATUS</returns>
NTSTATUS TriggerStackOverflowGS(IN PVOID pUserModeBuffer, IN SIZE_T userModeBufferSize) {
    NTSTATUS status = STATUS_SUCCESS;
    UCHAR kernelBuffer[BUFFER_SIZE] = {0};

    PAGED_CODE();

    __try {
        DbgPrint("[+] kernelBuffer: 0x%p\n", &kernelBuffer);
        DbgPrint("[+] kernelBuffer Size: 0x%X\n", sizeof(kernelBuffer));

        // Verify if the buffer resides in User Mode
        ProbeForRead(pUserModeBuffer, sizeof(kernelBuffer), (ULONG)__alignof(kernelBuffer));

        DbgPrint("[+] pUserModeBuffer: 0x%p\n", pUserModeBuffer);
        DbgPrint("[+] userModeBufferSize: 0x%X\n", userModeBufferSize);

        #ifdef SECURE
            // Secure Note: This is secure because the developer is passing a size 
            // equal to size of the allocated Pool memory to RtlCopyMemory()/memcpy() 
            // so, there will be no overflow
            RtlCopyMemory((PVOID)kernelBuffer, pUserModeBuffer, sizeof(kernelBuffer));
        #else
            DbgPrint("[+] Triggering Stack Overflow (GS)\n");

            // Vulnerability Note: This is a vanilla Stack Based Overflow vulnerability 
            // because the developer is passing the user supplied value directly to 
            // RtlCopyMemory()/memcpy() without validating if the size is greater or 
            // equal to the size allocated for it in on the stack
            RtlCopyMemory((PVOID)kernelBuffer, pUserModeBuffer, userModeBufferSize);
        #endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", status);
    }

    return status;
}

/// <summary>
/// Stack Overflow GS Ioctl Handler
/// </summary>
/// <param name="pIrp">The pointer to IRP</param>
/// <param name="pIoStackIrp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS StackOverflowGSIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp) {
    PVOID pUserModeBuffer = NULL;
    SIZE_T userModeBufferSize = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(pIrp);
    PAGED_CODE();

    pUserModeBuffer = pIoStackIrp->Parameters.DeviceIoControl.Type3InputBuffer;
    userModeBufferSize = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;

    if (pUserModeBuffer) {
        status = TriggerStackOverflowGS(pUserModeBuffer, userModeBufferSize);
    }

    return status;
}

#pragma auto_inline()
