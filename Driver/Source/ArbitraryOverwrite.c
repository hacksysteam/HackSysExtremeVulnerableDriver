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
/// <param name="pUserModeWriteWhatWhere">The pointer to WRITE_WHAT_WHERE structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS TriggerArbitraryOverwrite(IN PWRITE_WHAT_WHERE pUserModeWriteWhatWhere) {
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    __try {
        // Verify if the buffer resides in User Mode
        ProbeForRead((PVOID)pUserModeWriteWhatWhere,
                     sizeof(WRITE_WHAT_WHERE),
                     (ULONG)__alignof(WRITE_WHAT_WHERE));

        DbgPrint("[+] pUserModeWriteWhatWhere: 0x%p\n", pUserModeWriteWhatWhere);
        DbgPrint("[+] Size Of WRITE_WHAT_WHERE: 0x%X\n", sizeof(WRITE_WHAT_WHERE));
        DbgPrint("[+] pUserModeWriteWhatWhere->What: 0x%p\n", pUserModeWriteWhatWhere->What);
        DbgPrint("[+] pUserModeWriteWhatWhere->Where: 0x%p\n", pUserModeWriteWhatWhere->Where);

        #ifdef SECURE
            // Secure Note: This is secure because the developer is properly validating if address 
            // pointed by 'Where' and 'What' value resides in User mode by calling ProbeForRead() 
            // routine before performing the write operation
            ProbeForRead((PVOID)pUserModeWriteWhatWhere->Where,
                         sizeof(PULONG),
                         (ULONG)__alignof(PULONG));
            ProbeForRead((PVOID)pUserModeWriteWhatWhere->What,
                         sizeof(PULONG),
                         (ULONG)__alignof(PULONG));

            *(pUserModeWriteWhatWhere->Where) = *(pUserModeWriteWhatWhere->What);
        #else
            DbgPrint("[+] Triggering Arbitrary Overwrite\n");

            // Vulnerability Note: This is a vanilla Arbitrary Memory Overwrite vulnerability 
            // because the developer is writing value pointed by 'What' to a memory location 
            // pointed by 'Where' without properly validating if the values pointed by 'Where' 
            // and 'What' resides in User mode before performing the write operation
            *(pUserModeWriteWhatWhere->Where) = *(pUserModeWriteWhatWhere->What);
        #endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", status);
    }

    return status;
}

/// <summary>
/// Arbitrary Overwrite Ioctl Handler
/// </summary>
/// <param name="pIrp">The pointer to IRP</param>
/// <param name="pIoStackIrp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS ArbitraryOverwriteIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PWRITE_WHAT_WHERE pUserModeWriteWhatWhere = NULL;

    UNREFERENCED_PARAMETER(pIrp);
    PAGED_CODE();

    pUserModeWriteWhatWhere = (PWRITE_WHAT_WHERE)
                               pIoStackIrp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (pUserModeWriteWhatWhere) {
        status = TriggerArbitraryOverwrite(pUserModeWriteWhatWhere);
    }

    return status;
}

#pragma auto_inline()
