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
    NullPointerDereference.c

Abstract:
    This module implements the functions to demonstrate
    Null Pointer Dereference vulnerability.

--*/

#include "NullPointerDereference.h"

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, TriggerNullPointerDereference)
    #pragma alloc_text(PAGE, NullPointerDereferenceIoctlHandler)
    #pragma alloc_text(PAGE, NullPointerDereferenceObjectCallback)
#endif // ALLOC_PRAGMA

#pragma auto_inline(off)

/// <summary>
/// Null Pointer Dereference Object Callback
/// </summary>
VOID NullPointerDereferenceObjectCallback() {
    PAGED_CODE();

    DbgPrint("[+] Null Pointer Dereference Object Callback called\n");
}

/// <summary>
/// Trigger the Null Pointer Dereference Vulnerability
/// </summary>
/// <param name="pUserModeBuffer">The pointer to user mode buffer</param>
/// <returns>NTSTATUS</returns>
NTSTATUS TriggerNullPointerDereference(IN PVOID pUserModeBuffer) {
    ULONG userValue = 0;
    ULONG magicValue = 0xBAD0B0B0;
    NTSTATUS status = STATUS_SUCCESS;
    PNULL_POINTER_DEREFERENCE pNullPointerDereference = NULL;

    PAGED_CODE();

    __try {
        // Verify if the buffer resides in User Mode
        ProbeForRead(pUserModeBuffer,
                     sizeof(NULL_POINTER_DEREFERENCE),
                     (ULONG)__alignof(NULL_POINTER_DEREFERENCE));

        // Allocate Pool Memory
        pNullPointerDereference = (PNULL_POINTER_DEREFERENCE)
                                   ExAllocatePoolWithTag(NonPagedPool,
                                                         sizeof(NULL_POINTER_DEREFERENCE),
                                                         (ULONG)POOL_TAG);

        if (!pNullPointerDereference) {
            // Unable to allocate Pool Memory with Tag
            DbgPrint("[-] Unable To Allocate Pool Memory\n");

            status = STATUS_NO_MEMORY;
            return status;
        }
        else {
            DbgPrint("[+] Pool Address: 0x%p\n", pNullPointerDereference);
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%X\n", sizeof(NULL_POINTER_DEREFERENCE));
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
        }

        // Get the value from user mode
        userValue = *(PULONG)pUserModeBuffer;

        DbgPrint("[+] userValue: 0x%p\n", userValue);
        DbgPrint("[+] pNullPointerDereference: 0x%p\n", pNullPointerDereference);

        // Validate the value
        if (userValue == magicValue) {
            pNullPointerDereference->value = userValue;
            pNullPointerDereference->pCallback = &NullPointerDereferenceObjectCallback;

            DbgPrint("[+] pNullPointerDereference->value: 0x%p\n", pNullPointerDereference->value);
            DbgPrint("[+] pNullPointerDereference->pCallback: 0x%p\n", pNullPointerDereference->pCallback);
        }
        else {
            DbgPrint("[+] Freeing pNullPointerDereference Object\n");
            DbgPrint("[+] Pool Address: 0x%p\n", pNullPointerDereference);
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));

            // Free the allocated Pool Memory
            ExFreePoolWithTag((PVOID)pNullPointerDereference, (ULONG)POOL_TAG);
            pNullPointerDereference = NULL;
        }

        #ifdef SECURE
            // Secure Note: This is secure because the developer is checking if 
            // 'pNullPointerDereference' is not NULL before calling the callback
            // function
            if (pNullPointerDereference) {
                pNullPointerDereference->pCallback();
            }
        #else
            DbgPrint("[+] Triggering Null Pointer Dereference\n");

            // Vulnerability Note: This is a vanilla Null Pointer Dereference vulnerability 
            // because the developer is not validating if 'pNullPointerDereference' is NULL 
            // before calling the callback function
            pNullPointerDereference->pCallback();
        #endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", status);
    }

    return status;
}

/// <summary>
/// Null Pointer Dereference Ioctl Handler
/// </summary>
/// <param name="pIrp">The pointer to IRP</param>
/// <param name="pIoStackIrp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS NullPointerDereferenceIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp) {
    PVOID pUserModeBuffer = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(pIrp);
    PAGED_CODE();

    pUserModeBuffer = pIoStackIrp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (pUserModeBuffer) {
        status = TriggerNullPointerDereference(pUserModeBuffer);
    }

    return status;
}

#pragma auto_inline()
