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
    TypeConfusion.c

Abstract:
    This module implements the functions to demonstrate
    Type Confusion vulnerability.

--*/

#include "TypeConfusion.h"

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, TriggerTypeConfusion)
    #pragma alloc_text(PAGE, TypeConfusionIoctlHandler)
    #pragma alloc_text(PAGE, TypeConfusionObjectCallback)
    #pragma alloc_text(PAGE, TypeConfusionObjectInitializer)
#endif // ALLOC_PRAGMA

#pragma auto_inline(off)

/// <summary>
/// Type Confusion Object Callback
/// </summary>
VOID TypeConfusionObjectCallback() {
    PAGED_CODE();

    DbgPrint("[+] Type Confusion Object Callback called\n");
}

/// <summary>
/// Type Confusion Object Initializer
/// </summary>
/// <param name="pTypeConfusionKernelObject">The pointer to TYPE_CONFUSION_KERNEL_OBJECT object</param>
/// <returns>NTSTATUS</returns>
NTSTATUS TypeConfusionObjectInitializer(PTYPE_CONFUSION_KERNEL_OBJECT pTypeConfusionKernelObject) {
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    DbgPrint("[+] pTypeConfusionKernelObject->pCallback: 0x%p\n", pTypeConfusionKernelObject->pCallback);

    pTypeConfusionKernelObject->pCallback();

    DbgPrint("[+] Type Confusion Object Initialized\n");

    return status;
}

/// <summary>
/// Trigger the Type Confusion Vulnerability
/// </summary>
/// <param name="pTypeConfusionUserObject">The pointer to TYPE_CONFUSION_USER_OBJECT object</param>
/// <returns>NTSTATUS</returns>
NTSTATUS TriggerTypeConfusion(IN PTYPE_CONFUSION_USER_OBJECT pTypeConfusionUserObject) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PTYPE_CONFUSION_KERNEL_OBJECT pTypeConfusionKernelObject = NULL;

    PAGED_CODE();

    __try {
        // Verify if the buffer resides in User Mode
        ProbeForRead(pTypeConfusionUserObject,
                     sizeof(TYPE_CONFUSION_USER_OBJECT),
                     (ULONG)__alignof(TYPE_CONFUSION_USER_OBJECT));

        // Allocate Pool Memory
        pTypeConfusionKernelObject = (PTYPE_CONFUSION_KERNEL_OBJECT)
                                      ExAllocatePoolWithTag(NonPagedPool,
                                                            sizeof(TYPE_CONFUSION_KERNEL_OBJECT),
                                                            (ULONG)POOL_TAG);

        if (!pTypeConfusionKernelObject) {
            // Unable to allocate Pool Memory with Tag
            DbgPrint("[-] Unable To Allocate Pool Memory\n");

            status = STATUS_NO_MEMORY;
            return status;
        }
        else {
            DbgPrint("[+] Pool Address: 0x%p\n", pTypeConfusionKernelObject);
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%X\n", sizeof(TYPE_CONFUSION_KERNEL_OBJECT));
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
        }

        DbgPrint("[+] pTypeConfusionUserObject: 0x%p\n", pTypeConfusionUserObject);
        DbgPrint("[+] pTypeConfusionKernelObject: 0x%p\n", pTypeConfusionKernelObject);
        DbgPrint("[+] pTypeConfusionKernelObject Size: 0x%X\n", sizeof(TYPE_CONFUSION_KERNEL_OBJECT));

        pTypeConfusionKernelObject->objectID = pTypeConfusionUserObject->objectID;
        DbgPrint("[+] pTypeConfusionKernelObject->objectID: 0x%p\n", pTypeConfusionKernelObject->objectID);

        pTypeConfusionKernelObject->objectType = pTypeConfusionUserObject->objectType;
        DbgPrint("[+] pTypeConfusionKernelObject->objectType: 0x%p\n", pTypeConfusionKernelObject->objectType);

        #ifdef SECURE
            // Secure Note: This is secure because the developer is properly setting 'pCallback' 
            // member of the TYPE_CONFUSION_KERNEL_OBJECT structure before passing the pointer to 
            // itself to TypeConfusionObjectInitializer() function as parameter
            pTypeConfusionKernelObject->pCallback = &TypeConfusionObjectCallback;
            status = TypeConfusionObjectInitializer(pTypeConfusionKernelObject);
        #else
            DbgPrint("[+] Triggering Type Confusion\n");

            // Vulnerability Note: This is a vanilla Type Confusion vulnerability due to improper 
            // use of the UNION construct. The developer has not set the 'pCallback' member of the 
            // TYPE_CONFUSION_KERNEL_OBJECT structure before passing the pointer to itself to 
            // TypeConfusionObjectInitializer() function as parameter
            status = TypeConfusionObjectInitializer(pTypeConfusionKernelObject);
        #endif

        DbgPrint("[+] Freeing pTypeConfusionKernelObject Object\n");
        DbgPrint("[+] Pool Address: 0x%p\n", pTypeConfusionKernelObject);
        DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));

        // Free the allocated Pool Memory
        ExFreePoolWithTag((PVOID)pTypeConfusionKernelObject, (ULONG)POOL_TAG);
        pTypeConfusionKernelObject = NULL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", status);
    }

    return status;
}

/// <summary>
/// Type Confusion Ioctl Handler
/// </summary>
/// <param name="pIrp">The pointer to IRP</param>
/// <param name="pIoStackIrp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS TypeConfusionIoctlHandler(IN PIRP pIrp, IN PIO_STACK_LOCATION pIoStackIrp) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PTYPE_CONFUSION_USER_OBJECT pTypeConfusionUserObject = NULL;

    UNREFERENCED_PARAMETER(pIrp);
    PAGED_CODE();

    pTypeConfusionUserObject = (PTYPE_CONFUSION_USER_OBJECT)
                                pIoStackIrp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (pTypeConfusionUserObject) {
        status = TriggerTypeConfusion(pTypeConfusionUserObject);
    }

    return status;
}

#pragma auto_inline()
