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
    TypeConfusion.c

Abstract:
    This module implements the functions to demonstrate
    Type Confusion vulnerability due to improper use of
    UNION construct.

--*/

#include "TypeConfusion.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, TriggerTypeConfusion)
#pragma alloc_text(PAGE, TypeConfusionIoctlHandler)
#pragma alloc_text(PAGE, TypeConfusionObjectCallback)
#pragma alloc_text(PAGE, TypeConfusionObjectInitializer)
#endif // ALLOC_PRAGMA


/// <summary>
/// Type Confusion Object Callback
/// </summary>
VOID
TypeConfusionObjectCallback(
    VOID
)
{
    PAGED_CODE();

    DbgPrint("[+] Type Confusion Object Callback\n");
}


/// <summary>
/// Type Confusion Object Initializer
/// </summary>
/// <param name="KernelTypeConfusionObject">The pointer to KERNEL_TYPE_CONFUSION_OBJECT object</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
TypeConfusionObjectInitializer(
    _In_ PKERNEL_TYPE_CONFUSION_OBJECT KernelTypeConfusionObject
)
{
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    DbgPrint("[+] KernelTypeConfusionObject->Callback: 0x%p\n", KernelTypeConfusionObject->Callback);
    DbgPrint("[+] Calling Callback\n");

    KernelTypeConfusionObject->Callback();

    DbgPrint("[+] Kernel Type Confusion Object Initialized\n");

    return Status;
}


/// <summary>
/// Trigger the Type Confusion Vulnerability
/// </summary>
/// <param name="UserTypeConfusionObject">The pointer to USER_TYPE_CONFUSION_OBJECT object</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
TriggerTypeConfusion(
    _In_ PUSER_TYPE_CONFUSION_OBJECT UserTypeConfusionObject
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PKERNEL_TYPE_CONFUSION_OBJECT KernelTypeConfusionObject = NULL;

    PAGED_CODE();

    __try
    {
        //
        // Verify if the buffer resides in user mode
        //

        ProbeForRead(
            UserTypeConfusionObject,
            sizeof(USER_TYPE_CONFUSION_OBJECT),
            (ULONG)__alignof(UCHAR)
        );

        //
        // Allocate Pool chunk
        //

        KernelTypeConfusionObject = (PKERNEL_TYPE_CONFUSION_OBJECT)ExAllocatePoolWithTag(
            NonPagedPool,
            sizeof(KERNEL_TYPE_CONFUSION_OBJECT),
            (ULONG)POOL_TAG
        );

        if (!KernelTypeConfusionObject)
        {
            //
            // Unable to allocate Pool chunk
            //

            DbgPrint("[-] Unable to allocate Pool chunk\n");

            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else
        {
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%zX\n", sizeof(KERNEL_TYPE_CONFUSION_OBJECT));
            DbgPrint("[+] Pool Chunk: 0x%p\n", KernelTypeConfusionObject);
        }

        DbgPrint("[+] UserTypeConfusionObject: 0x%p\n", UserTypeConfusionObject);
        DbgPrint("[+] KernelTypeConfusionObject: 0x%p\n", KernelTypeConfusionObject);
        DbgPrint("[+] KernelTypeConfusionObject Size: 0x%zX\n", sizeof(KERNEL_TYPE_CONFUSION_OBJECT));

        KernelTypeConfusionObject->ObjectID = UserTypeConfusionObject->ObjectID;
        KernelTypeConfusionObject->ObjectType = UserTypeConfusionObject->ObjectType;

        DbgPrint("[+] KernelTypeConfusionObject->ObjectID: 0x%p\n", KernelTypeConfusionObject->ObjectID);
        DbgPrint("[+] KernelTypeConfusionObject->ObjectType: 0x%p\n", KernelTypeConfusionObject->ObjectType);


#ifdef SECURE
        //
        // Secure Note: This is secure because the developer is properly setting 'Callback'
        // member of the 'KERNEL_TYPE_CONFUSION_OBJECT' structure before passing the pointer
        // of 'KernelTypeConfusionObject' to 'TypeConfusionObjectInitializer()' function as
        // parameter
        //

        KernelTypeConfusionObject->Callback = &TypeConfusionObjectCallback;
        Status = TypeConfusionObjectInitializer(KernelTypeConfusionObject);
#else
        DbgPrint("[+] Triggering Type Confusion\n");

        //
        // Vulnerability Note: This is a vanilla Type Confusion vulnerability due to improper
        // use of the 'UNION' construct. The developer has not set the 'Callback' member of
        // the 'KERNEL_TYPE_CONFUSION_OBJECT' structure before passing the pointer of
        // 'KernelTypeConfusionObject' to 'TypeConfusionObjectInitializer()' function as
        // parameter
        //

        Status = TypeConfusionObjectInitializer(KernelTypeConfusionObject);
#endif

        DbgPrint("[+] Freeing KernelTypeConfusionObject Object\n");
        DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
        DbgPrint("[+] Pool Chunk: 0x%p\n", KernelTypeConfusionObject);

        //
        // Free the allocated Pool chunk
        //

        ExFreePoolWithTag((PVOID)KernelTypeConfusionObject, (ULONG)POOL_TAG);
        KernelTypeConfusionObject = NULL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}


/// <summary>
/// Type Confusion Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
TypeConfusionIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PUSER_TYPE_CONFUSION_OBJECT UserTypeConfusionObject = NULL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    UserTypeConfusionObject = (PUSER_TYPE_CONFUSION_OBJECT)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;

    if (UserTypeConfusionObject)
    {
        Status = TriggerTypeConfusion(UserTypeConfusionObject);
    }

    return Status;
}
