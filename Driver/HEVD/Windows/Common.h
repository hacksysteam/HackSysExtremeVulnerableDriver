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
Contact: ashfaq[at]hacksys[dot]io
Website: https://hacksys.io/

Copyright (C) 2021-2023 HackSys Inc. All rights reserved.
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
    Common.h

Abstract:
    This module implements the data structures which
    are common to the driver modules.

--*/

#pragma once

#ifndef __COMMON_H__
#define __COMMON_H__

#include <ntddk.h>


//
// Defines
//

#define POOL_TAG 'kcaH'
#define BUFFER_SIZE 512

#define _STRINGIFY(value) #value
#define STRINGIFY(value) _STRINGIFY(value)

#define DbgPrint(Format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, Format, __VA_ARGS__)

typedef void (*FunctionPointer)(void);


//
// Function Definitions
//

NTSTATUS
ArbitraryWriteIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
BufferOverflowNonPagedPoolIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
BufferOverflowNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
BufferOverflowPagedPoolSessionIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
BufferOverflowStackIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
BufferOverflowStackGSIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
DoubleFetchIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
InsecureKernelFileAccessIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
IntegerOverflowIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
MemoryDisclosureNonPagedPoolIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
MemoryDisclosureNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
NullPointerDereferenceIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
TypeConfusionIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
UninitializedMemoryPagedPoolIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
UninitializedMemoryStackIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
AllocateUaFObjectNonPagedPoolIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
AllocateFakeObjectNonPagedPoolIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
UseUaFObjectNonPagedPoolIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
FreeUaFObjectNonPagedPoolIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
AllocateUaFObjectNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
AllocateFakeObjectNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
UseUaFObjectNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
FreeUaFObjectNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
WriteNULLIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
CreateArbitraryReadWriteHelperObjectNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
SetArbitraryReadWriteHelperObjecNameNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
GetArbitraryReadWriteHelperObjecNameNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
DeleteArbitraryReadWriteHelperObjecNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
ArbitraryIncrementIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

#endif // !__COMMON_H__
