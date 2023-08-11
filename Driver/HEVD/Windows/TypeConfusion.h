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
    TypeConfusion.h

Abstract:
    This module implements the data structures for
    type confusion module.

--*/

#pragma once

#ifndef __TYPE_CONFUSION_H__
#define __TYPE_CONFUSION_H__

#include "Common.h"


//
// Structures
//

typedef struct _USER_TYPE_CONFUSION_OBJECT
{
    ULONG_PTR ObjectID;
    ULONG_PTR ObjectType;
} USER_TYPE_CONFUSION_OBJECT, *PUSER_TYPE_CONFUSION_OBJECT;

#pragma warning(push)
#pragma warning(disable : 4201)
typedef struct _KERNEL_TYPE_CONFUSION_OBJECT
{
    ULONG_PTR ObjectID;
    union
    {
        ULONG_PTR ObjectType;
        FunctionPointer Callback;
    };
} KERNEL_TYPE_CONFUSION_OBJECT, *PKERNEL_TYPE_CONFUSION_OBJECT;
#pragma warning(pop)


//
// Function Definitions
//

VOID
TypeConfusionObjectCallback(
    VOID
);

NTSTATUS
TriggerTypeConfusion(
    _In_ PUSER_TYPE_CONFUSION_OBJECT UserTypeConfusionObject
);

NTSTATUS
TypeConfusionObjectInitializer(
    _In_ PKERNEL_TYPE_CONFUSION_OBJECT KernelTypeConfusionObject
);

#endif  // !__TYPE_CONFUSION_H__
