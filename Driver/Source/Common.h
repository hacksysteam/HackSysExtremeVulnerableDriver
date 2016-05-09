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
    Common.h

Abstract:
    This module implements the data structures which
    are common to the driver modules.

--*/

#ifndef __COMMON_H__
    #define __COMMON_H__

    #pragma once

    #include <ntddk.h>

    #define POOL_TAG 'kcaH'
    #define BUFFER_SIZE 512

    #define _STRINGIFY(value) #value
    #define STRINGIFY(value) _STRINGIFY(value)

    typedef void (*FunctionPointer)();

    NTSTATUS    PoolOverflowIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);
    NTSTATUS    UseUaFObjectIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);
    NTSTATUS    FreeUaFObjectIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);
    NTSTATUS    TypeConfusionIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);
    NTSTATUS    StackOverflowIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);
    NTSTATUS    CreateUaFObjectIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);
    NTSTATUS    IntegerOverflowIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);
    NTSTATUS    StackOverflowGSIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);
    NTSTATUS    CreateFakeObjectIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);
    NTSTATUS    ArbitraryOverwriteIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);
    NTSTATUS    NullPointerDereferenceIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);
    NTSTATUS    UninitializedHeapVariableIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);
    NTSTATUS    UninitializedStackVariableIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);

#endif //__COMMON_H__
