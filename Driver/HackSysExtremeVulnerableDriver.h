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
    HackSysExtremeVulnerableDriver.h

Abstract:
    This module implements the data structures for main
    driver module.

--*/

#ifndef __HACKSYS_EXTREME_VULNERABLE_DRIVER_H__
    #define __HACKSYS_EXTREME_VULNERABLE_DRIVER_H__

    #pragma once

    #include "Common.h"

    #define HACKSYS_EVD_IOCTL_STACK_OVERFLOW                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_STACK_OVERFLOW_GS               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_NON_PAGED_POOL_OVERFLOW         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_USE_UAF_OBJECT                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_ALLOCATE_FAKE_OBJECT            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_TYPE_CONFUSION                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_UNINITIALIZED_STACK_VARIABLE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_UNINITIALIZED_HEAP_VARIABLE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_DOUBLE_FETCH                    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80D, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80E, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_MEMORY_DISCLOSURE               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80F, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_PAGED_POOL_SESSION              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_NEITHER, FILE_ANY_ACCESS)
    #define HACKSYS_EVD_IOCTL_WRITE_NULL                      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_NEITHER, FILE_ANY_ACCESS)

    #define BANNER \
        ("                                        \n" \
         " ##     ## ######## ##     ## ########  \n" \
         " ##     ## ##       ##     ## ##     ## \n" \
         " ##     ## ##       ##     ## ##     ## \n" \
         " ######### ######   ##     ## ##     ## \n" \
         " ##     ## ##        ##   ##  ##     ## \n" \
         " ##     ## ##         ## ##   ##     ## \n" \
         " ##     ## ########    ###    ########  \n" \
         "   HackSys Extreme Vulnerable Driver    \n" \
         "             Version: 2.00              \n")

    DRIVER_INITIALIZE    DriverEntry;
    DRIVER_UNLOAD        IrpUnloadHandler;
    DRIVER_DISPATCH      IrpNotImplementedHandler;

    __drv_dispatchType(IRP_MJ_CREATE)
        __drv_dispatchType(IRP_MJ_CLOSE)         DRIVER_DISPATCH    IrpCreateCloseHandler;
    __drv_dispatchType(IRP_MJ_DEVICE_CONTROL)    DRIVER_DISPATCH    IrpDeviceIoCtlHandler;

    VOID        IrpUnloadHandler(IN PDRIVER_OBJECT DriverObject);
    NTSTATUS    IrpCreateCloseHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
    NTSTATUS    IrpDeviceIoCtlHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
    NTSTATUS    IrpNotImplementedHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
    NTSTATUS    DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);

#endif  //__HACKSYS_EXTREME_VULNERABLE_DRIVER_H__
