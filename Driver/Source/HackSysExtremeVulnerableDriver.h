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

Copyright (C) 2011-2015 Payatu Technologies. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS
OR COPYRIGHT HOLDERS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

See the file 'LICENSE' for complete copying permission.

Module Name:
    HackSys.h

Abstract:
    This module implements the data structures for main
    driver module.

--*/

#ifndef __HACKSYS_H__
    #define __HACKSYS_H__

    #pragma once

    #include "Common.h"

    #define HACKSYS_EVD_IOCTL_STACK_OVERFLOW              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_STACK_OVERFLOW_GS           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_POOL_OVERFLOW               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_CREATE_UAF_OBJECT           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_USE_UAF_OBJECT              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_CREATE_FAKE_OBJECT          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_TYPE_CONFUSION              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
    #define HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

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
         "                                        \n")

    DRIVER_INITIALIZE    DriverEntry;
    DRIVER_UNLOAD        IrpUnloadHandler;
    DRIVER_DISPATCH      IrpNotImplementedHandler;

    __drv_dispatchType(IRP_MJ_CREATE)            DRIVER_DISPATCH    IrpCreateHandler;
    __drv_dispatchType(IRP_MJ_CLOSE)             DRIVER_DISPATCH    IrpCloseHandler;
    __drv_dispatchType(IRP_MJ_DEVICE_CONTROL)    DRIVER_DISPATCH    IrpDeviceIoCtlHandler;

    VOID        IrpUnloadHandler(IN PDRIVER_OBJECT pDriverObject);
    NTSTATUS    IrpCloseHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
    NTSTATUS    IrpCreateHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
    NTSTATUS    IrpDeviceIoCtlHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
    NTSTATUS    IrpNotImplementedHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
    NTSTATUS    DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath);

#endif  //__HACKSYS_H__
