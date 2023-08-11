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

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/version.h>

/**
 * Defines
 */

#define BUFFER_SIZE 512

#define STATUS_SUCCESS      0x0

#define _STRINGIFY(value) #value
#define STRINGIFY(value) _STRINGIFY(value)

#define PRINTK(level, fmt, ...) printk(KERN_##level "%s: " fmt, THIS_MODULE->name, ##__VA_ARGS__)

#define ERR(fmt, ...) PRINTK(ERR, fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) PRINTK(INFO, fmt, ##__VA_ARGS__)
#define WARNING(fmt, ...) PRINTK(WARNING, fmt, ##__VA_ARGS__)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0))

#define VERIFY_READ     0
#define VERIFY_WRITE    1
#define x_access_ok(type, addr, size) access_ok(addr, size)

#else /* LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0) */

#define x_access_ok(type, addr, size) access_ok(type, addr, size)

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0) */

typedef void (*FunctionPointer)(void);


/**
 * Structures
 */

struct hevd_io {
    void *input_buffer;
    size_t input_buffer_length;
    void *output_buffer;
    size_t output_buffer_length;
};


/**
 * Function Definitions
 */

int buffer_overflow_stack_ioctl_handler(struct hevd_io *io);
int integer_overflow_ioctl_handler(struct hevd_io *io);
int arbitrary_write_ioctl_handler(struct hevd_io *io);
int uninitialized_memory_stack_ioctl_handler(struct hevd_io *io);

#endif // !__COMMON_H__
