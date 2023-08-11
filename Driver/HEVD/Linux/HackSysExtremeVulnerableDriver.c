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
    HackSysExtremeVulnerableDriver.c

Abstract:
    This module implements the main kernel driver
    of HackSys Extreme Vulnerable Driver.

--*/

#include "HackSysExtremeVulnerableDriver.h"

/**
 * File Operations
 */

struct file_operations hevd_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = hevd_ioctl
};

/**
 * Miscellaneous Device
 */

static struct miscdevice hevd_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "HackSysExtremeVulnerableDriver",
    .fops = &hevd_fops
};

/**
 * Driver initialization routine
 *
 * @return status code
 */
static int __init hevd_init(void)
{
    int status = 0;

    /**
     * Register the device
     */

    status = misc_register(&hevd_device);

    if (status < 0)
    {
        ERR("[-] Error Initializing HackSys Extreme Vulnerable Driver\n");
        return status;
    }

    INFO(BANNER);
    INFO("[+] HackSys Extreme Vulnerable Driver Loaded\n");

    return status;
}

/**
 * Driver cleanup routine
 */
static void __exit hevd_exit(void)
{
    /**
     * Deregister the device
     */

    misc_deregister(&hevd_device);

    INFO("[-] HackSys Extreme Vulnerable Driver Unloaded\n");
}

/**
 * Driver IOCTL handler
 */
static long hevd_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int status = -EINVAL;
    struct hevd_io user_hevd_io = {0};

    if (copy_from_user(&user_hevd_io, (struct hevd_io __user *)arg, sizeof(user_hevd_io)))
    {
        return -EFAULT;
    }

    switch (cmd)
    {
    case HEVD_IOCTL_BUFFER_OVERFLOW_STACK:
        INFO("****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK ******\n");
        status = buffer_overflow_stack_ioctl_handler(&user_hevd_io);
        INFO("****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK ******\n");
        break;
    case HEVD_IOCTL_INTEGER_OVERFLOW:
        INFO("****** HEVD_IOCTL_INTEGER_OVERFLOW ******\n");
        status = integer_overflow_ioctl_handler(&user_hevd_io);
        INFO("****** HEVD_IOCTL_INTEGER_OVERFLOW ******\n");
        break;
    case HEVD_IOCTL_ARBITRARY_WRITE:
        INFO("****** HEVD_IOCTL_ARBITRARY_WRITE ******\n");
        status = arbitrary_write_ioctl_handler(&user_hevd_io);
        INFO("****** HEVD_IOCTL_ARBITRARY_WRITE ******\n");
        break;
    case HEVD_IOCTL_UNINITIALIZED_MEMORY_STACK:
        INFO("****** HEVD_IOCTL_UNINITIALIZED_MEMORY_STACK ******\n");
        status = uninitialized_memory_stack_ioctl_handler(&user_hevd_io);
        INFO("****** HEVD_IOCTL_UNINITIALIZED_MEMORY_STACK ******\n");
        break;
    default:
        WARNING("[-] Invalid IOCTL Code: 0x%X\n", cmd);
        status = -ENOIOCTLCMD;
        break;
    }

    return status;
}

/**
 * Set initialization and cleanup routines
 */

module_init(hevd_init);
module_exit(hevd_exit);

/**
 * Module information
 */

MODULE_VERSION("4.0");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ashfaq Ansari (@HackSysTeam)");
MODULE_DESCRIPTION("HackSys Extreme Vulnerable Driver");
