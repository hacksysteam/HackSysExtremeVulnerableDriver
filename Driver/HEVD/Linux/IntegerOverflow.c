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
    IntegerOverlfow.c

Abstract:
    This module implements the functions to demonstrate
    integer overflow in kernel module

--*/

#include "IntegerOverflow.h"


/**
 * @param[in] user_buffer the pointer to user mode buffer
 * @param[in] size size of the user mode buffer
 * @return status code
 */
int trigger_integer_overflow(void *user_buffer, size_t size)
{
    unsigned long count = 0;
    int status = STATUS_SUCCESS;
    unsigned long kernel_buffer[BUFFER_SIZE] = {0};
    unsigned long kernel_buffer_terminator = 0xBAD0B0B0;
    size_t terminator_size = sizeof(kernel_buffer_terminator);

    INFO("[+] user_buffer: 0x%p\n", user_buffer);
    INFO("[+] user_buffer size: 0x%zX\n", size);
    INFO("[+] kernel_buffer: 0x%p\n", &kernel_buffer);
    INFO("[+] kernel_buffer size: 0x%zX\n", sizeof(kernel_buffer));

#ifdef SECURE
    /**
     * Secure Note: This is secure because the developer is not doing any arithmetic
     * on the user supplied value. Instead, the developer is subtracting the size of
     * UINT i.e. 4 on x86 from the size of KernelBuffer. Hence, integer overflow will
     * not occur and this check will not fail
     */

    if (size > (sizeof(kernel_buffer) - terminator_size))
    {
        ERR("[-] Invalid user buffer size: 0x%zX\n", size);

        status = -EINVAL;
        return status;
    }

#else
    INFO("[+] Triggering Integer Overflow\n");

    /**
     * Vulnerability Note: This is a vanilla Integer Overflow vulnerability because if
     * 'Size' is 0xFFFFFFFF and we do an addition with size of ULONG i.e. 4 on x86, the
     * integer will wrap down and will finally cause this check to fail
     */

    if ((size + terminator_size) > sizeof(kernel_buffer))
    {
        ERR("[-] Invalid user buffer size: 0x%zX\n", size);

        status = -EINVAL;
        return status;
    }
#endif

    while (count < (size / sizeof(unsigned long)))
    {
        unsigned long n;

        if (copy_from_user((void *)&n, user_buffer + count, sizeof(n)))
        {
            status = -EFAULT;
            break;
        }

        if (n == kernel_buffer_terminator)
        {
            break;
        }

        kernel_buffer[count++] = n;
    }

    return status;
}


/**
 * @param[in] io user space buffer
 * @return status code
 */
int integer_overflow_ioctl_handler(struct hevd_io *io)
{
    size_t size = 0;
    void *user_buffer = NULL;
    int status = -EINVAL;

    user_buffer = io->input_buffer;
    size = io->input_buffer_length;

    if (user_buffer)
    {
        status = trigger_integer_overflow(user_buffer, size);
    }

    return status;
}
