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
    BufferOverflowStack.c

Abstract:
    This module implements the functions to demonstrate
    buffer overflow in Stack vulnerability.

--*/

#include "BufferOverflowStack.h"


/**
 * Trigger the buffer overflow in Stack Vulnerability
 * 
 * @param[in] user_buffer the pointer to user mode buffer
 * @param[in] size size of the user mode buffer
 * @return status code
 */
__attribute__((optimize("-fno-stack-protector")))
int trigger_buffer_overflow_stack(void *user_buffer, size_t size)
{
    int status = STATUS_SUCCESS;
    unsigned long kernel_buffer[BUFFER_SIZE] = { 0 };

    INFO("[+] user_buffer: 0x%p\n", user_buffer);
    INFO("[+] user_buffer size: 0x%zX\n", size);
    INFO("[+] kernel_buffer: 0x%p\n", &kernel_buffer);
    INFO("[+] kernel_buffer size: 0x%zX\n", sizeof(kernel_buffer));

#ifdef SECURE
    /**
     * Secure Note: This is secure because the developer is passing a size
     * equal to size of kernel_buffer to `copy_from_user()`. Hence,
     * there will be no overflow
     */

    if (copy_from_user(kernel_buffer, user_buffer, sizeof(kernel_buffer)))
    {
        status = -EFAULT;
    }
#else
    INFO("[+] Triggering Buffer Overflow in Stack\n");

    /**
     * Vulnerability Note: This is a vanilla Stack based Overflow vulnerability
     * because the developer is passing the user supplied size directly to
     * `__copy_from_user()` without validating if the size is greater or
     * equal to the size of kernel_buffer
     */

    if (__copy_from_user(kernel_buffer, user_buffer, size))
    {
        status = -EFAULT;
    }
#endif
    
    return status;
}


/**
 * Buffer Overflow Stack Ioctl Handler
 * 
 * @param[in] io user space buffer
 * @return status code
 */
int buffer_overflow_stack_ioctl_handler(struct hevd_io *io)
{
    size_t size = 0;
    void *user_buffer = NULL;
    int status = -EINVAL;

    user_buffer = io->input_buffer;
    size = io->input_buffer_length;

    if (user_buffer)
    {
        status = trigger_buffer_overflow_stack(user_buffer, size);
    }

    return status;
}
