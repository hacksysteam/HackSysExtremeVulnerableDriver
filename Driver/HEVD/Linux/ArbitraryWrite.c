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
    ArbitraryWrite.c

Abstract:
    This module implements the functions to demonstrate
    arbitrary write vulnerability in the kernel

--*/

#include "ArbitraryWrite.h"

/**
 * @param user_buffer the pointer to user mode buffer
 * @param size size of the user mode buffer
 */
int trigger_arbitrary_write(void *user_buffer, size_t size)
{
    int status = 0;
    WRITE_WHAT_WHERE params = { 0 };

    INFO("[+] user_buffer: 0x%p\n", user_buffer);
    INFO("[+] user_buffer size: 0x%zX\n", size);
    INFO("[+] params structure: 0x%p\n", &params);
    INFO("[+] params structure size: 0x%zX\n", sizeof(params));

    if(!access_ok(VERIFY_READ, user_buffer, sizeof(params))) {
        ERR("[+] Cannot read params from user space");
        
        status = -EINVAL;
        goto out;
    }

    copy_from_user(&params, user_buffer, sizeof(params));

#ifdef SECURE
    //
    // Secure Note: This is secure because the developer is properly validating if address
    // pointed by 'Where' and 'What' value resides in User mode
    //
    if (!access_ok(VERIFY_READ, params.What, sizeof(void*)) ||
        !access_ok(VERIFY_WRITE, params.Where, sizeof(void*))) {
        
        ERR("[-] Invalid parameters");
        
        status = -EINVAL;
        goto out;
    }

#endif

    INFO("[+] Triggering Write What Where\n");
    INFO("[+] WHAT: 0x%p\n", params.What);
    INFO("[+] WHERE: 0x%p\n", params.Where);

    //
    // Vulnerability Note: This is a vanilla Arbitrary Memory Overwrite vulnerability
    // because the developer is writing the value pointed by 'What' to memory location
    // pointed by 'Where' without properly validating if the values pointed by 'Where'
    // and 'What' resides in User mode
    //

    *((void**) params.Where) = *((void**) params.What);

out:
    return status;
}

/**
 * @param[in] io user space buffer
 * @return status code
 */
int arbitrary_write_ioctl_handler(struct hevd_io *io)
{
    size_t size = 0;
    void *user_buffer = NULL;
    int status = -EINVAL;

    user_buffer = io->input_buffer;
    size = io->input_buffer_length;

    if (user_buffer)
    {
        status = trigger_arbitrary_write(user_buffer, size);
    }

    return status;
}
