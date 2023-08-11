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
    ArbitraryWrite.c

Abstract:
    This module implements the functions to demonstrate
    arbitrary write vulnerability in the kernel

--*/

#include "ArbitraryWrite.h"


/**
 * @param[in] user_write_what_where the pointer to WRITE_WHAT_WHERE structure
 * @return status code
 */
int trigger_arbitrary_write(PWRITE_WHAT_WHERE user_write_what_where)
{
    void *what = NULL;
    void *where = NULL;
    int status = STATUS_SUCCESS;

    if (!x_access_ok(VERIFY_READ, user_write_what_where, sizeof(WRITE_WHAT_WHERE)))
    {
        ERR("[-] Invalid parameters");

        status = -EINVAL;
        return status;
    }

    what = user_write_what_where->What;
    where = user_write_what_where->Where;

    INFO("[+] user_write_what_where: 0x%p\n", user_write_what_where);
    INFO("[+] WRITE_WHAT_WHERE size: 0x%zX\n", sizeof(WRITE_WHAT_WHERE));
    INFO("[+] user_write_what_where->What: 0x%p\n", what);
    INFO("[+] user_write_what_where->Where: 0x%p\n", where);

#ifdef SECURE
    /**
     * Secure Note: This is secure because the developer is properly validating if address
     * pointed by 'Where' and 'What' value resides in User mode
     */

    if (!x_access_ok(VERIFY_READ, what, sizeof(void *)) ||
        !x_access_ok(VERIFY_WRITE, where, sizeof(void *)))
    {
        ERR("[-] Invalid parameters");

        status = -EINVAL;
        return status;
    }

#endif

    INFO("[+] Triggering Arbitrary Write\n");

    /**
     * Vulnerability Note: This is a vanilla Arbitrary Memory Overwrite vulnerability
     * because the developer is writing the value pointed by 'What' to memory location
     * pointed by 'Where' without properly validating if the values pointed by 'Where'
     * and 'What' resides in User mode
     */

    *((void **) where) = *((void **) what);
    
    return status;
}


/**
 * @param[in] io user space buffer
 * @return status code
 */
int arbitrary_write_ioctl_handler(struct hevd_io *io)
{
    int status = -EINVAL;
    PWRITE_WHAT_WHERE user_write_what_where = NULL;

    user_write_what_where = (PWRITE_WHAT_WHERE)io->input_buffer;

    if (user_write_what_where)
    {
        status = trigger_arbitrary_write(user_write_what_where);
    }

    return status;
}
