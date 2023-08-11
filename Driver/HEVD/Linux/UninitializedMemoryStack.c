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
    UninitializedMemoryStack.c

Abstract:
    This module implements the functions to demonstrate
    use of uninitialized memory in Stack vulnerability.

--*/

#include "UninitializedMemoryStack.h"

/// <summary>
/// Uninitialized Memory Stack Object Callback
/// </summary>
void
UninitializedMemoryStackObjectCallback(void)
{
    INFO("[+] Uninitialized Memory Stack Object Callback\n");
}


/**
 * @param[in] user_buffer the pointer to user mode buffer
 * @param[in] size size of the user mode buffer
 * @return status code
 */
int trigger_uninitialized_memory_stack(void *user_buffer, size_t size)
{
    unsigned long UserValue = 0;
    unsigned long MagicValue = 0xBAD0B0B0;
    int status = STATUS_SUCCESS;

#ifdef SECURE
    //
    // Secure Note: This is secure because the developer is properly initializing
    // UNINITIALIZED_MEMORY_STACK to NULL and checks for NULL pointer before calling
    // the callback
    //

    UNINITIALIZED_MEMORY_STACK UninitializedMemory = { 0 };
#else
    //
    // Vulnerability Note: This is a vanilla Uninitialized Memory in Stack vulnerability
    // because the developer is not initializing 'UNINITIALIZED_MEMORY_STACK' structure
    // before calling the callback when 'MagicValue' does not match 'UserValue'
    //

    UNINITIALIZED_MEMORY_STACK UninitializedMemory;
#endif

    if(copy_from_user(&UserValue, user_buffer, sizeof(UserValue))) {
        ERR("Failed to copy UserValue from user space\n");

        status = -EINVAL;
        return status;
    }

    INFO("[+] UserValue: [0x%p] [0x%zX]\n", &UserValue, UserValue);
    INFO("[+] UninitializedMemory Address: 0x%p\n", &UninitializedMemory);

    if (UserValue == MagicValue) {
        UninitializedMemory.Value = UserValue;
        UninitializedMemory.Callback = &UninitializedMemoryStackObjectCallback;
    }

#ifndef SECURE
    INFO("[+] Triggering Uninitialized Memory in Stack\n");
#endif

    if (UninitializedMemory.Callback) {
        UninitializedMemory.Callback();
    }

    return status;
}


/**
 * @param[in] io user space buffer
 * @return status code
 */
int uninitialized_memory_stack_ioctl_handler(struct hevd_io *io)
{
    size_t size = 0;
    void *user_buffer = NULL;
    int status = -EINVAL;

    user_buffer = io->input_buffer;
    size = io->input_buffer_length;

    if (user_buffer)
    {
        status = trigger_uninitialized_memory_stack(user_buffer, size);
    }

    return status;
}
