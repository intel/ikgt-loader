################################################################################
# Copyright (c) 2015 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

/* primary guest entry */
.file   "pg_entry.s"

#define __BOOT_CS    0x10
#define __BOOT_DS    0x18


.text

.extern load_primary_guest_kernel


/*
* enter linux kernel code, should not return.
* configure the initial state according to linux boot protocol:
* Documentation/x86/boot.txt
*/
.globl jump_to_kernel
jump_to_kernel:

    movl 0x04(%esp), %esi  /* esi --> address of boot params */
    movl 0x08(%esp), %edx  /* kernel entry */

    xor %ebp, %ebp
    xor %edi, %edi
    xor %ebx, %ebx
    xor %eax, %eax


    movl $(__BOOT_DS), %ecx
    mov %cx, %ds
    mov %cx, %es
    mov %cx, %fs
    mov %cx, %gs
    mov %cx, %ss
    ljmp $(__BOOT_CS), $(1f)
1:
    cli
    jmp *%edx
    ud2
    ret


.globl primary_guest_entry
primary_guest_entry:

    /* after xmon starts, CPU resumes back to here
    *  to launch primary guest OS kernel (currently only support linux)
    *  ecx - xmon_desc_t pointer
    */
    pushl %ecx
    call load_primary_guest_kernel

    jmp .
