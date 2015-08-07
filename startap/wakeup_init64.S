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

#include "msr_defs.h"

.file   "wakeup_init64.s"

.text
.globl ap_continue_wakeup_code
ap_continue_wakeup_code:
	cli
	movl $IA32_MSR_APIC_BASE, %ecx
	rdmsr
	andl $~0xFFF, %eax  # LOCAL_APIC_BASE_MSR_MASK
	movl 0x20(%eax), %ecx  #LOCAL_APIC_IDENTIFICATION_OFFSET
	shrl $24, %ecx  # LOCAL_APIC_ID_LOW_RESERVED_BITS_COUNT - ecx = local_apic_id
	leal ap_presence_array, %edx

	addl %ecx, %edx
	movb $1, (%edx)
wait_lock_1:
	cmpl $1, mp_bootstrap_state

	je stage_2
	pause
	jmp wait_lock_1

//stage 2 - setup the stack, GDT, IDT and jump to "C"
stage_2:
	xor %ecx, %ecx
	movb (%edx), %cl 	# now ecx contains AP ordered ID [1..Max]
	movl %ecx, %eax
	# AP starts from 1, so subtract one to get proper index in g_stacks_arr
	decl %eax
	shll $2, %eax 		#  eax = sizeof(uint32_t)*eax *
	movl gp_init32_data, %edx
	addl $8, %edx 	# now edx points to gp_init32_data->i32_esp
	addl %eax, %edx		# now edx points to gp_init32_data->i32_esp[eax]
	movl (%edx), %esp
	lgdt gp_GDT
	lidt gp_IDT
	pushl %ecx 	# push  AP ordered ID
	call ap_continue_wakeup_code_C		# should never return
	ret


.globl start_64bit_mode
start_64bit_mode:
    # prepare arguments for 64-bit mode
    # align stack and push them on 8-byte alignment
    movl 0x04(%esp), %ebx
    movl 0x08(%esp), %ebp
    movl 0x0c(%esp), %ecx
    movl 0x10(%esp), %edx
    movl 0x14(%esp), %edi
    movl 0x18(%esp), %esi

    xorl %eax, %eax
    andl $~7, %esp
    pushl %eax
    pushl %esi
    pushl %eax
    pushl %edi
    pushl %eax
    pushl %edx
    pushl %eax
    pushl %ecx

    cli

    pushl %ebp    		# push segment and offset
    pushl $START64    	# for following retf
						# address is in ebx

    # enable 64-bit mode
    movl $0x0C0000080, %ecx     # EFER MSR register
    rdmsr                   	# read EFER into EAX
    bts $8, %eax                # set EFER.LME=1
    wrmsr                   	# write EFER
    # enable paging CR0.pg=1
    movl %cr0, %eax
    bts $31, %eax                # set pg=1
    movl %eax, %cr0

    # at this point we are in 32-bit compatibility mode
    # LMA=1, CS.L=0, CS.D=1
    # jump from 32bit compatibility mode into 64bit mode.

    lret

START64:
	popl   %ecx              # in 64bit this is actually pop rcx
	popl   %edx              # in 64bit this is actually pop rdx

	.byte  0x41
	.byte  0x58              # pop r8

	.byte  0x41
	.byte  0x59              # pop r9

	.byte  0x48              # in 64bit this is actually
	subl  $0x18, %esp        #   sub  rsp, 0x18

	call   *%ebx             # in 64bit this is actually

### EOF ###

