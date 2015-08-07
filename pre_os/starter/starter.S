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

.file   "starter.s"

#define ASM_FILE  1
#include "xmon_desc.h"

/* The flags for the Multiboot header (non-ELF) */
#define MULTIBOOT_HEADER_FLAGS  0x00010003

.text

.extern starter_main

#---------------------------------------------------------------------
#  void_t start(void)
# This is the first loader componet to run after GRUB/EFI/SFI BIOS
# tranfers control to the loader.
# It performs below operations:
#   1. save CPU states - pushal - eax, ecx, edx, ebx, esp, ebp, esi, edi
#                        pushfl - flags
#   2. call starter efi-loader function to load xmon_loader binary
#   3. jump to xmon_loader entry point
#---------------------------------------------------------------------

.globl start, _start
.org 0
start:
_start:

/* add ELF32 header to make TBOOT happy!
*  header must be starting from offset zero
*/
.align 1
elf32_header:
	.long 0x464C457f  /* 0x7f, 'E', 'L', 'F' */
        /*EI_CLASS 01- 32bit architecture */
	.byte 1
	/*EI_DATA 01- little-endian */
	.byte 1
        /*EI_VERSION 01- current version */
	.byte 1
	/*EI_OSABI 00- unspecified  */
	.byte 0

	/*offset 8~15: 00- unspecified or not used padding zeros */
	.long 0
	.long 0

	/* type(2) - executable
	*  machine(3) - Intel arch
	*/
	.long 0x00030002

	/* version */
	.long 0x1

	/* e_entry: the entry address of jump call (+base, because of no relocation) */
	.long STARTER_DEFAULT_LOAD_ADDR + starter_entry - _start

	/* e_phoff: offset to program header */
	.long elf32_program_header - _start

	/* e_shoff: Section header file offset, not used */
	.long 0

	/* e_flags: not used */
	.long 0

	/* e_ehsz : Size of ELF header in bytes */
	.short elf32_header_end - elf32_header

	/* e_phentsize: Size of program header entry. */
	.short elf32_program_header_end - elf32_program_header

	/*e_phnum :Number of program header entries.
	* only one for us
	*/
	.short 1

	/* e_shentsize: Size of section header entry. */
	.short 0
	/* e_shnum: Number of section header entries. */
	.short 0
	/* e_shstrndx:  Section name strings section. */
	.short 0

elf32_header_end:

.align 1
elf32_program_header:
	/* p_type;   Entry type. */
	.long 1 /* PT_LOAD */

	/* p_offset; File offset of contents.
	*  set it as zero, means copy the whole data starting
	*  from the beginning
	*/
	.long 0

	/* p_vaddr;  Virtual address in memory image. (not used now)*/
	.long 0

	/* p_paddr;  Physical address . */
	/* tboot copy the starter content to here */
	.long STARTER_DEFAULT_LOAD_ADDR

	/* p_filesz; Size of contents in file. */
	/*.long __etext - _start ; do not use this because there are appending files */
	.long LOADER_BIN_SIZE

	/* p_memsz;  Size of contents in memory. */
	/* the same with p_filesz */
	/*.long __etext - _start  */
	.long LOADER_BIN_SIZE

	/* p_flags;  Access permission flags. (not used now) */
	.long 0

	/* p_align;  Alignment in memory and file. (not used now)*/
	.long 0

elf32_program_header_end:


 /* code executed from here */
starter_entry:
	jmp multiboot_entry

	/* Align 32 bits boundary. */
	.align  4

	/* Multiboot1 header. */
multiboot_header:
	/* magic */
	.long   MULTIBOOT_HEADER_MAGIC
	/* flags */
	.long   MULTIBOOT_HEADER_FLAGS
	/* checksum */
	.long   -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)

	/* header_addr */
	.long   STARTER_DEFAULT_LOAD_ADDR + multiboot_header - _start
	/* load_addr */
	.long   STARTER_DEFAULT_LOAD_ADDR
	/* load_end_addr */
	.long   0
	/* bss_end_addr */
	.long   0
	/* entry_addr */
	.long   STARTER_DEFAULT_LOAD_ADDR + starter_entry - _start

/* multiboot2 header */
	.align 8
multiboot2_header:
	/* magic */
	.long MULTIBOOT2_HEADER_MAGIC
	/* architecture */
	.long MB2_ARCH_X86
	/* header_length*/
	.long multiboot2_header_end - multiboot2_header
	/* checksum */
	.long -(MULTIBOOT2_HEADER_MAGIC + MB2_ARCH_X86 + (multiboot2_header_end - multiboot2_header))
address_tag_start:
	.short MB2_HDR_TAG_ADDR
	.short MB2_HDR_TAG_OPTIONAL
	.long  address_tag_end - address_tag_start
	/* header_addr */
	.long  STARTER_DEFAULT_LOAD_ADDR + multiboot2_header - _start
	/* load_addr */
	.long  STARTER_DEFAULT_LOAD_ADDR
	/* load_end_addr */
	.long  0
	/* bss_end_addr */
	.long  0
address_tag_end:
entry_address_tag_start:
	.short MB2_HDR_TAG_ENTRY_ADDR
	.short MB2_HDR_TAG_OPTIONAL
	.long  entry_address_tag_end - entry_address_tag_start
	/* entry_addr */
	.long  STARTER_DEFAULT_LOAD_ADDR + starter_entry - _start
	.long  0
entry_address_tag_end:
	.short MB2_HDR_TAG_END
	.short 0
	.long  8
multiboot2_header_end:

multiboot_entry:

	/* Initialize the stack pointer (highest address). leal bspstack, %esp*/
	movl $(bspstack - 4 - _start), %esp
	addl $(STARTER_DEFAULT_LOAD_ADDR), %esp  /* add base */

	/* use ecx as the size of .text section
	*  because ecx is undefined by multiboot, so use it.
	*/
	movl $(__etext - _start), %ecx

	/* Reset EFLAGS. */
	pushl   $0
	popf

	pushal
	pushfl
	call starter_main
	jmp  .


/*
* stacks
*/
.align  4
bspstack_end:
	.fill STARTER_STACK_SIZE, 1, 0xCC
bspstack:
