/*******************************************************************************
* Copyright (c) 2015 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

#ifndef __MULTIBOOT_UTIL_H__
#define __MULTIBOOT_UTIL_H__

#include "multiboot.h"
#include "xmon_desc.h"

#define ALIGN_UP(addr, align) \
	((addr + (typeof(addr))align - 1) & ~((typeof(addr))align - 1))

/* For multiboot2 information. There two fixed parts at the beginning.
 * |total_size|
 * |reserved  |
 * And this parts need to be 8-bytes aligned.
 * So the real multiboot2 tag starts at 8 bytes behind the multiboot2 information.
 */
#define MB2_TAG_START(mb2_info) ((struct mb2_tag *)((uint32_t)(mb2_info) + 8))

struct efi_memory_desc {
	uint32_t type;
	uint32_t pad;
	uint64_t phys_addr;
	uint64_t virt_addr;
	uint64_t num_pages;
	uint64_t attribute;
};

/*
 * Memory map descriptor:
 */

/* Memory types: */
#define EFI_RESERVED_TYPE               0
#define EFI_LOADER_CODE                 1
#define EFI_LOADER_DATA                 2
#define EFI_BOOT_SERVICES_CODE          3
#define EFI_BOOT_SERVICES_DATA          4
#define EFI_RUNTIME_SERVICES_CODE       5
#define EFI_RUNTIME_SERVICES_DATA       6
#define EFI_CONVENTIONAL_MEMORY         7
#define EFI_UNUSABLE_MEMORY             8
#define EFI_ACPI_RECLAIM_MEMORY         9
#define EFI_ACPI_MEMORY_NVS             10
#define EFI_MEMORY_MAPPED_IO            11
#define EFI_MEMORY_MAPPED_IO_PORT_SPACE 12
#define EFI_PAL_CODE                    13
#define EFI_MAX_MEMORY_TYPE             14

/* Attribute values: */
#define EFI_MEMORY_UC       ((uint64_t)0x0000000000000001ULL)           /* uncached */
#define EFI_MEMORY_WC       ((uint64_t)0x0000000000000002ULL)           /* write-coalescing */
#define EFI_MEMORY_WT       ((uint64_t)0x0000000000000004ULL)           /* write-through */
#define EFI_MEMORY_WB       ((uint64_t)0x0000000000000008ULL)           /* write-back */
#define EFI_MEMORY_WP       ((uint64_t)0x0000000000001000ULL)           /* write-protect */
#define EFI_MEMORY_RP       ((uint64_t)0x0000000000002000ULL)           /* read-protect */
#define EFI_MEMORY_XP       ((uint64_t)0x0000000000004000ULL)           /* execute-protect */
#define EFI_MEMORY_RUNTIME  ((uint64_t)0x8000000000000000ULL)           /* range requires runtime mapping */
#define EFI_MEMORY_DESCRIPTOR_VERSION   1

#define EFI_PAGE_SHIFT      12

/* EFI memory map support */
struct efi_memory_desc *get_efi_mmap(xmon_desc_t *ed, uint32_t *mmap_size);

struct mb2_tag *next_mb2_tag(struct mb2_tag *start);
struct mb2_tag *get_mb2_tag_type(struct mb2_tag *start, uint32_t tag_type);

enum efi_status {
    EFI_NONE,
    EFI_32BIT,
    EFI_64BIT,
    EFI_UNKNOWN
};
boolean_t get_loader_efi_addr(struct mb2_tag *start, uint32_t *addr, uint64_t *long_addr);
boolean_t is_loader_launch_efi_mb1(xmon_desc_t *xd);
boolean_t is_loader_launch_efi_mb2(xmon_desc_t *xd);
enum efi_status get_loader_launch_efi_status(struct mb2_tag *start);

#endif  /* ! MULTIBOOT_UTIL_HEADER */
