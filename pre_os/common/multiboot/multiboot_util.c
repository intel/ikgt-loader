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

#include <mon_defs.h>
#include <multiboot_util.h>
#include "memory.h"

struct mb2_tag *next_mb2_tag(struct mb2_tag *start)
{
	void *addr = (void *)start;

	if (start == NULL ||
	    start->type == MB2_TAG_TYPE_END) {
		return NULL;
	}
	addr += ALIGN_UP(start->size, MB2_TAG_ALIGN);
	return (struct mb2_tag *)addr;
}

struct mb2_tag *get_mb2_tag_type(struct mb2_tag *start, uint32_t tag_type)
{
	while (start != NULL) {
		if (start->type == tag_type) {
			return start;
		}
		start = next_mb2_tag(start);
	}
	return start;
}

/* get legacy memory map info from MBI info, and convert the memory type to EFI-style
 * the right way to get it is to invoke EFI boot-time service get_memory_map()
 * so we to need add noefi to vmlinuz command line in grub.cfg to disable efi runtime service
 * TODO: need to get efi memory map by invoking EFI boot-time service get_memory_map()
 */
struct efi_memory_desc *get_efi_mmap(xmon_desc_t *xd, uint32_t *mmap_size)
{
	uint32_t i = 0;
	struct mb2_tag_mmap *mp_tag;
	struct mb2_mmap_entry *mp;
	struct efi_memory_desc *ep;
	uint32_t num_of_entris = 0;

	mp_tag = (struct mb2_tag_mmap *)get_mb2_tag_type(
		MB2_TAG_START(xd->mb_initial_state.ebx), MB2_TAG_TYPE_MMAP);
	if (!mp_tag) {
		return NULL;
	}
	num_of_entris = (mp_tag->size - 4 * sizeof(uint32_t)) / mp_tag->entry_size;
	mp = mp_tag->entries;
	ep = (struct efi_memory_desc *)allocate_memory(
		sizeof(struct efi_memory_desc) * num_of_entris);
	if (!ep) {
		return NULL;
	}

	for (i = 0; i < num_of_entris; i++) {
		ep[i].phys_addr = ep[i].virt_addr = mp[i].addr;
		ep[i].pad = 0;
		uint64_t len = PAGE_ALIGN_4K(mp[i].len);
		ep[i].num_pages = len / PAGE_4KB_SIZE;
		switch (mp[i].type) {
		case MULTIBOOT_MEMORY_AVAILABLE:
			ep[i].type = EFI_CONVENTIONAL_MEMORY;
			break;
		case MULTIBOOT_MEMORY_ACPI_RECLAIMABLE:
			ep[i].type = EFI_ACPI_RECLAIM_MEMORY;
			break;
		case MULTIBOOT_MEMORY_NVS:
			ep[i].type = EFI_ACPI_MEMORY_NVS;
			break;
		case MULTIBOOT_MEMORY_BADRAM:
			ep[i].type = EFI_UNUSABLE_MEMORY;
			break;
		case MULTIBOOT_MEMORY_RESERVED:
		default:
			ep[i].type = EFI_RESERVED_TYPE;
			break;
		}
	}
	*mmap_size = sizeof(struct efi_memory_desc) * num_of_entris;
	return ep;
}

boolean_t get_loader_efi_addr(struct mb2_tag *start,
			      uint32_t *addr,
			      uint64_t *long_addr)
{
	struct mb2_tag *got;
	struct mb2_tag_efi32 *efi32;
	struct mb2_tag_efi64 *efi64;

	got = get_mb2_tag_type(start, MB2_TAG_TYPE_EFI32);
	if (got != NULL) {
		efi32 = (struct mb2_tag_efi32 *)got;
		*addr = (uint32_t)efi32->pointer;
		*long_addr = 0;
		return TRUE;
	}

	got = get_mb2_tag_type(start, MB2_TAG_TYPE_EFI64);
	if (got != NULL) {
		efi64 = (struct mb2_tag_efi64 *)got;
		*addr = 0;
		*long_addr = (uint64_t)efi64->pointer;
		return TRUE;
	}
	return FALSE;
}

enum efi_status get_loader_launch_efi_status(struct mb2_tag *start)
{
	uint32_t addr = 0;
	uint64_t long_addr = 0;
	enum efi_status efi_stat = EFI_UNKNOWN;

	if (get_loader_efi_addr(start, &addr, &long_addr)) {
		if (addr != 0 && long_addr == 0) {
			efi_stat = EFI_32BIT;
		} else if (addr == 0 && long_addr != 0) {
			efi_stat = EFI_64BIT;
		} else {
			efi_stat = EFI_UNKNOWN;
		}
	} else {
		efi_stat = EFI_NONE;
	}
	return efi_stat;
}

boolean_t is_loader_launch_efi_mb1(xmon_desc_t *xd)
{
	return FALSE;
}

boolean_t is_loader_launch_efi_mb2(xmon_desc_t *xd)
{
	enum efi_status efi_stat =
		get_loader_launch_efi_status(MB2_TAG_START(xd->mb_initial_state.ebx));
	if (efi_stat == EFI_32BIT ||
	    efi_stat == EFI_64BIT) {
		return TRUE;
	} else {
		return FALSE;
	}
}
