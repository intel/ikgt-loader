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

#include "mon_defs.h"
#include "mon_arch_defs.h"
#include "mon_startup.h"
#include "xmon_desc.h"
#include "common.h"
#include "multiboot.h"
#include "screen.h"
#include "memory.h"
#include "e820.h"
#include "multiboot_util.h"

void *CDECL mon_page_alloc(uint32_t pages);

boolean_t get_e820_table_from_mb1(xmon_desc_t *xd, uint64_t *e820_addr)
{
	int15_e820_memory_map_t *e820;
	uint32_t start;
	uint32_t next;
	uint32_t end;
	multiboot_info_t *inf;
	int i;

	inf = (multiboot_info_t *)(xd->mb_initial_state.ebx);

	if (((inf->flags & 0x00000003) == 0) || (inf->mmap_length > 4096)) {
		return FALSE;
	}

	e820 = (int15_e820_memory_map_t *)mon_page_alloc(1);

	if (e820 == NULL) {
		return FALSE;
	}

	start = inf->mmap_addr;
	end = inf->mmap_addr + inf->mmap_length;
	i = 0;

	for (next = start; next < end;
	     next += ((multiboot_memory_map_t *)next)->size + 4) {
		multiboot_memory_map_t *map = (multiboot_memory_map_t *)next;
		e820->memory_map_entry[i].basic_entry.base_address = map->addr;
		e820->memory_map_entry[i].basic_entry.length = map->len;
		e820->memory_map_entry[i].basic_entry.address_range_type = map->type;
		e820->memory_map_entry[i].extended_attributes.uint32 = 1;
		i++;
	}

	e820->memory_map_size = i * sizeof(int15_e820_memory_map_entry_ext_t);
	*e820_addr = (uint64_t)(uint32_t)e820;
	return TRUE;
}

boolean_t get_e820_table_from_mb2(xmon_desc_t *xd, uint64_t *e820_addr)
{
	int15_e820_memory_map_t *e820;
	uint32_t start;
	uint32_t next;
	uint32_t end;
	struct mb2_tag_mmap *mb_info;
	int i;

	mb_info =
		(struct mb2_tag_mmap *)get_mb2_tag_type(MB2_TAG_START(xd->
				mb_initial_state.
				ebx), MB2_TAG_TYPE_MMAP);
	if (mb_info == NULL) {
		return FALSE;
	}
	if ((mb_info->size - 4 * sizeof(uint32_t)) > 4096) {
		return FALSE;
	}

	e820 = (int15_e820_memory_map_t *)mon_page_alloc(1);

	if (e820 == NULL) {
		return FALSE;
	}

	start = (uint32_t)mb_info->entries;
	end = (uint32_t)mb_info->entries + mb_info->size - 4 * sizeof(uint32_t);
	i = 0;

	for (next = start; next < end; next += mb_info->entry_size) {
		struct mb2_mmap_entry *map = (struct mb2_mmap_entry *)next;

		e820->memory_map_entry[i].basic_entry.base_address = map->addr;
		e820->memory_map_entry[i].basic_entry.length = map->len;
		e820->memory_map_entry[i].basic_entry.address_range_type = map->type;
		e820->memory_map_entry[i].extended_attributes.uint32 = 1;
		i++;
	}

	e820->memory_map_size = i * sizeof(int15_e820_memory_map_entry_ext_t);
	*e820_addr = (uint64_t)(uint32_t)e820;
	return TRUE;
}

int copy_e820_table_from_efi(xmon_desc_t *xd, uint64_t *e820_addr)
{
	int15_e820_memory_map_t *e820;
	void *inf;

	inf = (void *)((uint32_t)(xd->mb_initial_state.ebx));

	e820 = (int15_e820_memory_map_t *)mon_page_alloc(1);

	if (e820 == NULL) {
		return -1;
	}

	mon_memcpy(e820, inf, 4096);
	*e820_addr = (uint64_t)(uint32_t)e820;

	return 0;
}

/*
 * copy e820 memory info to other address, and hide some memories in e820 table.
 */
boolean_t hide_runtime_memory_mb1(xmon_desc_t *xd,
				 uint32_t hide_mem_addr,
				 uint32_t hide_mem_size)
{
	uint32_t num_of_entries, entry_idx;
	multiboot_memory_map_t *newmmap_addr;
	multiboot_info_t *mbi = (multiboot_info_t *)xd->mb_initial_state.ebx;

	/* Are mmap_* valid? */
	if (!(mbi->flags & MBI_MEMMAP)) {
		return FALSE;
	}

	multiboot_memory_map_t *mmap;

	/* add space for two more entries for boundary case. */
	num_of_entries = mbi->mmap_length / sizeof(multiboot_memory_map_t) + 2;
	newmmap_addr = (multiboot_memory_map_t *)
		       allocate_memory(
		sizeof(multiboot_memory_map_t) * num_of_entries);
	if (!newmmap_addr) {
		return FALSE;
	}


	for (entry_idx = 0, mmap = (multiboot_memory_map_t *)mbi->mmap_addr;
	     (unsigned long)mmap < mbi->mmap_addr + mbi->mmap_length;
	     entry_idx++, mmap = (multiboot_memory_map_t *)
				 ((unsigned long)mmap + mmap->size +
				  sizeof(mmap->size))) {
		if (((mmap->addr + mmap->len) <= hide_mem_addr) ||
		    ((hide_mem_addr + hide_mem_size) <= mmap->addr)) {
			/* do not modify it */
			mon_memcpy(&newmmap_addr[entry_idx], mmap,
				sizeof(multiboot_memory_map_t));
		} else {
			/* input address range to be hidden needs to be of type AVAILABLE. */
			if (mmap->type != MULTIBOOT_MEMORY_AVAILABLE) {
				print_string(
					"ERROR: the type of memory to hide is not AVAILABLE in e820 table!!\n");
				return FALSE;
			}

			newmmap_addr[entry_idx].size = mmap->size;
			newmmap_addr[entry_idx].addr = mmap->addr;
			newmmap_addr[entry_idx].len = hide_mem_addr - mmap->addr;
			newmmap_addr[entry_idx].type = mmap->type;

			entry_idx++;

			newmmap_addr[entry_idx].size = mmap->size;
			newmmap_addr[entry_idx].addr = hide_mem_addr;
			newmmap_addr[entry_idx].len = hide_mem_size;
			newmmap_addr[entry_idx].type = MULTIBOOT_MEMORY_RESERVED;

			if ((hide_mem_addr + hide_mem_size) >
			    (mmap->addr + mmap->len)) {
				print_string(
					"ERROR: hide_mem_addr+hide_mem_size crossing two E820 entries!!\n");
				return FALSE;
			}

			if ((hide_mem_addr + hide_mem_size) <
			    (mmap->addr + mmap->len)) {
				/* need one more entry */
				entry_idx++;
				newmmap_addr[entry_idx].size = mmap->size;
				newmmap_addr[entry_idx].addr = hide_mem_addr +
							       hide_mem_size;
				newmmap_addr[entry_idx].len =
					(mmap->addr +
					 mmap->len) -
					(hide_mem_addr + hide_mem_size);
				newmmap_addr[entry_idx].type = mmap->type;
			} else {
				/* no need one more entry */
			}
		}
	}

	/* update map addr and len (entry_idx, using the exact entry num value) */
	mbi->mmap_addr = (uint32_t)newmmap_addr;
	mbi->mmap_length = sizeof(multiboot_memory_map_t) * entry_idx; /* do not use num_of_entries*/

	return TRUE;
}


boolean_t hide_runtime_memory_mb2(xmon_desc_t *xd,
				 uint32_t hide_mem_addr,
				 uint32_t hide_mem_size)
{
	uint32_t num_of_entries, entry_idx;

	struct mb2_tag *original_tag = (struct mb2_tag *)(xd->mb_initial_state.ebx);
	/* size = the whole size of original multiboot2 information */
	uint32_t size = *(uint32_t *)(xd->mb_initial_state.ebx);
	/* Allocate memory for the new multiboot2 information
	 *  Need more entries to hide xmon/startap runtime memories
	 *  There are two scenarios:
	 *  1. need two more entries:
	 *  (entry1)- (xmon_runtime_memory_base) - (xmon_runtime_memory_base+xmon_runtime_memory_size)- (entry2)
	 *  2. need only one more entry:
	 *  (entry1)- (xmon_runtime_memory_base) - (xmon_runtime_memory_base+xmon_runtime_memory_size)- (END)
	 */
	struct mb2_tag *new_tag = (struct mb2_tag *)allocate_memory(
		size + 2 * sizeof(struct mb2_mmap_entry));

	struct mb2_tag *tmp_tag = MB2_TAG_START(new_tag);

	original_tag = MB2_TAG_START(xd->mb_initial_state.ebx);

	while (original_tag != NULL) {
		if (original_tag->type == MB2_TAG_TYPE_END) {
			tmp_tag->type = original_tag->type;
			tmp_tag->size = original_tag->size;
			break;
		}
		if (original_tag->type != MB2_TAG_TYPE_MMAP) {
			mon_memcpy(tmp_tag, original_tag,
				((uint32_t)next_mb2_tag(original_tag) -
				 (uint32_t)original_tag));
		} else {
			struct mb2_tag_mmap *new_mmap_tag =
				(struct mb2_tag_mmap *)tmp_tag;
			struct mb2_mmap_entry *mmap;

			/* need max two more entries
			 *  including consider the boundary case.
			 */
			num_of_entries =
				(((struct mb2_tag_mmap *)original_tag)->size - 4 *
				 sizeof(uint32_t)) / sizeof(struct mb2_mmap_entry) +
				2;

			for (entry_idx = 0,
			     mmap = ((struct mb2_tag_mmap *)original_tag)->entries;
			     (unsigned long)mmap <
			     (unsigned long)original_tag +
			     ((struct mb2_tag_mmap *)original_tag)->size;
			     entry_idx++, mmap = (struct mb2_mmap_entry *)
						 ((unsigned long)mmap +
						  ((struct mb2_tag_mmap *)
						   original_tag)->entry_size)) {
				if (((mmap->addr + mmap->len) <= hide_mem_addr) ||
				    ((hide_mem_addr + hide_mem_size) <=
				     mmap->addr)) {
					/* do not modify it */
					mon_memcpy(&new_mmap_tag->entries[entry_idx],
						mmap,
						sizeof(struct mb2_mmap_entry));
				} else {
					/* input address range to be hidden needs to be of type AVAILABLE. */
					if (mmap->type !=
					    MULTIBOOT_MEMORY_AVAILABLE) {
						return FALSE;
					}

					new_mmap_tag->entries[entry_idx].zero =
						mmap->zero;
					new_mmap_tag->entries[entry_idx].addr =
						mmap->addr;
					new_mmap_tag->entries[entry_idx].len =
						hide_mem_addr - mmap->addr;
					new_mmap_tag->entries[entry_idx].type =
						mmap->type;

					entry_idx++;

					new_mmap_tag->entries[entry_idx].zero =
						mmap->zero;
					new_mmap_tag->entries[entry_idx].addr =
						hide_mem_addr;
					new_mmap_tag->entries[entry_idx].len =
						hide_mem_size;
					new_mmap_tag->entries[entry_idx].type =
						MULTIBOOT_MEMORY_RESERVED;

					if ((hide_mem_addr + hide_mem_size) >
					    (mmap->addr + mmap->len)) {
						return FALSE;
					}

					if ((hide_mem_addr + hide_mem_size) <
					    (mmap->addr + mmap->len)) {
						/* need one more entry */
						entry_idx++;
						new_mmap_tag->entries[entry_idx].zero
							= mmap->zero;
						new_mmap_tag->entries[entry_idx].addr
							= hide_mem_addr +
							  hide_mem_size;
						new_mmap_tag->entries[entry_idx].len
							= (mmap->addr + mmap->len) -
							  (hide_mem_addr +
							   hide_mem_size);
						new_mmap_tag->entries[entry_idx].type
							= mmap->type;
					} else {
						/* no need one more entry */
					}
				}
			}

			/* update map addr and len (entry_idx, using the exact entry num value) */
			new_mmap_tag->type = original_tag->type;
			new_mmap_tag->size = sizeof(uint32_t) * 4 +
					     sizeof(struct mb2_mmap_entry) *
					     entry_idx;                                                               /* do not use num_of_entries*/
			new_mmap_tag->entry_size =
				((struct mb2_tag_mmap *)original_tag)->entry_size;
			new_mmap_tag->entry_version =
				((struct mb2_tag_mmap *)original_tag)->entry_version;
		}
		tmp_tag = next_mb2_tag(tmp_tag);
		original_tag = next_mb2_tag(original_tag);
	}
	xd->mb_initial_state.ebx = (uint32_t)new_tag;
	return TRUE;
}

/* End of file */
