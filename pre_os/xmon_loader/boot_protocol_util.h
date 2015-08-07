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

#ifndef BOOT_PROTOCOL_UTIL_H
#define BOOT_PROTOCOL_UTIL_H

#include "xmon_desc.h"
#include "multiboot.h"
#include "linux_loader.h"

typedef struct {
	char name[10];

	boolean_t (*get_e820_table)(xmon_desc_t *td, uint64_t *e820_addr);
	boolean_t (*hide_runtime_memory)(xmon_desc_t *xd, uint32_t hide_mem_addr,
					uint32_t hide_mem_size);
	multiboot_module_t *(*get_module)(xmon_desc_t *xd,
					  grub_module_index_t midx);
	char *(*get_module_cmdline)(xmon_desc_t *xd,
				    grub_module_index_t midx);
	void (*get_highest_sized_ram)(xmon_desc_t *xd, uint64_t size, uint64_t limit,
				      uint64_t *ram_base, uint64_t *ram_size);
	boolean_t (*setup_boot_params)(xmon_desc_t *xd, boot_params_t *boot_params,
				       linux_kernel_header_t *hdr);
	boolean_t (*is_loader_launch_efi)(xmon_desc_t *xd);
	void (*parse_mb_xmon_cmdline)(xmon_desc_t *xd);
} boot_protocol_ops_t;

boolean_t protocol_ops_init(uint32_t boot_magic);
boolean_t loader_get_e820_table(xmon_desc_t *td, uint64_t *e820_addr);
boolean_t loader_hide_runtime_memory(xmon_desc_t *xd,
				    uint32_t hide_mem_addr,
				    uint32_t hide_mem_size);
multiboot_module_t *loader_get_module(xmon_desc_t *xd, grub_module_index_t midx);
char *loader_get_module_cmdline(xmon_desc_t *xd, grub_module_index_t midx);
void loader_get_highest_sized_ram(xmon_desc_t *xd,
				  uint64_t size,
				  uint64_t limit,
				  uint64_t *ram_base,
				  uint64_t *ram_size);
boolean_t loader_setup_boot_params(xmon_desc_t *xd,
				   boot_params_t *boot_params,
				   linux_kernel_header_t *hdr);
boolean_t is_loader_launch_efi(xmon_desc_t *xd);
void loader_parse_mb_xmon_cmdline(xmon_desc_t *xd);

#endif    /* BOOT_PROTOCOL_UTIL_H */
