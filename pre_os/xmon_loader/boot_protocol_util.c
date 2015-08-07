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


#include "common_types.h"
#include "mon_defs.h"
#include "mon_arch_defs.h"
#include "mon_startup.h"
#include "startap.h"
#include "loader.h"
#include "xmon_desc.h"
#include "common.h"
#include "xmon_loader.h"
#include "multiboot.h"
#include "boot_protocol_util.h"
#include "linux_loader.h"
#include "e820.h"
#include "multiboot_util.h"

static boot_protocol_ops_t *boot_protocol_ops;

static boot_protocol_ops_t default_ops = {
	.name	= "default",
};

static boot_protocol_ops_t mb1_ops = {
	.name			= "mb1",
	.get_e820_table		= get_e820_table_from_mb1,
	.hide_runtime_memory	= hide_runtime_memory_mb1,
	.get_module		= get_module_mb1,
	.get_module_cmdline	= get_module_cmdline_mb1,
	.get_highest_sized_ram	= get_highest_sized_ram_mb1,
	.setup_boot_params	= setup_boot_params_mb1,
	.is_loader_launch_efi	= is_loader_launch_efi_mb1,
	.parse_mb_xmon_cmdline	= parse_mb_xmon_cmdline_mb1,
};

static boot_protocol_ops_t mb2_ops = {
	.name			= "mb2",
	.get_e820_table		= get_e820_table_from_mb2,
	.hide_runtime_memory	= hide_runtime_memory_mb2,
	.get_module		= get_module_mb2,
	.get_module_cmdline	= get_module_cmdline_mb2,
	.get_highest_sized_ram	= get_highest_sized_ram_mb2,
	.setup_boot_params	= setup_boot_params_mb2,
	.is_loader_launch_efi	= is_loader_launch_efi_mb2,
	.parse_mb_xmon_cmdline	= parse_mb_xmon_cmdline_mb2,
};

boolean_t protocol_ops_init(uint32_t boot_magic)
{
	if (boot_magic == MULTIBOOT_BOOTLOADER_MAGIC) {
		boot_protocol_ops = &mb1_ops;
		return true;
	} else if (boot_magic == MULTIBOOT2_BOOTLOADER_MAGIC) {
		boot_protocol_ops = &mb2_ops;
		return true;
	} else {
		boot_protocol_ops = &default_ops;
		return false;
	}
}

boolean_t loader_get_e820_table(xmon_desc_t *xd, uint64_t *e820_addr)
{
	if (boot_protocol_ops->get_e820_table) {
		return boot_protocol_ops->get_e820_table(xd, e820_addr);
	} else {
		return false;
	}
}

boolean_t loader_hide_runtime_memory(xmon_desc_t *xd, uint32_t hide_mem_addr,
				    uint32_t hide_mem_size)
{
	if (boot_protocol_ops->hide_runtime_memory) {
		return boot_protocol_ops->hide_runtime_memory(xd, hide_mem_addr,
			hide_mem_size);
	} else {
		/* No need to hide runtime memory
		 * hide_run_time_memory() is not a must for some boot loaders,
		 * for instance, EFI Kernelflinger
		 */
		return true;
	}
}

multiboot_module_t *loader_get_module(xmon_desc_t *xd,
				      grub_module_index_t midx)
{
	if (boot_protocol_ops->get_module) {
		return boot_protocol_ops->get_module(xd, midx);
	} else {
		return NULL;
	}
}

char *loader_get_module_cmdline(xmon_desc_t *xd,
				grub_module_index_t midx)
{
	if (boot_protocol_ops->get_module_cmdline) {
		return boot_protocol_ops->get_module_cmdline(xd, midx);
	} else {
		return NULL;
	}
}

void loader_get_highest_sized_ram(xmon_desc_t *xd,
				  uint64_t size, uint64_t limit,
				  uint64_t *ram_base, uint64_t *ram_size)
{
	if (boot_protocol_ops->get_highest_sized_ram) {
		return boot_protocol_ops->get_highest_sized_ram(xd, size, limit,
			ram_base, ram_size);
	} else {
		return;
	}
}

boolean_t loader_setup_boot_params(xmon_desc_t *xd,
				   boot_params_t *boot_params,
				   linux_kernel_header_t *hdr)
{
	if (boot_protocol_ops->setup_boot_params) {
		return boot_protocol_ops->setup_boot_params(xd, boot_params, hdr);
	} else {
		return false;
	}
}

boolean_t is_loader_launch_efi(xmon_desc_t *xd)
{
	if (boot_protocol_ops->is_loader_launch_efi) {
		return boot_protocol_ops->is_loader_launch_efi(xd);
	} else {
		return false;
	}
}

void loader_parse_mb_xmon_cmdline(xmon_desc_t *xd)
{
	if (boot_protocol_ops->parse_mb_xmon_cmdline) {
		return boot_protocol_ops->parse_mb_xmon_cmdline(xd);
	} else {
		return;
	}
}
