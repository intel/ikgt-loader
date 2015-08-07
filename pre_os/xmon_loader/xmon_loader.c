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
#include "image_loader.h"
#include "memory.h"
#include "x32_gdt64.h"
#include "x32_pt64.h"
#include "x32_init64.h"
#include "xmon_desc.h"
#include "common.h"
#include "boot_protocol_util.h"
#include "screen.h"
#include "error_code.h"
#include "cmdline.h"
#include "multiboot_util.h"
#include "string.h"
#include "loader_serial.h"


void __cpuid(int cpu_info[4], int info_type);
extern mon_guest_startup_t *setup_primary_guest_env(xmon_desc_t *td);

static uint32_t get_xmon_img_base(xmon_desc_t *xmon_desc)
{
	xmon_runtime_memory_layout_t *rt_mem;

	rt_mem = (xmon_runtime_memory_layout_t *)xmon_desc->runtime_mem_addr;


	return (uint32_t)rt_mem->u_xmon.img_base;
}

static uint32_t get_startap_img_base(xmon_desc_t *xmon_desc)
{
	xmon_runtime_memory_layout_t *rt_mem;

	rt_mem = (xmon_runtime_memory_layout_t *)xmon_desc->runtime_mem_addr;

	return (uint32_t)rt_mem->u_startap_img.base;
}

/*
 * cmdline for xmon inputs.
 * it will be updated after parsing.
 *
 * This structure can include options without value.
 * 1. option has no value ( no = ), and not present by default.
 * { "example1", "0"}
 * 2. option doesn't have value ( no = )
 * { "example2", CMD_OPTION_PRESENT_BUT_NO_VALUE}
 */
cmdline_string_options_t xmon_cmdline_options[] = {
	/* io debug port for xmon dbg message print */
	{ "iobase=",  "0"				 },

	/* efi, sfi, grub(default) */
	{ "type=",    "grub"				 },

	/* appended by tboot to pass tboot shared address */
	{ "tboot=",   "0"				 },

	/* keep this as last one */
	{ "\0",	      "\0"				 }
};

/*
 *  parse cmdline (options/values pair) in mbi.
 */
void parse_mb_xmon_cmdline_mb1(xmon_desc_t *xd)
{
	multiboot_info_t *mbi;

	/*
	 * get mbi information from rbx passed on
	 * by grub or other bootloaders
	 */
	mbi = (multiboot_info_t *)(xd->mb_initial_state.ebx);

	/*
	 * parse cmdline if cmdline is available.
	 */
	if (mbi->flags & MBI_CMDLINE) {
		if (XMON_LOADER_SUCCESS !=
		    parse_cmdline((char *)(mbi->cmdline),
			    xmon_cmdline_options)) {
			print_string(
				"WARN: failed to parse grub cmdline, ignore it, use default values\n");
			return;
		}
	}

	return;
}

/*
 * parse cmdline (options/values pair) in mbi.
 */
void parse_mb_xmon_cmdline_mb2(xmon_desc_t *xd)
{
	struct mb2_tag_string *cmdline_tag = NULL;

	cmdline_tag = (struct mb2_tag_string *)get_mb2_tag_type(
		MB2_TAG_START(xd->mb_initial_state.ebx),
		MB2_TAG_TYPE_CMDLINE);
	if (cmdline_tag != NULL) {
		if (XMON_LOADER_SUCCESS !=
		    parse_cmdline((char *)(cmdline_tag->string),
			    xmon_cmdline_options)) {
			print_string(
				"WARN: failed to parse grub cmdline, ignore it, use default values\n");
			return;
		}
	}

	return;
}


 /*
  * get ioport base address in cmdline from grub.
  * if no port or zero base, then no serial port output.
  */
static uint32_t get_io_base_from_cmdline_option()
{
	const char *iobasestr =
		get_cmdline_value_str(xmon_cmdline_options, "iobase=");
	uint16_t io_base;

	if (iobasestr == NULL) {
		io_base = 0;                                            /* not exists */
	} else {
		io_base = (uint16_t)strtoul(iobasestr, NULL, 16);       /* can be zero */
	}

	return io_base;
}

static boolean_t setup_startup_env(xmon_desc_t *xmon_desc,
				   mon_guest_startup_t *primary_guest,
				   mon_guest_startup_t *secondary_guest_array,
				   uint32_t secondary_guest_count)
{
	mon_startup_struct_t *mon_env;
	uint64_t e820_addr;

	if (!loader_get_e820_table(xmon_desc, &e820_addr)) {
		return FALSE;
	}

	mon_env = &(xmon_desc->mon_env);

	mon_env->size_of_this_struct = sizeof(mon_startup_struct_t);
	mon_env->version_of_this_struct = MON_STARTUP_STRUCT_VERSION;
	mon_env->number_of_processors_at_install_time = 1;      /* not used by xmon */
	mon_env->number_of_processors_at_boot_time = 1;         /* will be updated by startap */
	mon_env->number_of_secondary_guests = secondary_guest_count;
	mon_env->size_of_mon_stack = MON_DEFAULT_STACK_SIZE_PAGES;
	mon_env->flags = 0;

	mon_env->primary_guest_startup_state = (uint64_t)((uint32_t)primary_guest) &
					       0x0000000FFFFFFFF;
	mon_env->physical_memory_layout_E820 = e820_addr;

	mon_env->mon_memory_layout[mon_image].base_address =
		xmon_desc->xmon.img_base;
	mon_env->mon_memory_layout[mon_image].entry_point =
		xmon_desc->xmon.entry_point & 0x0000000FFFFFFFF;
	mon_env->mon_memory_layout[mon_image].image_size = MON_PAGE_ALIGN_4K(
		xmon_desc->xmon.hdr_info.load_size);
	mon_env->mon_memory_layout[mon_image].total_size =
		xmon_desc->xmon.total_size;

	mon_env->mon_memory_layout[thunk_image].base_address =
		xmon_desc->startap.img_base;
	mon_env->mon_memory_layout[thunk_image].entry_point =
		xmon_desc->startap.entry_point;
	mon_env->mon_memory_layout[thunk_image].image_size = MON_PAGE_ALIGN_4K(
		xmon_desc->startap.hdr_info.load_size);
	mon_env->mon_memory_layout[thunk_image].total_size =
		xmon_desc->startap.total_size;


	/* set debug params */
	uint16_t io_base = get_io_base_from_cmdline_option();

	if (io_base == 0) {
		mon_env->debug_params.port.type = MON_DEBUG_PORT_NONE;
		mon_env->debug_params.port.ident_type = MON_DEBUG_PORT_IDENT_DEFAULT;
		mon_env->debug_params.port.ident.io_base = 0;
		mon_env->debug_params.mask = 0;
	} else {
		mon_env->debug_params.port.type = MON_DEBUG_PORT_SERIAL;     /*0x01 00 00 01*/
		mon_env->debug_params.port.ident_type = MON_DEBUG_PORT_IDENT_IO;
		mon_env->debug_params.mask = (uint64_t)-1;
		mon_env->debug_params.port.ident.io_base = io_base;
	}


	mon_env->debug_params.verbosity = 4;
	mon_env->debug_params.port.virt_mode = MON_DEBUG_PORT_VIRT_NONE;
	mon_env->debug_params.port.reserved_1 = 0;

	return TRUE;
}

static void heap_init(xmon_desc_t *xmon_desc)
{
	xmon_loader_memory_layout_t *loader_mem =
		(xmon_loader_memory_layout_t *)(xmon_desc->loader_mem_addr);

	/* TODO:
	 * if required, we can make this function position-independent by remove the global
	 * variables, like heap_current, heap_tops and heap_base.
	 */
	initialize_memory_manager((uint32_t)loader_mem->u_ldr_heap.base,
		LOADER_HEAP_SIZE);
}

static uint32_t setup_env(xmon_desc_t *xd)
{
	mon_guest_startup_t *primary_guest;
	mon_guest_startup_t *secondary_guest_array;
	uint32_t secondary_guest_count = 0;

	/* firstly setup primary guest env */
	primary_guest = setup_primary_guest_env(xd);
	if (!primary_guest) {
		return XMON_FAILED_TO_SETUP_PRIMARY_GUEST_ENV;
	}

	/* finally setup startup environment */
	if (!setup_startup_env(xd, primary_guest, secondary_guest_array,
		    secondary_guest_count)) {
		return XMON_LOADER_FAILED_TO_SETUP_STARTUP_ENV;
	}

	return XMON_LOADER_SUCCESS;
}

uint32_t xmon_loader(xmon_desc_t *xd)
{
	static init64_struct_t init64;
	static init32_struct_t init32;

	image_info_status_t image_info_status;

	mon_startup_struct_t *mon_env;
	startap_image_entry_point_t call_startap_entry;
	uint64_t call_startap;
	uint64_t call_xmon;

	uint32_t heap_base;
	uint32_t heap_size;

	void *p_xmon = NULL;
	void *p_startap = NULL;
	void *p_low_mem = (void *)AP_WAKEUP_BOOTSTRAP_CODE_ADDR;

	int info[4] = { 0, 0, 0, 0 };
	int num_of_aps;
	boolean_t ok;
	int r;
	int i;

	uint32_t ret;

	if (!protocol_ops_init(xd->mb_initial_state.eax)) {
		print_string("protocol_ops_init failed\n");
		return XMON_LOADER_FAILED_TO_INIT_PROTOCOL_OPS;
	}

	/*
	 * parse mbi cmdline to update xmon_cmdline_options[]
	 */
	loader_parse_mb_xmon_cmdline(xd);

	/*
	 * Init serial port
	 * This function should be called after parsing grub cmdline.
	 * And before init, no log will be print through serial port.
	 */
	loader_serial_init(get_io_base_from_cmdline_option());

	/* currently only support grub bootloader */
	if (strcmp(get_cmdline_value_str(xmon_cmdline_options, "type="),
		    "grub") != 0) {
		print_string("ERROR: not supported bootloader\n");
		return XMON_CODING_ERROR;
	}

	/* Init loader heap, run-time space, and idt. */
	heap_init(xd);

	xd->xmon.img_base = get_xmon_img_base(xd);
	p_xmon = (void *)(xd->xmon_file.addr);
	image_info_status = get_image_info(p_xmon,
		xd->xmon_file.size,
		&(xd->xmon.hdr_info));
	if ((image_info_status != IMAGE_INFO_OK) ||
	    (xd->xmon.hdr_info.machine_type != IMAGE_MACHINE_EM64T) ||
	    (xd->xmon.hdr_info.load_size == 0) ||
	    (xd->xmon.hdr_info.load_size > xd->xmon.total_size)) {
		return XMON_LOADER_FAILED_TO_GET_XMON_IMG_INFO;
	}

	/* Load xmon image */
	ok = load_image(p_xmon,
		(void *)(xd->xmon.img_base),
		xd->xmon.hdr_info.load_size,
		&call_xmon);
	if (!ok) {
		return XMON_LOADER_FAILED_TO_LOAD_XMON_IMG;
	}

	xd->xmon.entry_point = (uint32_t)call_xmon;

	/* Load startap image */
	xd->startap.img_base = get_startap_img_base(xd);
	xd->startap.total_size = STARTAP_IMG_SIZE;

	p_startap = (void *)(xd->startap_file.addr);

	image_info_status = get_image_info((void *)p_startap,
		xd->startap_file.size,
		&(xd->startap.hdr_info));
	if ((image_info_status != IMAGE_INFO_OK) ||
	    (xd->startap.hdr_info.machine_type != IMAGE_MACHINE_X86) ||
	    (xd->startap.hdr_info.load_size == 0) ||
	    (xd->startap.hdr_info.load_size > STARTAP_IMG_SIZE)) {
		return XMON_LOADER_FAILED_TO_GET_STARTAP_IMG_INFO;
	}

	ok = load_image((void *)p_startap,
		(void *)(xd->startap.img_base),
		xd->startap.hdr_info.load_size, &call_startap);

	if (!ok) {
		return XMON_LOADER_FAILED_TO_LOAD_STARTAP_IMG;
	}

	xd->startap.entry_point = (uint32_t)call_startap;

	/* setup xmon/primary/secondary guests startup env */
	ret = setup_env(xd);
	if (XMON_LOADER_SUCCESS != ret) {
		return ret;
	}

	/* hide xmon/startap runtime memories*/
	if (!loader_hide_runtime_memory(xd, xd->runtime_mem_addr,
			XMON_RUNTIME_MEMORY_SIZE)) {
		return XMON_FAILED_TO_HIDE_RUNTIME_MEMORY;
	}


	/* Setup init32. */
	/* Use the max number of logical cores which xmon supports.
	 * It will be OK here since it only waste some memory
	 * (STARTUP_AP_STACK_SIZE(1024bytes) for each core) and
	 * the memory will be abandoned after MON lunch and
	 * MON will get the real number using SIPI.
	 */
	num_of_aps = MAX_CPUS - 1;

	xd->startap.init32.i32_low_memory_page = (uint32_t)p_low_mem;
	xd->startap.init32.i32_num_of_aps = num_of_aps;

	for (i = 0; i < num_of_aps; i++) {
		uint8_t *buf = allocate_memory(STARTUP_AP_STACK_SIZE);
		if (buf == NULL) {
			return XMON_LOADER_FAILED_TO_INIT_INIT32;
		}

		xd->startap.init32.i32_esp[i] =
			(uint32_t)&buf[STARTUP_AP_STACK_SIZE - 4];
	}

	/* Setup init64. */
	x32_gdt64_setup();
	x32_gdt64_get_gdtr(&(xd->startap.init64).i64_gdtr);
	x32_pt64_setup_paging(((uint64_t)1024 * 4) * 0x100000);
	xd->startap.init64.i64_cr3 = x32_pt64_get_cr3();
	xd->startap.init64.i64_cs = x32_gdt64_get_cs();
	xd->startap.init64.i64_efer = 0;

	call_startap_entry = (startap_image_entry_point_t)((uint32_t)call_startap);
	call_startap_entry((num_of_aps != 0) ? &(xd->startap.init32) : 0,
		&(xd->startap.init64), &xd->mon_env, (uint32_t)call_xmon);

	while (1) {
	}
}

/* End of file */
