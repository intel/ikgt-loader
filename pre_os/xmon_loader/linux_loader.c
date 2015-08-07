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
#include "common.h"
#include "multiboot.h"
#include "linux_loader.h"
#include "screen.h"
#include "ia32_low_level.h"
#include "error_code.h"
#include "memory.h"
#include "mon_startup.h"
#include "boot_protocol_util.h"
#include "multiboot_util.h"
#include "cmdline.h"
#include "string.h"

extern cmdline_string_options_t xmon_cmdline_options[];

static inline boolean_t plus_overflow_u32(uint32_t x, uint32_t y)
{
	return (((uint32_t)(~0)) - x) < y;
}

/* set address of tboot shared page for measured launch
 *  check "tboot=%p" in starter.bin cmdline appended by tboot code.
 *  (not the cmdline on module "linux vmlinuz")
 */
static uint32_t get_tboot_shared_addr()
{
	const char *tboot_cmdline = get_cmdline_value_str(xmon_cmdline_options,
		"tboot=");

	if (tboot_cmdline == NULL) {
		return 0; /* not exists */
	} else {
		/* convert string to value */
		return strtoul(tboot_cmdline, NULL, 16);
	}
}

static void setup_tboot_shared_addr(uint64_t *tboot_shared_addr)
{
	/* get tboot shared address from cmdline (filled by tboot code if boot xmon with tboot) */
	*tboot_shared_addr = (uint64_t)get_tboot_shared_addr() &
			     0x00000000ffffffffUL;

	if (*tboot_shared_addr != 0) {
		print_string_value("tboot shared addr =0x",
			*(uint32_t *)tboot_shared_addr);
	}

}

/*
 * retrieve the grub module from mbi info.
 */
multiboot_module_t *get_module_mb1(xmon_desc_t *xd,
				   grub_module_index_t midx)
{
	multiboot_info_t *mbi = (multiboot_info_t *)xd->mb_initial_state.ebx;

	if (mbi->mods_count == 0) {
		print_string("At least one module available.\n");
		return NULL;
	}

	/* module not exist */
	if (midx > mbi->mods_count) {
		return NULL;
	}

	multiboot_module_t *mod = (multiboot_module_t *)mbi->mods_addr;

	return &mod[midx];
}

multiboot_module_t *get_module_mb2(xmon_desc_t *xd,
				   grub_module_index_t midx)
{
	struct mb2_tag *start = MB2_TAG_START(xd->mb_initial_state.ebx);
	uint32_t i = 0;
	struct mb2_tag_module *mod_tag = NULL;
	multiboot_module_t *mod = NULL;

	start = get_mb2_tag_type(start, MB2_TAG_TYPE_MODULE);
	if (start != NULL) {
		for (i = 0; i < midx; i++) {
			if (start == NULL) {
				return NULL;
			} else {
				start = next_mb2_tag(start);
				start = get_mb2_tag_type(start, MB2_TAG_TYPE_MODULE);
			}
		}
		mod_tag = (struct mb2_tag_module *)start;
		mod = (multiboot_module_t *)&(mod_tag->mod_start);
	}
	return mod;
}

/*
 * find highest (less than <limit>) RAM region of at least <size> bytes
 */
void get_highest_sized_ram_mb1(xmon_desc_t *xd,
			       uint64_t size, uint64_t limit,
			       uint64_t *ram_base, uint64_t *ram_size)
{
	uint64_t last_fit_base = 0, last_fit_size = 0;

	multiboot_info_t *mbi = (multiboot_info_t *)xd->mb_initial_state.ebx;

	multiboot_memory_map_t *mmap = (multiboot_memory_map_t *)(mbi->mmap_addr);

	/* walk through each one of mem map entry to get highest aviable address */
	for (unsigned int i = 0;
	     i < mbi->mmap_length / sizeof(multiboot_memory_map_t); i++) {
		multiboot_memory_map_t *entry = &(mmap[i]);

		/* only check AVAILABLE memory range */
		if (entry->type == MULTIBOOT_MEMORY_AVAILABLE) {
			uint64_t base = entry->addr;
			uint64_t length = entry->len;

			/* over "limit" so use the last region that fits */
			if (base + length > limit) {
				break;
			}

			if (size <= length) {
				/* do not assume the "base" is always larger than "last_fit_base" */
				if (base > last_fit_base) {
					last_fit_base = base;
					last_fit_size = length;
				}
			}
		}
	}

	*ram_base = last_fit_base;
	*ram_size = last_fit_size;
}

void get_highest_sized_ram_mb2(xmon_desc_t *xd,
			       uint64_t size, uint64_t limit,
			       uint64_t *ram_base, uint64_t *ram_size)
{
	struct mb2_tag *tag = MB2_TAG_START(xd->mb_initial_state.ebx);
	uint64_t last_fit_base = 0, last_fit_size = 0;

	if (ram_base == NULL || ram_size == NULL) {
		return;
	}

	struct mb2_tag_mmap *mmap_tag = (struct mb2_tag_mmap *)get_mb2_tag_type(tag,
		MB2_TAG_TYPE_MMAP);
	struct mb2_mmap_entry *mmap = mmap_tag->entries;

	for (unsigned int i = 0;
	     i < (mmap_tag->size - 4 * sizeof(uint32_t)) / mmap_tag->entry_size;
	     i++) {
		struct mb2_mmap_entry *entry = &(mmap[i]);

		if (entry->type == MULTIBOOT_MEMORY_AVAILABLE) {
			uint64_t base = entry->addr;
			uint64_t length = entry->len;

			/* over "limit" so use the last region that fit */
			if (base + length > limit) {
				break;
			}
			if (size <= length) {
				/* do not assume the "base" is always larger than "last_fit_base" */
				if (base > last_fit_base) {
					last_fit_base = base;
					last_fit_size = length;
				}
			}
		}
	}

	*ram_base = last_fit_base;
	*ram_size = last_fit_size;
}

void load_fb_info(xmon_desc_t *xd, void *vscr)
{
	screen_info_t *scr = (screen_info_t *)vscr;
	struct mb2_tag *start;

	if (scr == NULL) {
		return;
	}
	start = MB2_TAG_START(xd->mb_initial_state.ebx);
	start = get_mb2_tag_type(start, MB2_TAG_TYPE_FRAMEBUFFER);
	if (start != NULL) {
		struct mb2_tag_fb *mbf = (struct mb2_tag_fb *)start;

		scr->lfb_base = (uint32_t)mbf->common.fb_addr;
		scr->lfb_width = mbf->common.fb_width;
		scr->lfb_height = mbf->common.fb_height;
		scr->lfb_depth = mbf->common.fb_bpp;
		scr->lfb_line_len = mbf->common.fb_pitch;
		scr->red_mask_size = mbf->fb_red_mask_size;
		scr->red_field_pos = mbf->fb_red_field_position;
		scr->blue_mask_size = mbf->fb_blue_mask_size;
		scr->blue_field_pos = mbf->fb_blue_field_position;
		scr->green_mask_size = mbf->fb_green_mask_size;
		scr->green_field_pos = mbf->fb_green_field_position;
		scr->lfb_size = scr->lfb_line_len * scr->lfb_height;
		scr->lfb_size = (scr->lfb_size + 65535) & 65535;        /* round up to next 64k */
		scr->orig_video_is_vga = 0x70;                          /* EFI FB */
		scr->orig_y = 24;
	}
}

void prepare_efi_info(xmon_desc_t *xd, efi_info_t *efi)
{
	uint32_t addr = 0;
	uint64_t long_addr = 0ul;

	/* loader signature */
	enum efi_status efi_stat = get_loader_launch_efi_status(
		MB2_TAG_START(xd->mb_initial_state.ebx));

	if (efi_stat == EFI_64BIT) {
		mon_memcpy(&efi->efi_loader_signature, "EL64", sizeof(uint32_t));
	} else if (efi_stat == EFI_32BIT) {
		mon_memcpy(&efi->efi_loader_signature, "EL32", sizeof(uint32_t));
	}

	/* EFI system table address */
	if (get_loader_efi_addr(MB2_TAG_START(xd->mb_initial_state.ebx), &addr,
		    &long_addr)) {
		if (long_addr) {
			efi->efi_systab = (uint32_t)(long_addr & 0xffffffff);
			efi->efi_systab_hi = long_addr >> 32;
		} else {
			efi->efi_systab = addr;
			efi->efi_systab_hi = 0;
		}
	} else {
		print_string("failed to get EFI system table address");
	}

	/* EFI mmap descriptor size */
	efi->efi_memdesc_size = sizeof(struct efi_memory_desc);

	/* EFI mmap descriptor version */
	efi->efi_memdesc_version = 1;

	/* EFI mmap addr */
	uint32_t len = 0;
	/* Need to set efi_memmap
	 * even after add noefi to linux kernel boot params
	 */
	efi->efi_memmap = (uint32_t)get_efi_mmap(xd, &len);
	efi->efi_memmap_size = len;

	/* EFI mmap high */
	efi->efi_memmap_hi = 0;
}


/*
 *  setup boot parames based on the linux boot protocol.
 */
boolean_t setup_boot_params_mb1(xmon_desc_t *xd,
				boot_params_t *boot_params,
				linux_kernel_header_t *hdr)
{
	multiboot_info_t *mbi = (multiboot_info_t *)xd->mb_initial_state.ebx;

	/* copy the whole setup data from image header to boot parameter */
	mon_memcpy(&boot_params->setup_hdr, &hdr->setup_hdr, sizeof(setup_header_t));


	/* detect e820 table, and update e820_map[] in boot parameters */
	if (mbi->flags & MBI_MEMMAP) {
		int i;

		multiboot_memory_map_t *mmap =
			(multiboot_memory_map_t *)(mbi->mmap_addr);

		/* get e820 entries from mbi info */
		for (i = 0; i < mbi->mmap_length / sizeof(multiboot_memory_map_t);
		     i++) {
			boot_params->e820_map[i].addr = mmap[i].addr;
			boot_params->e820_map[i].size = mmap[i].len;

			if (mmap[i].type == E820_BAD_MEM) {                             /*5, bad memory */
				boot_params->e820_map[i].type = E820_RESERVED_MEM;      /*2, reserved*/
			} else {
				boot_params->e820_map[i].type = mmap[i].type;
			}
		}

		boot_params->e820_entries = i;
	} else {
		print_string(
			"ERROR: something was wrong, why no memory map info in multiboot info structure\n");
		return false;
	}


	/* fill up screen info
	 *  no need this for efi boot.
	 */
	{
		screen_info_t *screen = (screen_info_t *)&boot_params->screen_info;
		screen->orig_video_mode = 3; /* BIOS 80*25 text mode */
		screen->orig_video_lines = 25;
		screen->orig_video_cols = 80;
		screen->orig_video_points = 16; /* set font height to 16 pixels */
		screen->orig_video_is_vga = 1;  /* use VGA text screen setups */
		screen->orig_y = 24;            /* start display text @ screen end*/


		/* Only used when `video_mode == 0x7', otherwise ignored.  */
		screen->orig_video_ega_bx = 0;
	}

	setup_tboot_shared_addr((uint64_t *)&boot_params->tboot_shared_addr);

	return true;
}

boolean_t setup_boot_params_mb2(xmon_desc_t *xd,
				boot_params_t *boot_params,
				linux_kernel_header_t *hdr)
{
	/* copy the whole setup data from image header to boot parameter */
	mon_memcpy(&boot_params->setup_hdr, &hdr->setup_hdr, sizeof(setup_header_t));

	int num = 0;
	/* detect e820 table, and update e820_map[] boot parameters */
	int i;
	struct mb2_tag_mmap *mmap_tag = (struct mb2_tag_mmap *)get_mb2_tag_type(
		MB2_TAG_START(xd->mb_initial_state.ebx), MB2_TAG_TYPE_MMAP);
	struct mb2_mmap_entry *mmap = (struct mb2_mmap_entry *)(mmap_tag->entries);

	num = (mmap_tag->size - 4 * sizeof(uint32_t)) / mmap_tag->entry_size;

	for (i = 0;
	     i < (mmap_tag->size - 4 * sizeof(uint32_t)) / mmap_tag->entry_size;
	     i++) {
		boot_params->e820_map[i].addr = mmap[i].addr;
		boot_params->e820_map[i].size = mmap[i].len;

		if (mmap[i].type == E820_BAD_MEM) {                             /*5, bad memory */
			boot_params->e820_map[i].type = E820_RESERVED_MEM;      /*2, reserved*/
		} else {
			boot_params->e820_map[i].type = mmap[i].type;
		}
	}

	boot_params->e820_entries = i;

	/* add EFI support*/
	if (is_loader_launch_efi(xd)) {
		efi_info_t *efi = &(boot_params->efi_info);
		screen_info_t *scr = (screen_info_t *)(boot_params->screen_info);

		prepare_efi_info(xd, efi);

		/* grub2 probably threw a framebuffer tag at us ????? */
		load_fb_info(xd, (void *)scr);
	}

	/* fill up screen info
	 *  no need this for efi boot.
	 */
	if (!is_loader_launch_efi(xd)) {
		screen_info_t *screen = (screen_info_t *)&boot_params->screen_info;
		screen->orig_video_mode = 3; /* BIOS 80*25 text mode */
		screen->orig_video_lines = 25;
		screen->orig_video_cols = 80;
		screen->orig_video_points = 16; /* set font height to 16 pixels */
		screen->orig_video_is_vga = 1;  /* use VGA text screen setups */
		screen->orig_y = 24;            /* start display text @ screen end*/


		/* Only used when `video_mode == 0x7', otherwise ignored.  */
		screen->orig_video_ega_bx = 0;
	}

	setup_tboot_shared_addr((uint64_t *)&boot_params->tboot_shared_addr);

	return true;
}


/* helper function to get the length of the string */
uint32_t strlen(const char *str)
{
	const char *s = str;

	while (*s)
		++s;

	return s - str;
}

char *get_module_cmdline_mb1(xmon_desc_t *xd, grub_module_index_t midx)
{
	multiboot_module_t *mod = loader_get_module(xd, midx);

	return (char *)mod->cmdline;
}

char *get_module_cmdline_mb2(xmon_desc_t *xd, grub_module_index_t midx)
{
	multiboot_module_t *mod = loader_get_module(xd, midx);

	return (char *)&(mod->cmdline);
}

/* expand linux kernel with kernel image and initrd image */
static bool_t expand_linux_image(xmon_desc_t *xd,
				 const void *linux_image, size_t linux_size,
				 const void *initrd_image, size_t initrd_size,
				 unsigned int *boot_param_addr,
				 unsigned int *entry_point)
{
	linux_kernel_header_t *hdr;
	uint32_t protected_mode_base;
	unsigned long real_mode_size, prot_size = 0, protected_mode_file_size;
	boot_params_t *boot_params;
	uint32_t initrd_base;

	/* Check params */
	if (linux_image == NULL) {
		return false;
	}

	if (linux_size == 0) {
		return false;
	}

	if (linux_size < sizeof(linux_kernel_header_t)) {
		return false;
	}

	hdr = (linux_kernel_header_t *)(linux_image);


	if (entry_point == NULL || boot_param_addr == NULL) {
		return false;
	}


	/* according to linux boot protocol,
	 * if setup_sects is zero, set to default value 4.
	 */
	if (hdr->setup_hdr.setup_sects == 0) {
		hdr->setup_hdr.setup_sects = DEFAULT_SECTOR_NUM;
	}

	if (hdr->setup_hdr.setup_sects > MAX_SECTOR_NUM) {
		print_string("ERROR: exceed the max sector number, invalid kernel\n");
		return false;
	}

	/* compare to the magic number */
	if (hdr->setup_hdr.header != HDRS_MAGIC) {
		print_string("ERROR: Old kernel header magic not supported now\n");
		/* old kernel */
		return false;
	}

	/* can be loaded to high memory? */
	if (!(hdr->setup_hdr.loadflags & FLAG_LOAD_HIGH)) {
		print_string(
			"ERROR: cannot support the old kernel that not loaded to high memory\n");
		return false;
	}


	/* real_mode_size calculated according to boot protocol:
	 *  linuxsrc/Documentation/x86/boot.txt
	 */
	real_mode_size = (hdr->setup_hdr.setup_sects + 1) * SECTOR_SIZE;


	/* Note: according to the boot protocol,
	 *  real_mode_size + protected_mode_file_size = totol linux file size
	 *  so we can calculate protected mode code file size.
	 */
	protected_mode_file_size = linux_size - real_mode_size;


	/* allocate "boot_params+cmdline" from heap space.
	 *  and zero them (already zeroed in allocate_memory()).
	 */
	boot_params = (boot_params_t *)allocate_memory(
		sizeof(boot_params_t) + hdr->setup_hdr.cmdline_size);
	if (boot_params == NULL) {
		print_string("Allocate memory for linux boot_params failed\n");
		return false;
	}


	/* put cmd_line_ptr after boot_parameters */
	hdr->setup_hdr.cmd_line_ptr = (uint32_t)(boot_params) +
				      sizeof(boot_params_t);


	/*
	 *  check boot protocol version 2.10 (Kernel 2.6.31+)
	 */
	if ((hdr->setup_hdr.version) >= 0x020a) {
		prot_size = hdr->setup_hdr.init_size;
		prot_size = PAGE_ALIGN_4K(prot_size);
	} else {
		print_string_value(
			"Boot protocol version < 2.10, not supported right now. ver=0x%",
			hdr->setup_hdr.version);
		return false;
	}


	/* boot loader is grub2, so set type_of_loader to 0x72 */
	hdr->setup_hdr.type_of_loader = GRUB_LINUX_BOOT_LOADER_TYPE;

	/* clear loadflags and heap_end_ptr
	 *  question?: do we need to set this flag? so far so good for recent kernels.
	 */
	hdr->setup_hdr.loadflags &= ~FLAG_CAN_USE_HEAP; /* can not use heap */

	if ((initrd_image !=  0) && (initrd_size != 0)) {
		/* load initrd and set ramdisk_image and ramdisk_size
		 *  The initrd should typically be located as high in memory as possible
		 *
		 *  check if Linux command line explicitly specified a memory limit
		 *  TODO: hardcode here to 4GB. (call get_cmdline_str_value() to get
		 *  "mem=" limit value (not supported right now)
		 */
		uint64_t mem_limit = 0x100000000ULL;
		uint64_t max_ram_base, max_ram_size;

		loader_get_highest_sized_ram(xd, initrd_size, mem_limit,
			&max_ram_base, &max_ram_size);

		if (max_ram_base == 0) {
			return false;
		}
		if (max_ram_size == 0) {
			return false;
		}

		if (initrd_size > max_ram_size) {
			return false;
		}
		if (max_ram_base > ((uint64_t)(uint32_t)(~0))) {
			return false;
		}
		if (plus_overflow_u32((uint32_t)max_ram_base,
			    (uint32_t)(max_ram_size - initrd_size))) {
			return false;
		}

		/*
		 *  try to get the higher part in an AVAILABLE memory range
		 *  and clear lower 12 bit to make it page-aligned down.
		 */
		initrd_base = (max_ram_base + max_ram_size - initrd_size) & (~PAGE_4KB_MASK);

		/* exceed initrd_addr_max specified in vmlinuz header? */
		if (initrd_base + initrd_size > hdr->setup_hdr.initrd_addr_max) {
			/* make it much lower, if exceed it */
			initrd_base = hdr->setup_hdr.initrd_addr_max - initrd_size;
			initrd_base = initrd_base & (~PAGE_4KB_MASK);
		}
	}


	if (hdr->setup_hdr.relocatable_kernel) {
		/* A relocatable kernel that is loaded at an alignment
		 * incompatible value will be realigned during kernel
		 * initialization.
		 * Detail info see:
		 * https://www.kernel.org/doc/Documentation/x86/boot.txt
		 */
		protected_mode_base = (uint32_t)(linux_image + real_mode_size);
	} else {
		/* If need to support older kernel, need to move
		 * kernel to pref_address.
		 * Detailed info see:
		 * https://www.kernel.org/doc/Documentation/x86/boot.txt
		 */
		print_string(
			"ERROR: Linux protected mode not loaded (old kernel not relocatable)\n");
		return false;
	}


	if ((initrd_image != 0) && (initrd_size != 0)) {
		/* make sure no overlap between initrd and protected mode kernel code */
		if ((protected_mode_base + PAGE_ALIGN_4K(prot_size)) > initrd_base) {
			print_string(
				"ERROR: Initrd size is too large (or protected mode code size is too large)\n");
			return false;
		}

		/* relocate initrd image to higher end location. */
		mon_memcpy((void *)initrd_base, initrd_image, initrd_size);

		hdr->setup_hdr.ramdisk_image = initrd_base;
		hdr->setup_hdr.ramdisk_size = initrd_size;
	} else {
		hdr->setup_hdr.ramdisk_image = 0;
		hdr->setup_hdr.ramdisk_size = 0;
	}


	hdr->setup_hdr.code32_start = protected_mode_base;


	/* set vid_mode
	 *  hardcode as normal mode,
	 *  TODO-need to get it from cmdlline if present.
	 */
	hdr->setup_hdr.vid_mode = GRUB_LINUX_VID_MODE_NORMAL;


	/* get cmdline param */
	const char *kernel_cmdline =
		(char *)(loader_get_module_cmdline(xd, MVMLINUZ));

	/* check max cmdline_size */
	if (strlen(kernel_cmdline) > hdr->setup_hdr.cmdline_size) {
		print_string("WARN: cmdline size exceeds the max allowable value\n");

		/*TODO: truncate it, instead of returning error */
		return false;
	}

	/* copy cmdline to boot parameter */
	mon_memcpy((void *)hdr->setup_hdr.cmd_line_ptr, kernel_cmdline,
		strlen(kernel_cmdline));


	/* setup boot parameters according to linux boot protocol */
	if (!loader_setup_boot_params(xd, boot_params, hdr)) {
		print_string("ERROR: failed to configure linux boot parames\n");
		return false;
	}


	/* get protected mode entry point */
	*entry_point = boot_params->setup_hdr.code32_start;

	/*
	 *  get boot params address
	 *  (will be put into esi according to boot protocol)
	 */
	*boot_param_addr = (unsigned int)boot_params;

	return true;
}



extern void CDECL
jump_to_kernel(unsigned int bootparams_addr, unsigned int entry_point_addr);


/* jump to protected-mode code of kernel */
bool_t jump_linux_image(unsigned int bootparams, unsigned int entry_point)
{
	/* configure gdt entries according to boot protocol */
	static const uint64_t gdt_table[] __attribute__ ((aligned(16))) = {
		0,
		0,
		0x00cf9b000000ffff,     /* cs */
		0x00cf93000000ffff      /* ds */
	};
	/* both 4G flat, CS: execute/read, DS: read/write */

	static ia32_gdtr_t gdt_desc;

	gdt_desc.limit = sizeof(gdt_table) - 1;
	gdt_desc.base = (uint32_t)&gdt_table[0];


	ia32_write_gdtr(&gdt_desc);

	jump_to_kernel(bootparams, entry_point);

	return false;
}


/*
 * this function will do following tasks.
 * 1) parse mbi structure to get boot info.
 * 2) parse linux image header info, then
 * 3) prepare the boot_prames to jump linux kernel
 *
 */
void launch_linux_kernel(xmon_desc_t *xd)
{
	unsigned int kernel_entry_point;
	unsigned int boot_param_addr;
	void *initrd_image;
	size_t initrd_size;

	/* get kernel module */
	multiboot_module_t *m = loader_get_module(xd, MVMLINUZ);

	if (m == NULL) {
		print_string("ERROR: get kernel module failed\n");
		return;
	}

	void *kernel_image = (void *)m->mod_start;
	size_t kernel_size = m->mod_end - m->mod_start;


	/* get initrd module */
	m = loader_get_module(xd, MINITRD);
	if (m == NULL) {
		initrd_image = 0;
		initrd_size = 0;
	} else {
		initrd_image = (void *)m->mod_start;
		initrd_size = m->mod_end - m->mod_start;
	}


	if (!expand_linux_image(xd,
		    kernel_image, kernel_size,
		    initrd_image, initrd_size,
		    &boot_param_addr,
		    &kernel_entry_point)) {
		print_string("ERROR: Failed to expand linux image\n");
		return;
	}

	jump_linux_image(boot_param_addr, kernel_entry_point);


	return;
}
