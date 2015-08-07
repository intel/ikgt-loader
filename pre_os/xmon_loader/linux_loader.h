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

#ifndef __LINUX_LOADER_H__
#define __LINUX_LOADER_H__

#include "multiboot.h"
#include "xmon_desc.h"


#define E820_RESERVED_MEM       2
#define E820_BAD_MEM            5



#define SECTOR_SIZE                 (1 << 9)    /* 0x200 = 512B */

#define DEFAULT_SECTOR_NUM          4           /* default sector number 4 */
#define MAX_SECTOR_NUM              64          /* max sector number 64 */
#define HDRS_MAGIC                  0x53726448
#define GRUB_LINUX_BOOT_LOADER_TYPE 0x72
#define LOADER_TYPE_UNKNOWN         0xFF
#define FLAG_LOAD_HIGH              0x01
#define FLAG_CAN_USE_HEAP           0x80
#define GRUB_LINUX_VID_MODE_NORMAL  0xFFFF

typedef int bool_t;
#define true 1
#define false 0

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;

typedef unsigned int size_t;


/* setup header according to the linux boot protocol */
typedef struct {
	uint8_t setup_sects;                    /* The size of the setup in sectors */

	uint16_t root_flags;                    /* If set, the root is mounted readonly */
	uint32_t syssize;                       /* The size of the 32-bit code in 16-byte paras */
	uint16_t ram_size;                      /* DO NOT USE - for bootsect.S use only */
	uint16_t vid_mode;                      /* Video mode control */
	uint16_t root_dev;                      /* Default root device number */
	uint16_t boot_flag;                     /* 0xAA55 magic number */
	uint16_t jump;                          /* Jump instruction */

	uint32_t header;                        /* Magic signature "HdrS" */

	uint16_t version;                       /* Boot protocol version supported */
	uint32_t realmode_swtch;                /* Boot loader hook */
	uint16_t start_sys;                     /* The load-low segment (0x1000) (obsolete) */
	uint16_t kernel_version;                /* Points to kernel version string */

	uint8_t type_of_loader;                 /* Boot loader identifier */

	uint8_t loadflags;                      /* Boot protocol option flags */

	uint16_t setup_move_size;               /* Move to high memory size (used with hooks) */
	uint32_t code32_start;                  /* Boot loader hook */
	uint32_t ramdisk_image;                 /* initrd load address (set by boot loader) */
	uint32_t ramdisk_size;                  /* initrd size (set by boot loader) */
	uint32_t bootsect_kludge;               /* DO NOT USE - for bootsect.S use only */
	uint16_t heap_end_ptr;                  /* Free memory after setup end */
	uint16_t pad1;                          /* Unused */
	uint32_t cmd_line_ptr;                  /* 32-bit pointer to the kernel command line */
	uint32_t initrd_addr_max;               /* Highest legal initrd address */
	uint32_t kernel_alignment;              /* Physical addr alignment required for kernel */
	uint8_t relocatable_kernel;             /* Whether kernel is relocatable or not */
	uint8_t min_alignment;
	uint8_t pad2[2];                        /* Unused */
	uint32_t cmdline_size;                  /* Maximum size of the kernel command line */
	uint32_t hardware_subarch;              /* Hardware subarchitecture */
	uint64_t hardware_subarch_data;         /* Subarchitecture-specific data */
	uint32_t payload_offset;
	uint32_t payload_length;
	uint64_t setup_data;
	uint64_t pref_address;
	uint32_t init_size;
} __attribute__((packed)) setup_header_t;


typedef struct {
	uint8_t code1[0x0020];
	uint16_t cl_magic;                              /* Magic number 0xA33F */
	uint16_t cl_offset;                             /* The offset of command line */
	uint8_t code2[0x01F1 - 0x0020 - 2 - 2];

	setup_header_t setup_hdr;
} linux_kernel_header_t;

typedef struct {
	uint64_t addr;                                  /* start of memory segment */
	uint64_t size;                                  /* size of memory segment */
	uint32_t type;                                  /* type of memory segment */
} __attribute__ ((packed)) e820entry_t;

#define E820MAX 128

typedef struct {
	uint32_t efi_loader_signature;
	uint32_t efi_systab;
	uint32_t efi_memdesc_size;
	uint32_t efi_memdesc_version;
	uint32_t efi_memmap;
	uint32_t efi_memmap_size;
	uint32_t efi_systab_hi;
	uint32_t efi_memmap_hi;
} efi_info_t;

/* boot params structure according to the linux boot protocol */
typedef struct  {
	uint8_t screen_info[0x040 - 0x000];                     /* 0x000 */
	uint8_t apm_bios_info[0x054 - 0x040];                   /* 0x040 */
	uint8_t _pad2[4];                                       /* 0x054 */
	uint8_t tboot_shared_addr[8];                           /* 0x058 */
	uint8_t ist_info[0x070 - 0x060];                        /* 0x060 */
	uint8_t _pad3[16];                                      /* 0x070 */
	uint8_t hd0_info[16];                                   /* obsolete! */         /* 0x080 */
	uint8_t hd1_info[16];                                   /* obsolete! */         /* 0x090 */
	uint8_t sys_desc_table[0x0b0 - 0x0a0];                  /* 0x0a0 */
	uint8_t _pad4[144];                                     /* 0x0b0 */
	uint8_t edid_info[0x1c0 - 0x140];                       /* 0x140 */
	efi_info_t efi_info;                                    /* 0x1c0 */
	uint8_t alt_mem_k[0x1e4 - 0x1e0];                       /* 0x1e0 */
	uint8_t scratch[0x1e8 - 0x1e4];                         /* 0x1e4 */
	uint8_t e820_entries;                                   /* 0x1e8 */
	uint8_t eddbuf_entries;                                 /* 0x1e9 */
	uint8_t edd_mbr_sig_buf_entries;                        /* 0x1ea */
	uint8_t _pad6[6];                                       /* 0x1eb */
	setup_header_t setup_hdr;                               /* setup header */      /* 0x1f1 */
	uint8_t _pad7[0x290 - 0x1f1 - sizeof(setup_header_t)];
	uint8_t edd_mbr_sig_buffer[0x2d0 - 0x290];              /* 0x290 */
	e820entry_t e820_map[E820MAX];                          /* 0x2d0 */
	uint8_t _pad8[48];                                      /* 0xcd0 */
	uint8_t eddbuf[0xeec - 0xd00];                          /* 0xd00 */
	uint8_t _pad9[276];                                     /* 0xeec */
} __attribute__ ((packed)) boot_params_t;

typedef struct  {
	u8_t orig_x;                    /* 0x00 */
	u8_t orig_y;                    /* 0x01 */
	u16_t ext_mem_k;                /* extended memory size in kb */    /* 0x02 */
	u16_t orig_video_page;          /* 0x04 */
	u8_t orig_video_mode;           /* representing the specific mode
					* that was in effect when booting */  /* 0x06 */
	u8_t orig_video_cols;           /* 0x07 */
	u16_t unused2;                  /* 0x08 */
	u16_t orig_video_ega_bx;        /* video state and installed memory */ /* 0x0a */
	u16_t unused3;                  /* 0x0c */
	u8_t orig_video_lines;          /* 0x0e */
	u8_t orig_video_is_vga;         /* distinguish between VGA text and vesa lfb based screen setups */ /* 0x0f */
	u16_t orig_video_points;        /* font height */                   /* 0x10 */

	u16_t lfb_width;                /* 0x12 */
	u16_t lfb_height;               /* 0x14 */
	u16_t lfb_depth;                /* 0x16 */
	u32_t lfb_base;                 /* 0x18 */
	u32_t lfb_size;                 /* 0x1c */

	u16_t cl_magic;                 /* 0x20 */
	u16_t cl_offset;                /* 0x22 */

	u16_t lfb_line_len;             /* 0x24 */
	u8_t red_mask_size;             /* 0x26 */
	u8_t red_field_pos;             /* 0x27 */
	u8_t green_mask_size;           /* 0x28 */
	u8_t green_field_pos;           /* 0x29 */
	u8_t blue_mask_size;            /* 0x2a */
	u8_t blue_field_pos;            /* 0x2b */
	u8_t reserved_mask_size;        /* 0x2c */
	u8_t reserved_field_pos;        /* 0x2d */
	u16_t vesapm_segment;           /* 0x2e */
	u16_t vesapm_offset;            /* 0x30 */
	u16_t lfb_pages;                /* 0x32 */
	u16_t vesa_attrib;              /* 0x34 */
	u32_t capabilities;             /* 0x36 */
	/* padding out to 0x40 */
} __attribute__ ((packed)) screen_info_t;



void launch_linux_kernel(xmon_desc_t *xd);

multiboot_module_t *get_module_mb1(xmon_desc_t *xd, grub_module_index_t midx);
void get_highest_sized_ram_mb1(xmon_desc_t *xd,
			       uint64_t size,
			       uint64_t limit,
			       uint64_t *ram_base,
			       uint64_t *ram_size);
boolean_t setup_boot_params_mb1(xmon_desc_t *xd,
				boot_params_t *boot_params,
				linux_kernel_header_t *hdr);
char *get_module_cmdline_mb1(xmon_desc_t *xd, grub_module_index_t midx);

multiboot_module_t *get_module_mb2(xmon_desc_t *xd, grub_module_index_t midx);
void get_highest_sized_ram_mb2(xmon_desc_t *xd,
			       uint64_t size,
			       uint64_t limit,
			       uint64_t *ram_base,
			       uint64_t *ram_size);
boolean_t setup_boot_params_mb2(xmon_desc_t *xd,
				boot_params_t *boot_params,
				linux_kernel_header_t *hdr);
char *get_module_cmdline_mb2(xmon_desc_t *xd, grub_module_index_t midx);

#endif
