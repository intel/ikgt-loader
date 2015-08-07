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
#ifndef _ELF_LD_ENV_H_
#define _ELF_LD_ENV_H_

#include "elf_env.h"
#include "elf32.h"
#include "elf32_ld.h"
#include "elf_info.h"
#include "image_access_mem.h"

#ifdef DEBUG
void clear_screen(void);
void print_string(uint8_t *string);
void print_value(uint32_t value);
#define ELF_CLEAR_SCREEN()     clear_screen()
#define ELF_PRINT_STRING(arg)  print_string((uint8_t *)arg)
#define ELF_PRINT_VALUE(arg) \
	{ \
		print_value((uint32_t)arg); \
		print_string(" "); \
	}
#define ELF_PRINTLN_VALUE(arg) \
	{ \
		print_value((uint32_t)arg); \
		print_string("\n"); \
	}
#else
#define ELF_CLEAR_SCREEN()
#define ELF_PRINT_STRING(arg)
#define ELF_PRINT_VALUE(arg)
#define ELF_PRINTLN_VALUE(arg)
#endif


#define UINT16_TO_UINT64(x) (((uint64_t)(x)) & 0x000000000000FFFF)

/* Macros to facilitate locations of section headers */
#define GET_SHDR_LOADER(__ehdr, __shdrtab, __i) \
	((__shdrtab) + (UINT16_TO_UINT64(__i)) * \
	 (UINT16_TO_UINT64((__ehdr)->e_shentsize)))


#endif
