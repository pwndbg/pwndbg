#line 1 "../../binutils-gdb/bfd/elfnn-aarch64.c"
/* AArch64-specific support for 32-bit ELF.
   Copyright (C) 2009-2025 Free Software Foundation, Inc.
   Contributed by ARM Ltd.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING3. If not,
   see <http://www.gnu.org/licenses/>.  */

/* Notes on implementation:

  Thread Local Store (TLS)

  Overview:

  The implementation currently supports both traditional TLS and TLS
  descriptors, but only general dynamic (GD).

  For traditional TLS the assembler will present us with code
  fragments of the form:

  adrp x0, :tlsgd:foo
			   R_AARCH64_TLSGD_ADR_PAGE21(foo)
  add  x0, :tlsgd_lo12:foo
			   R_AARCH64_TLSGD_ADD_LO12_NC(foo)
  bl   __tls_get_addr
  nop

  For TLS descriptors the assembler will present us with code
  fragments of the form:

  adrp	x0, :tlsdesc:foo		      R_AARCH64_TLSDESC_ADR_PAGE21(foo)
  ldr	x1, [x0, #:tlsdesc_lo12:foo]	      R_AARCH64_TLSDESC_LD64_LO12(foo)
  add	x0, x0, #:tlsdesc_lo12:foo	      R_AARCH64_TLSDESC_ADD_LO12(foo)
  .tlsdesccall foo
  blr	x1				      R_AARCH64_TLSDESC_CALL(foo)

  The relocations R_AARCH64_TLSGD_{ADR_PREL21,ADD_LO12_NC} against foo
  indicate that foo is thread local and should be accessed via the
  traditional TLS mechanims.

  The relocations R_AARCH64_TLSDESC_{ADR_PAGE21,LD64_LO12_NC,ADD_LO12_NC}
  against foo indicate that 'foo' is thread local and should be accessed
  via a TLS descriptor mechanism.

  The precise instruction sequence is only relevant from the
  perspective of linker relaxation which is currently not implemented.

  The static linker must detect that 'foo' is a TLS object and
  allocate a double GOT entry. The GOT entry must be created for both
  global and local TLS symbols. Note that this is different to none
  TLS local objects which do not need a GOT entry.

  In the traditional TLS mechanism, the double GOT entry is used to
  provide the tls_index structure, containing module and offset
  entries. The static linker places the relocation R_AARCH64_TLS_DTPMOD
  on the module entry. The loader will subsequently fixup this
  relocation with the module identity.

  For global traditional TLS symbols the static linker places an
  R_AARCH64_TLS_DTPREL relocation on the offset entry. The loader
  will subsequently fixup the offset. For local TLS symbols the static
  linker fixes up offset.

  In the TLS descriptor mechanism the double GOT entry is used to
  provide the descriptor. The static linker places the relocation
  R_AARCH64_TLSDESC on the first GOT slot. The loader will
  subsequently fix this up.

  Implementation:

  The handling of TLS symbols is implemented across a number of
  different backend functions. The following is a top level view of
  what processing is performed where.

  The TLS implementation maintains state information for each TLS
  symbol. The state information for local and global symbols is kept
  in different places. Global symbols use generic BFD structures while
  local symbols use backend specific structures that are allocated and
  maintained entirely by the backend.

  The flow:

  elf32_aarch64_check_relocs()

  This function is invoked for each relocation.

  The TLS relocations R_AARCH64_TLSGD_{ADR_PREL21,ADD_LO12_NC} and
  R_AARCH64_TLSDESC_{ADR_PAGE21,LD64_LO12_NC,ADD_LO12_NC} are
  spotted. One time creation of local symbol data structures are
  created when the first local symbol is seen.

  The reference count for a symbol is incremented.  The GOT type for
  each symbol is marked as general dynamic.

  elf32_aarch64_allocate_dynrelocs ()

  For each global with positive reference count we allocate a double
  GOT slot. For a traditional TLS symbol we allocate space for two
  relocation entries on the GOT, for a TLS descriptor symbol we
  allocate space for one relocation on the slot. Record the GOT offset
  for this symbol.

  elf32_aarch64_late_size_sections ()

  Iterate all input BFDS, look for in the local symbol data structure
  constructed earlier for local TLS symbols and allocate them double
  GOT slots along with space for a single GOT relocation. Update the
  local symbol structure to record the GOT offset allocated.

  elf32_aarch64_relocate_section ()

  Calls elf32_aarch64_final_link_relocate ()

  Emit the relevant TLS relocations against the GOT for each TLS
  symbol. For local TLS symbols emit the GOT offset directly. The GOT
  relocations are emitted once the first time a TLS symbol is
  encountered. The implementation uses the LSB of the GOT offset to
  flag that the relevant GOT relocations for a symbol have been
  emitted. All of the TLS code that uses the GOT offset needs to take
  care to mask out this flag bit before using the offset.

  elf32_aarch64_final_link_relocate ()

  Fixup the R_AARCH64_TLSGD_{ADR_PREL21, ADD_LO12_NC} relocations.  */

#include "sysdep.h"
#include "bfd.h"
#include "libiberty.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "bfdlink.h"
#include "objalloc.h"
#include "elf/aarch64.h"
#include "elfxx-aarch64.h"
#include "cpu-aarch64.h"

#define ARCH_SIZE	32

#if ARCH_SIZE == 64
#define AARCH64_R(NAME)		R_AARCH64_ ## NAME
#define AARCH64_R_STR(NAME)	"R_AARCH64_" #NAME
#define HOWTO64(...)		HOWTO (__VA_ARGS__)
#define HOWTO32(...)		EMPTY_HOWTO (0)
#define LOG_FILE_ALIGN	3
#define BFD_RELOC_AARCH64_TLSDESC_LD64_LO12_NC BFD_RELOC_AARCH64_TLSDESC_LD64_LO12
#endif

#if ARCH_SIZE == 32
#define AARCH64_R(NAME)		R_AARCH64_P32_ ## NAME
#define AARCH64_R_STR(NAME)	"R_AARCH64_P32_" #NAME
#define HOWTO64(...)		EMPTY_HOWTO (0)
#define HOWTO32(...)		HOWTO (__VA_ARGS__)
#define LOG_FILE_ALIGN	2
#define BFD_RELOC_AARCH64_TLSDESC_LD32_LO12	BFD_RELOC_AARCH64_TLSDESC_LD32_LO12_NC
#define R_AARCH64_P32_TLSDESC_ADD_LO12		R_AARCH64_P32_TLSDESC_ADD_LO12_NC
#endif

#define IS_AARCH64_TLS_RELOC(R_TYPE)				\
  ((R_TYPE) == BFD_RELOC_AARCH64_TLSGD_ADD_LO12_NC		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSGD_ADR_PAGE21		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSGD_ADR_PREL21		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSGD_MOVW_G0_NC		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSGD_MOVW_G1		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSIE_LD32_GOTTPREL_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSIE_LD_GOTTPREL_PREL19	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G1	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_ADD_DTPREL_HI12	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_ADD_DTPREL_LO12	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_ADD_DTPREL_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_ADD_LO12_NC		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_ADR_PAGE21		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_ADR_PREL21		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_LDST16_DTPREL_LO12	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_LDST32_DTPREL_LO12	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_LDST64_DTPREL_LO12	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_LDST8_DTPREL_LO12	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_MOVW_DTPREL_G0	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_MOVW_DTPREL_G0_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_MOVW_DTPREL_G1	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_MOVW_DTPREL_G1_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_MOVW_DTPREL_G2	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_ADD_TPREL_HI12	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_ADD_TPREL_LO12	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_ADD_TPREL_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_LDST16_TPREL_LO12	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_LDST16_TPREL_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_LDST32_TPREL_LO12	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_LDST32_TPREL_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_LDST64_TPREL_LO12	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_LDST64_TPREL_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_LDST8_TPREL_LO12	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_LDST8_TPREL_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G0		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G0_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G1		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G1_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G2		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLS_DTPMOD			\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLS_DTPREL			\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLS_TPREL			\
   || IS_AARCH64_TLSDESC_RELOC ((R_TYPE)))

#define IS_AARCH64_TLS_RELAX_RELOC(R_TYPE)			\
  ((R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_ADD			\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_ADD_LO12		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_ADR_PAGE21		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_ADR_PREL21		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_CALL		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_LD_PREL19		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_LD32_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_LDR			\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_OFF_G0_NC		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_OFF_G1		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_LDR			\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSGD_ADR_PAGE21		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSGD_ADR_PREL21		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSGD_ADD_LO12_NC		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSGD_MOVW_G0_NC		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSGD_MOVW_G1		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSIE_LD_GOTTPREL_PREL19	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSIE_LD32_GOTTPREL_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_ADD_LO12_NC		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_ADR_PAGE21		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSLD_ADR_PREL21)

#define IS_AARCH64_TLSDESC_RELOC(R_TYPE)			\
  ((R_TYPE) == BFD_RELOC_AARCH64_TLSDESC			\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_ADD			\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_ADD_LO12		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_ADR_PAGE21		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_ADR_PREL21		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_CALL		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_LD32_LO12_NC	\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_LD64_LO12		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_LDR			\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_LD_PREL19		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_OFF_G0_NC		\
   || (R_TYPE) == BFD_RELOC_AARCH64_TLSDESC_OFF_G1)

#define ELIMINATE_COPY_RELOCS 1

/* Return size of a relocation entry.  HTAB is the bfd's
   elf_aarch64_link_hash_entry.  */
#define RELOC_SIZE(HTAB) (sizeof (Elf32_External_Rela))

/* GOT Entry size - 8 bytes in ELF64 and 4 bytes in ELF32.  */
#define GOT_ENTRY_SIZE			(ARCH_SIZE / 8)
#define PLT_ENTRY_SIZE			(32)
#define PLT_SMALL_ENTRY_SIZE		(16)
#define PLT_TLSDESC_ENTRY_SIZE		(32)
/* PLT sizes with BTI insn.  */
#define PLT_BTI_SMALL_ENTRY_SIZE	(24)
/* PLT sizes with PAC insn.  */
#define PLT_PAC_SMALL_ENTRY_SIZE	(24)
/* PLT sizes with BTI and PAC insn.  */
#define PLT_BTI_PAC_SMALL_ENTRY_SIZE	(24)

/* Encoding of the nop instruction.  */
#define INSN_NOP 0xd503201f

#define aarch64_compute_jump_table_size(htab)		\
  (((htab)->root.srelplt == NULL) ? 0			\
   : (htab)->root.srelplt->reloc_count * GOT_ENTRY_SIZE)

/* The first entry in a procedure linkage table looks like this
   if the distance between the PLTGOT and the PLT is < 4GB use
   these PLT entries. Note that the dynamic linker gets &PLTGOT[2]
   in x16 and needs to work out PLTGOT[1] by using an address of
   [x16,#-GOT_ENTRY_SIZE].  */
static const bfd_byte elf32_aarch64_small_plt0_entry[PLT_ENTRY_SIZE] =
{
  0xf0, 0x7b, 0xbf, 0xa9,	/* stp x16, x30, [sp, #-16]!  */
  0x10, 0x00, 0x00, 0x90,	/* adrp x16, (GOT+16)  */
#if ARCH_SIZE == 64
  0x11, 0x0A, 0x40, 0xf9,	/* ldr x17, [x16, #PLT_GOT+0x10]  */
  0x10, 0x42, 0x00, 0x91,	/* add x16, x16,#PLT_GOT+0x10   */
#else
  0x11, 0x0A, 0x40, 0xb9,	/* ldr w17, [x16, #PLT_GOT+0x8]  */
  0x10, 0x22, 0x00, 0x11,	/* add w16, w16,#PLT_GOT+0x8   */
#endif
  0x20, 0x02, 0x1f, 0xd6,	/* br x17  */
  0x1f, 0x20, 0x03, 0xd5,	/* nop */
  0x1f, 0x20, 0x03, 0xd5,	/* nop */
  0x1f, 0x20, 0x03, 0xd5,	/* nop */
};

static const bfd_byte elf32_aarch64_small_plt0_bti_entry[PLT_ENTRY_SIZE] =
{
  0x5f, 0x24, 0x03, 0xd5,	/* bti c.  */
  0xf0, 0x7b, 0xbf, 0xa9,	/* stp x16, x30, [sp, #-16]!  */
  0x10, 0x00, 0x00, 0x90,	/* adrp x16, (GOT+16)  */
#if ARCH_SIZE == 64
  0x11, 0x0A, 0x40, 0xf9,	/* ldr x17, [x16, #PLT_GOT+0x10]  */
  0x10, 0x42, 0x00, 0x91,	/* add x16, x16,#PLT_GOT+0x10   */
#else
  0x11, 0x0A, 0x40, 0xb9,	/* ldr w17, [x16, #PLT_GOT+0x8]  */
  0x10, 0x22, 0x00, 0x11,	/* add w16, w16,#PLT_GOT+0x8   */
#endif
  0x20, 0x02, 0x1f, 0xd6,	/* br x17  */
  0x1f, 0x20, 0x03, 0xd5,	/* nop */
  0x1f, 0x20, 0x03, 0xd5,	/* nop */
};

/* Per function entry in a procedure linkage table looks like this
   if the distance between the PLTGOT and the PLT is < 4GB use
   these PLT entries.  Use BTI versions of the PLTs when enabled.  */
static const bfd_byte elf32_aarch64_small_plt_entry[PLT_SMALL_ENTRY_SIZE] =
{
  0x10, 0x00, 0x00, 0x90,	/* adrp x16, PLTGOT + n * 8  */
#if ARCH_SIZE == 64
  0x11, 0x02, 0x40, 0xf9,	/* ldr x17, [x16, PLTGOT + n * 8] */
  0x10, 0x02, 0x00, 0x91,	/* add x16, x16, :lo12:PLTGOT + n * 8  */
#else
  0x11, 0x02, 0x40, 0xb9,	/* ldr w17, [x16, PLTGOT + n * 4] */
  0x10, 0x02, 0x00, 0x11,	/* add w16, w16, :lo12:PLTGOT + n * 4  */
#endif
  0x20, 0x02, 0x1f, 0xd6,	/* br x17.  */
};

static const bfd_byte
elf32_aarch64_small_plt_bti_entry[PLT_BTI_SMALL_ENTRY_SIZE] =
{
  0x5f, 0x24, 0x03, 0xd5,	/* bti c.  */
  0x10, 0x00, 0x00, 0x90,	/* adrp x16, PLTGOT + n * 8  */
#if ARCH_SIZE == 64
  0x11, 0x02, 0x40, 0xf9,	/* ldr x17, [x16, PLTGOT + n * 8] */
  0x10, 0x02, 0x00, 0x91,	/* add x16, x16, :lo12:PLTGOT + n * 8  */
#else
  0x11, 0x02, 0x40, 0xb9,	/* ldr w17, [x16, PLTGOT + n * 4] */
  0x10, 0x02, 0x00, 0x11,	/* add w16, w16, :lo12:PLTGOT + n * 4  */
#endif
  0x20, 0x02, 0x1f, 0xd6,	/* br x17.  */
  0x1f, 0x20, 0x03, 0xd5,	/* nop */
};

static const bfd_byte
elf32_aarch64_small_plt_pac_entry[PLT_PAC_SMALL_ENTRY_SIZE] =
{
  0x10, 0x00, 0x00, 0x90,	/* adrp x16, PLTGOT + n * 8  */
#if ARCH_SIZE == 64
  0x11, 0x02, 0x40, 0xf9,	/* ldr x17, [x16, PLTGOT + n * 8] */
  0x10, 0x02, 0x00, 0x91,	/* add x16, x16, :lo12:PLTGOT + n * 8  */
#else
  0x11, 0x02, 0x40, 0xb9,	/* ldr w17, [x16, PLTGOT + n * 4] */
  0x10, 0x02, 0x00, 0x11,	/* add w16, w16, :lo12:PLTGOT + n * 4  */
#endif
  0x9f, 0x21, 0x03, 0xd5,	/* autia1716 */
  0x20, 0x02, 0x1f, 0xd6,	/* br x17.  */
  0x1f, 0x20, 0x03, 0xd5,	/* nop */
};

static const bfd_byte
elf32_aarch64_small_plt_bti_pac_entry[PLT_BTI_PAC_SMALL_ENTRY_SIZE] =
{
  0x5f, 0x24, 0x03, 0xd5,	/* bti c.  */
  0x10, 0x00, 0x00, 0x90,	/* adrp x16, PLTGOT + n * 8  */
#if ARCH_SIZE == 64
  0x11, 0x02, 0x40, 0xf9,	/* ldr x17, [x16, PLTGOT + n * 8] */
  0x10, 0x02, 0x00, 0x91,	/* add x16, x16, :lo12:PLTGOT + n * 8  */
#else
  0x11, 0x02, 0x40, 0xb9,	/* ldr w17, [x16, PLTGOT + n * 4] */
  0x10, 0x02, 0x00, 0x11,	/* add w16, w16, :lo12:PLTGOT + n * 4  */
#endif
  0x9f, 0x21, 0x03, 0xd5,	/* autia1716 */
  0x20, 0x02, 0x1f, 0xd6,	/* br x17.  */
};

static const bfd_byte
elf32_aarch64_tlsdesc_small_plt_entry[PLT_TLSDESC_ENTRY_SIZE] =
{
  0xe2, 0x0f, 0xbf, 0xa9,	/* stp x2, x3, [sp, #-16]! */
  0x02, 0x00, 0x00, 0x90,	/* adrp x2, 0 */
  0x03, 0x00, 0x00, 0x90,	/* adrp x3, 0 */
#if ARCH_SIZE == 64
  0x42, 0x00, 0x40, 0xf9,	/* ldr x2, [x2, #0] */
  0x63, 0x00, 0x00, 0x91,	/* add x3, x3, 0 */
#else
  0x42, 0x00, 0x40, 0xb9,	/* ldr w2, [x2, #0] */
  0x63, 0x00, 0x00, 0x11,	/* add w3, w3, 0 */
#endif
  0x40, 0x00, 0x1f, 0xd6,	/* br x2 */
  0x1f, 0x20, 0x03, 0xd5,	/* nop */
  0x1f, 0x20, 0x03, 0xd5,	/* nop */
};

static const bfd_byte
elf32_aarch64_tlsdesc_small_plt_bti_entry[PLT_TLSDESC_ENTRY_SIZE] =
{
  0x5f, 0x24, 0x03, 0xd5,	/* bti c.  */
  0xe2, 0x0f, 0xbf, 0xa9,	/* stp x2, x3, [sp, #-16]! */
  0x02, 0x00, 0x00, 0x90,	/* adrp x2, 0 */
  0x03, 0x00, 0x00, 0x90,	/* adrp x3, 0 */
#if ARCH_SIZE == 64
  0x42, 0x00, 0x40, 0xf9,	/* ldr x2, [x2, #0] */
  0x63, 0x00, 0x00, 0x91,	/* add x3, x3, 0 */
#else
  0x42, 0x00, 0x40, 0xb9,	/* ldr w2, [x2, #0] */
  0x63, 0x00, 0x00, 0x11,	/* add w3, w3, 0 */
#endif
  0x40, 0x00, 0x1f, 0xd6,	/* br x2 */
  0x1f, 0x20, 0x03, 0xd5,	/* nop */
};

#define elf_info_to_howto		elf32_aarch64_info_to_howto
#define elf_info_to_howto_rel		elf32_aarch64_info_to_howto

#define AARCH64_ELF_ABI_VERSION		0

/* In case we're on a 32-bit machine, construct a 64-bit "-1" value.  */
#define ALL_ONES (~ (bfd_vma) 0)

/* Indexed by the bfd interal reloc enumerators.
   Therefore, the table needs to be synced with BFD_RELOC_AARCH64_*
   in reloc.c.   */

static reloc_howto_type elf32_aarch64_howto_table[] =
{
  EMPTY_HOWTO (0),

  /* Basic data relocations.  */

  /* Deprecated, but retained for backwards compatibility.  */
  HOWTO64 (R_AARCH64_NULL,	/* type */
	 0,			/* rightshift */
	 0,			/* size */
	 0,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_AARCH64_NULL",	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 false),		/* pcrel_offset */
  HOWTO (R_AARCH64_NONE,	/* type */
	 0,			/* rightshift */
	 0,			/* size */
	 0,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_AARCH64_NONE",	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* .xword: (S+A) */
  HOWTO64 (AARCH64_R (ABS64),	/* type */
	 0,			/* rightshift */
	 8,			/* size */
	 64,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (ABS64),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 ALL_ONES,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* .word: (S+A) */
  HOWTO (AARCH64_R (ABS32),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (ABS32),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* .half:  (S+A) */
  HOWTO (AARCH64_R (ABS16),	/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (ABS16),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* .xword: (S+A-P) */
  HOWTO64 (AARCH64_R (PREL64),	/* type */
	 0,			/* rightshift */
	 8,			/* size */
	 64,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (PREL64),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 ALL_ONES,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* .word: (S+A-P) */
  HOWTO (AARCH64_R (PREL32),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (PREL32),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffffffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* .half: (S+A-P) */
  HOWTO (AARCH64_R (PREL16),	/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (PREL16),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* Group relocations to create a 16, 32, 48 or 64 bit
     unsigned data or abs address inline.  */

  /* MOVZ:   ((S+A) >>  0) & 0xffff */
  HOWTO (AARCH64_R (MOVW_UABS_G0),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_UABS_G0),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* MOVK:   ((S+A) >>  0) & 0xffff [no overflow check] */
  HOWTO (AARCH64_R (MOVW_UABS_G0_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_UABS_G0_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* MOVZ:   ((S+A) >> 16) & 0xffff */
  HOWTO (AARCH64_R (MOVW_UABS_G1),	/* type */
	 16,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_UABS_G1),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* MOVK:   ((S+A) >> 16) & 0xffff [no overflow check] */
  HOWTO64 (AARCH64_R (MOVW_UABS_G1_NC),	/* type */
	 16,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_UABS_G1_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* MOVZ:   ((S+A) >> 32) & 0xffff */
  HOWTO64 (AARCH64_R (MOVW_UABS_G2),	/* type */
	 32,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_UABS_G2),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* MOVK:   ((S+A) >> 32) & 0xffff [no overflow check] */
  HOWTO64 (AARCH64_R (MOVW_UABS_G2_NC),	/* type */
	 32,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_UABS_G2_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* MOVZ:   ((S+A) >> 48) & 0xffff */
  HOWTO64 (AARCH64_R (MOVW_UABS_G3),	/* type */
	 48,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_UABS_G3),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Group relocations to create high part of a 16, 32, 48 or 64 bit
     signed data or abs address inline. Will change instruction
     to MOVN or MOVZ depending on sign of calculated value.  */

  /* MOV[ZN]:   ((S+A) >>  0) & 0xffff */
  HOWTO (AARCH64_R (MOVW_SABS_G0),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 17,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_SABS_G0),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* MOV[ZN]:   ((S+A) >> 16) & 0xffff */
  HOWTO64 (AARCH64_R (MOVW_SABS_G1),	/* type */
	 16,			/* rightshift */
	 4,			/* size */
	 17,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_SABS_G1),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* MOV[ZN]:   ((S+A) >> 32) & 0xffff */
  HOWTO64 (AARCH64_R (MOVW_SABS_G2),	/* type */
	 32,			/* rightshift */
	 4,			/* size */
	 17,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_SABS_G2),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Group relocations to create a 16, 32, 48 or 64 bit
     PC relative address inline.  */

  /* MOV[NZ]:   ((S+A-P) >>  0) & 0xffff */
  HOWTO (AARCH64_R (MOVW_PREL_G0),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 17,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_PREL_G0),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 true),		/* pcrel_offset */

  /* MOVK:   ((S+A-P) >>  0) & 0xffff [no overflow check] */
  HOWTO (AARCH64_R (MOVW_PREL_G0_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_PREL_G0_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 true),		/* pcrel_offset */

  /* MOV[NZ]:   ((S+A-P) >> 16) & 0xffff */
  HOWTO (AARCH64_R (MOVW_PREL_G1),	/* type */
	 16,			/* rightshift */
	 4,			/* size */
	 17,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_PREL_G1),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 true),		/* pcrel_offset */

  /* MOVK:   ((S+A-P) >> 16) & 0xffff [no overflow check] */
  HOWTO64 (AARCH64_R (MOVW_PREL_G1_NC),	/* type */
	 16,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_PREL_G1_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 true),		/* pcrel_offset */

  /* MOV[NZ]:   ((S+A-P) >> 32) & 0xffff */
  HOWTO64 (AARCH64_R (MOVW_PREL_G2),	/* type */
	 32,			/* rightshift */
	 4,			/* size */
	 17,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_PREL_G2),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 true),		/* pcrel_offset */

  /* MOVK:   ((S+A-P) >> 32) & 0xffff [no overflow check] */
  HOWTO64 (AARCH64_R (MOVW_PREL_G2_NC),	/* type */
	 32,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_PREL_G2_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 true),		/* pcrel_offset */

  /* MOV[NZ]:   ((S+A-P) >> 48) & 0xffff */
  HOWTO64 (AARCH64_R (MOVW_PREL_G3),	/* type */
	 48,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_PREL_G3),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 true),		/* pcrel_offset */

/* Relocations to generate 19, 21 and 33 bit PC-relative load/store
   addresses: PG(x) is (x & ~0xfff).  */

  /* LD-lit: ((S+A-P) >> 2) & 0x7ffff */
  HOWTO (AARCH64_R (LD_PREL_LO19),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 19,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (LD_PREL_LO19),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x7ffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* ADR:    (S+A-P) & 0x1fffff */
  HOWTO (AARCH64_R (ADR_PREL_LO21),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 21,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (ADR_PREL_LO21),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1fffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* ADRP:   ((PG(S+A)-PG(P)) >> 12) & 0x1fffff */
  HOWTO (AARCH64_R (ADR_PREL_PG_HI21),	/* type */
	 12,			/* rightshift */
	 4,			/* size */
	 21,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (ADR_PREL_PG_HI21),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1fffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* ADRP:   ((PG(S+A)-PG(P)) >> 12) & 0x1fffff [no overflow check] */
  HOWTO64 (AARCH64_R (ADR_PREL_PG_HI21_NC),	/* type */
	 12,			/* rightshift */
	 4,			/* size */
	 21,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (ADR_PREL_PG_HI21_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1fffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* ADD:    (S+A) & 0xfff [no overflow check] */
  HOWTO (AARCH64_R (ADD_ABS_LO12_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (ADD_ABS_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x3ffc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD/ST8:  (S+A) & 0xfff */
  HOWTO (AARCH64_R (LDST8_ABS_LO12_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (LDST8_ABS_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,				/* src_mask */
	 0xfff,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* Relocations for control-flow instructions.  */

  /* TBZ/NZ: ((S+A-P) >> 2) & 0x3fff */
  HOWTO (AARCH64_R (TSTBR14),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 14,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TSTBR14),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x3fff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* B.cond: ((S+A-P) >> 2) & 0x7ffff */
  HOWTO (AARCH64_R (CONDBR19),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 19,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (CONDBR19),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x7ffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* B:      ((S+A-P) >> 2) & 0x3ffffff */
  HOWTO (AARCH64_R (JUMP26),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 26,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (JUMP26),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x3ffffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* BL:     ((S+A-P) >> 2) & 0x3ffffff */
  HOWTO (AARCH64_R (CALL26),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 26,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (CALL26),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x3ffffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* LD/ST16:  (S+A) & 0xffe */
  HOWTO (AARCH64_R (LDST16_ABS_LO12_NC),	/* type */
	 1,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (LDST16_ABS_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffe,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD/ST32:  (S+A) & 0xffc */
  HOWTO (AARCH64_R (LDST32_ABS_LO12_NC),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (LDST32_ABS_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffc,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD/ST64:  (S+A) & 0xff8 */
  HOWTO (AARCH64_R (LDST64_ABS_LO12_NC),	/* type */
	 3,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (LDST64_ABS_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xff8,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD/ST128:  (S+A) & 0xff0 */
  HOWTO (AARCH64_R (LDST128_ABS_LO12_NC),	/* type */
	 4,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (LDST128_ABS_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xff0,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* Set a load-literal immediate field to bits
     0x1FFFFC of G(S)-P */
  HOWTO (AARCH64_R (GOT_LD_PREL19),	/* type */
	 2,				/* rightshift */
	 4,				/* size */
	 19,				/* bitsize */
	 true,				/* pc_relative */
	 0,				/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,		/* special_function */
	 AARCH64_R_STR (GOT_LD_PREL19),	/* name */
	 false,				/* partial_inplace */
	 0,				/* src_mask */
	 0xffffe0,			/* dst_mask */
	 true),				/* pcrel_offset */

  /* Get to the page for the GOT entry for the symbol
     (G(S) - P) using an ADRP instruction.  */
  HOWTO (AARCH64_R (ADR_GOT_PAGE),	/* type */
	 12,			/* rightshift */
	 4,			/* size */
	 21,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (ADR_GOT_PAGE),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1fffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* LD64: GOT offset G(S) & 0xff8  */
  HOWTO64 (AARCH64_R (LD64_GOT_LO12_NC),	/* type */
	 3,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (LD64_GOT_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xff8,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD32: GOT offset G(S) & 0xffc  */
  HOWTO32 (AARCH64_R (LD32_GOT_LO12_NC),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (LD32_GOT_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffc,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* Lower 16 bits of GOT offset for the symbol.  */
  HOWTO64 (AARCH64_R (MOVW_GOTOFF_G0_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_GOTOFF_G0_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Higher 16 bits of GOT offset for the symbol.  */
  HOWTO64 (AARCH64_R (MOVW_GOTOFF_G1),	/* type */
	 16,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (MOVW_GOTOFF_G1),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD64: GOT offset for the symbol.  */
  HOWTO64 (AARCH64_R (LD64_GOTOFF_LO15),	/* type */
	 3,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (LD64_GOTOFF_LO15),	/* name */
	 false,			/* partial_inplace */
	 0,				/* src_mask */
	 0x7ff8,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD32: GOT offset to the page address of GOT table.
     (G(S) - PAGE (_GLOBAL_OFFSET_TABLE_)) & 0x5ffc.  */
  HOWTO32 (AARCH64_R (LD32_GOTPAGE_LO14),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (LD32_GOTPAGE_LO14),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x5ffc,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD64: GOT offset to the page address of GOT table.
     (G(S) - PAGE (_GLOBAL_OFFSET_TABLE_)) & 0x7ff8.  */
  HOWTO64 (AARCH64_R (LD64_GOTPAGE_LO15),	/* type */
	 3,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (LD64_GOTPAGE_LO15),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x7ff8,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Get to the page for the GOT entry for the symbol
     (G(S) - P) using an ADRP instruction.  */
  HOWTO (AARCH64_R (TLSGD_ADR_PAGE21),	/* type */
	 12,			/* rightshift */
	 4,			/* size */
	 21,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSGD_ADR_PAGE21),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1fffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  HOWTO (AARCH64_R (TLSGD_ADR_PREL21),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 21,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSGD_ADR_PREL21),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1fffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* ADD: GOT offset G(S) & 0xff8 [no overflow check] */
  HOWTO (AARCH64_R (TLSGD_ADD_LO12_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSGD_ADD_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xfff,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* Lower 16 bits of GOT offset to tls_index.  */
  HOWTO64 (AARCH64_R (TLSGD_MOVW_G0_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSGD_MOVW_G0_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Higher 16 bits of GOT offset to tls_index.  */
  HOWTO64 (AARCH64_R (TLSGD_MOVW_G1),	/* type */
	 16,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSGD_MOVW_G1),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (TLSIE_ADR_GOTTPREL_PAGE21),	/* type */
	 12,			/* rightshift */
	 4,			/* size */
	 21,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSIE_ADR_GOTTPREL_PAGE21),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1fffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO64 (AARCH64_R (TLSIE_LD64_GOTTPREL_LO12_NC),	/* type */
	 3,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSIE_LD64_GOTTPREL_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xff8,			/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO32 (AARCH64_R (TLSIE_LD32_GOTTPREL_LO12_NC),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSIE_LD32_GOTTPREL_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffc,			/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (TLSIE_LD_GOTTPREL_PREL19),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 19,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSIE_LD_GOTTPREL_PREL19),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1ffffc,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO64 (AARCH64_R (TLSIE_MOVW_GOTTPREL_G0_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSIE_MOVW_GOTTPREL_G0_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO64 (AARCH64_R (TLSIE_MOVW_GOTTPREL_G1),	/* type */
	 16,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSIE_MOVW_GOTTPREL_G1),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* ADD: bit[23:12] of byte offset to module TLS base address.  */
  HOWTO (AARCH64_R (TLSLD_ADD_DTPREL_HI12),	/* type */
	 12,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_ADD_DTPREL_HI12),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xfff,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* Unsigned 12 bit byte offset to module TLS base address.  */
  HOWTO (AARCH64_R (TLSLD_ADD_DTPREL_LO12),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_ADD_DTPREL_LO12),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xfff,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* No overflow check version of BFD_RELOC_AARCH64_TLSLD_ADD_DTPREL_LO12.  */
  HOWTO (AARCH64_R (TLSLD_ADD_DTPREL_LO12_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_ADD_DTPREL_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xfff,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* ADD: GOT offset G(S) & 0xff8 [no overflow check] */
  HOWTO (AARCH64_R (TLSLD_ADD_LO12_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_ADD_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xfff,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* Get to the page for the GOT entry for the symbol
     (G(S) - P) using an ADRP instruction.  */
  HOWTO (AARCH64_R (TLSLD_ADR_PAGE21),	/* type */
	 12,			/* rightshift */
	 4,			/* size */
	 21,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_ADR_PAGE21),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1fffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  HOWTO (AARCH64_R (TLSLD_ADR_PREL21),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 21,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_ADR_PREL21),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1fffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* LD/ST16: bit[11:1] of byte offset to module TLS base address.  */
  HOWTO64 (AARCH64_R (TLSLD_LDST16_DTPREL_LO12),	/* type */
	 1,			/* rightshift */
	 4,			/* size */
	 11,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_LDST16_DTPREL_LO12),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1ffc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Same as BFD_RELOC_AARCH64_TLSLD_LDST16_DTPREL_LO12, but no overflow check.  */
  HOWTO64 (AARCH64_R (TLSLD_LDST16_DTPREL_LO12_NC),	/* type */
	 1,			/* rightshift */
	 4,			/* size */
	 11,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_LDST16_DTPREL_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1ffc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD/ST32: bit[11:2] of byte offset to module TLS base address.  */
  HOWTO64 (AARCH64_R (TLSLD_LDST32_DTPREL_LO12),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 10,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_LDST32_DTPREL_LO12),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x3ffc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Same as BFD_RELOC_AARCH64_TLSLD_LDST32_DTPREL_LO12, but no overflow check.  */
  HOWTO64 (AARCH64_R (TLSLD_LDST32_DTPREL_LO12_NC),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 10,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_LDST32_DTPREL_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD/ST64: bit[11:3] of byte offset to module TLS base address.  */
  HOWTO64 (AARCH64_R (TLSLD_LDST64_DTPREL_LO12),	/* type */
	 3,			/* rightshift */
	 4,			/* size */
	 9,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_LDST64_DTPREL_LO12),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x3ffc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Same as BFD_RELOC_AARCH64_TLSLD_LDST64_DTPREL_LO12, but no overflow check.  */
  HOWTO64 (AARCH64_R (TLSLD_LDST64_DTPREL_LO12_NC),	/* type */
	 3,			/* rightshift */
	 4,			/* size */
	 9,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_LDST64_DTPREL_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x7fc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD/ST8: bit[11:0] of byte offset to module TLS base address.  */
  HOWTO64 (AARCH64_R (TLSLD_LDST8_DTPREL_LO12),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_LDST8_DTPREL_LO12),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x3ffc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Same as BFD_RELOC_AARCH64_TLSLD_LDST8_DTPREL_LO12, but no overflow check.  */
  HOWTO64 (AARCH64_R (TLSLD_LDST8_DTPREL_LO12_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_LDST8_DTPREL_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x3ffc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* MOVZ: bit[15:0] of byte offset to module TLS base address.  */
  HOWTO (AARCH64_R (TLSLD_MOVW_DTPREL_G0),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_MOVW_DTPREL_G0),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* No overflow check version of BFD_RELOC_AARCH64_TLSLD_MOVW_DTPREL_G0.  */
  HOWTO (AARCH64_R (TLSLD_MOVW_DTPREL_G0_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_MOVW_DTPREL_G0_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* MOVZ: bit[31:16] of byte offset to module TLS base address.  */
  HOWTO (AARCH64_R (TLSLD_MOVW_DTPREL_G1),	/* type */
	 16,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_MOVW_DTPREL_G1),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* No overflow check version of BFD_RELOC_AARCH64_TLSLD_MOVW_DTPREL_G1.  */
  HOWTO64 (AARCH64_R (TLSLD_MOVW_DTPREL_G1_NC),	/* type */
	 16,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_MOVW_DTPREL_G1_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* MOVZ: bit[47:32] of byte offset to module TLS base address.  */
  HOWTO64 (AARCH64_R (TLSLD_MOVW_DTPREL_G2),	/* type */
	 32,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLD_MOVW_DTPREL_G2),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO64 (AARCH64_R (TLSLE_MOVW_TPREL_G2),	/* type */
	 32,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_MOVW_TPREL_G2),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (TLSLE_MOVW_TPREL_G1),	/* type */
	 16,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_MOVW_TPREL_G1),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO64 (AARCH64_R (TLSLE_MOVW_TPREL_G1_NC),	/* type */
	 16,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_MOVW_TPREL_G1_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (TLSLE_MOVW_TPREL_G0),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_MOVW_TPREL_G0),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (TLSLE_MOVW_TPREL_G0_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_MOVW_TPREL_G0_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (TLSLE_ADD_TPREL_HI12),	/* type */
	 12,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_ADD_TPREL_HI12),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xfff,			/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (TLSLE_ADD_TPREL_LO12),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_ADD_TPREL_LO12),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xfff,			/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (TLSLE_ADD_TPREL_LO12_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_ADD_TPREL_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xfff,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD/ST16: bit[11:1] of byte offset to module TLS base address.  */
  HOWTO (AARCH64_R (TLSLE_LDST16_TPREL_LO12),	/* type */
	 1,			/* rightshift */
	 4,			/* size */
	 11,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_LDST16_TPREL_LO12),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1ffc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Same as BFD_RELOC_AARCH64_TLSLE_LDST16_TPREL_LO12, but no overflow check.  */
  HOWTO (AARCH64_R (TLSLE_LDST16_TPREL_LO12_NC),	/* type */
	 1,			/* rightshift */
	 4,			/* size */
	 11,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_LDST16_TPREL_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1ffc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD/ST32: bit[11:2] of byte offset to module TLS base address.  */
  HOWTO (AARCH64_R (TLSLE_LDST32_TPREL_LO12),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 10,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_LDST32_TPREL_LO12),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Same as BFD_RELOC_AARCH64_TLSLE_LDST32_TPREL_LO12, but no overflow check.  */
  HOWTO (AARCH64_R (TLSLE_LDST32_TPREL_LO12_NC),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 10,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_LDST32_TPREL_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD/ST64: bit[11:3] of byte offset to module TLS base address.  */
  HOWTO (AARCH64_R (TLSLE_LDST64_TPREL_LO12),	/* type */
	 3,			/* rightshift */
	 4,			/* size */
	 9,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_LDST64_TPREL_LO12),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x7fc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Same as BFD_RELOC_AARCH64_TLSLE_LDST64_TPREL_LO12, but no overflow check.  */
  HOWTO (AARCH64_R (TLSLE_LDST64_TPREL_LO12_NC),	/* type */
	 3,			/* rightshift */
	 4,			/* size */
	 9,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_LDST64_TPREL_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x7fc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD/ST8: bit[11:0] of byte offset to module TLS base address.  */
  HOWTO (AARCH64_R (TLSLE_LDST8_TPREL_LO12),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_LDST8_TPREL_LO12),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x3ffc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  /* Same as BFD_RELOC_AARCH64_TLSLE_LDST8_TPREL_LO12, but no overflow check.  */
  HOWTO (AARCH64_R (TLSLE_LDST8_TPREL_LO12_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 10,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSLE_LDST8_TPREL_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x3ffc00,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (TLSDESC_LD_PREL19),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 19,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSDESC_LD_PREL19),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x0ffffe0,		/* dst_mask */
	 true),			/* pcrel_offset */

  HOWTO (AARCH64_R (TLSDESC_ADR_PREL21),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 21,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSDESC_ADR_PREL21),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1fffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* Get to the page for the GOT entry for the symbol
     (G(S) - P) using an ADRP instruction.  */
  HOWTO (AARCH64_R (TLSDESC_ADR_PAGE21),	/* type */
	 12,			/* rightshift */
	 4,			/* size */
	 21,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSDESC_ADR_PAGE21),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0x1fffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  /* LD64: GOT offset G(S) & 0xff8.  */
  HOWTO64 (AARCH64_R (TLSDESC_LD64_LO12),	/* type */
	 3,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSDESC_LD64_LO12),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xff8,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* LD32: GOT offset G(S) & 0xffc.  */
  HOWTO32 (AARCH64_R (TLSDESC_LD32_LO12_NC),	/* type */
	 2,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSDESC_LD32_LO12_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffc,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* ADD: GOT offset G(S) & 0xfff.  */
  HOWTO (AARCH64_R (TLSDESC_ADD_LO12),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSDESC_ADD_LO12),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xfff,			/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO64 (AARCH64_R (TLSDESC_OFF_G1),	/* type */
	 16,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSDESC_OFF_G1),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO64 (AARCH64_R (TLSDESC_OFF_G0_NC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSDESC_OFF_G0_NC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO64 (AARCH64_R (TLSDESC_LDR),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSDESC_LDR),	/* name */
	 false,			/* partial_inplace */
	 0x0,			/* src_mask */
	 0x0,			/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO64 (AARCH64_R (TLSDESC_ADD),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 12,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSDESC_ADD),	/* name */
	 false,			/* partial_inplace */
	 0x0,			/* src_mask */
	 0x0,			/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (TLSDESC_CALL),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 0,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSDESC_CALL),	/* name */
	 false,			/* partial_inplace */
	 0x0,			/* src_mask */
	 0x0,			/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (COPY),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 64,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (COPY),	/* name */
	 true,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (GLOB_DAT),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 64,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (GLOB_DAT),	/* name */
	 true,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (JUMP_SLOT),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 64,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (JUMP_SLOT),	/* name */
	 true,			/* partial_inplace */
	 0,			/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (RELATIVE),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 64,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (RELATIVE),	/* name */
	 true,			/* partial_inplace */
	 0,			/* src_mask */
	 ALL_ONES,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (TLS_DTPMOD),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 64,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
#if ARCH_SIZE == 64
	 AARCH64_R_STR (TLS_DTPMOD64),	/* name */
#else
	 AARCH64_R_STR (TLS_DTPMOD),	/* name */
#endif
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 ALL_ONES,		/* dst_mask */
	 false),		/* pc_reloffset */

  HOWTO (AARCH64_R (TLS_DTPREL),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 64,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
#if ARCH_SIZE == 64
	 AARCH64_R_STR (TLS_DTPREL64),	/* name */
#else
	 AARCH64_R_STR (TLS_DTPREL),	/* name */
#endif
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 ALL_ONES,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (TLS_TPREL),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 64,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
#if ARCH_SIZE == 64
	 AARCH64_R_STR (TLS_TPREL64),	/* name */
#else
	 AARCH64_R_STR (TLS_TPREL),	/* name */
#endif
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 ALL_ONES,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (TLSDESC),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 64,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (TLSDESC),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 ALL_ONES,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (AARCH64_R (IRELATIVE),	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 64,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 AARCH64_R_STR (IRELATIVE),	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 ALL_ONES,		/* dst_mask */
	 false),		/* pcrel_offset */

  EMPTY_HOWTO (0),
};

static reloc_howto_type elf32_aarch64_howto_none =
  HOWTO (R_AARCH64_NONE,	/* type */
	 0,			/* rightshift */
	 0,			/* size */
	 0,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_AARCH64_NONE",	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 false);		/* pcrel_offset */

/* Given HOWTO, return the bfd internal relocation enumerator.  */

static bfd_reloc_code_real_type
elf32_aarch64_bfd_reloc_from_howto (reloc_howto_type *howto)
{
  const int size
    = (int) ARRAY_SIZE (elf32_aarch64_howto_table);
  const ptrdiff_t offset
    = howto - elf32_aarch64_howto_table;

  if (offset > 0 && offset < size - 1)
    return BFD_RELOC_AARCH64_RELOC_START + offset;

  if (howto == &elf32_aarch64_howto_none)
    return BFD_RELOC_AARCH64_NONE;

  return BFD_RELOC_AARCH64_RELOC_START;
}

/* Given R_TYPE, return the bfd internal relocation enumerator.  */

static bfd_reloc_code_real_type
elf32_aarch64_bfd_reloc_from_type (bfd *abfd, unsigned int r_type)
{
  static bool initialized_p = false;
  /* Indexed by R_TYPE, values are offsets in the howto_table.  */
  static unsigned int offsets[R_AARCH64_end];

  if (!initialized_p)
    {
      unsigned int i;

      for (i = 1; i < ARRAY_SIZE (elf32_aarch64_howto_table) - 1; ++i)
	if (elf32_aarch64_howto_table[i].type != 0)
	  offsets[elf32_aarch64_howto_table[i].type] = i;

      initialized_p = true;
    }

  if (r_type == R_AARCH64_NONE || r_type == R_AARCH64_NULL)
    return BFD_RELOC_AARCH64_NONE;

  /* PR 17512: file: b371e70a.  */
  if (r_type >= R_AARCH64_end)
    {
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			  abfd, r_type);
      bfd_set_error (bfd_error_bad_value);
      return BFD_RELOC_AARCH64_NONE;
    }

  return BFD_RELOC_AARCH64_RELOC_START + offsets[r_type];
}

struct elf_aarch64_reloc_map
{
  bfd_reloc_code_real_type from;
  bfd_reloc_code_real_type to;
};

/* Map bfd generic reloc to AArch64-specific reloc.  */
static const struct elf_aarch64_reloc_map elf_aarch64_reloc_map[] =
{
  {BFD_RELOC_NONE, BFD_RELOC_AARCH64_NONE},

  /* Basic data relocations.  */
  {BFD_RELOC_CTOR, BFD_RELOC_AARCH64_32},
  {BFD_RELOC_64, BFD_RELOC_AARCH64_64},
  {BFD_RELOC_32, BFD_RELOC_AARCH64_32},
  {BFD_RELOC_16, BFD_RELOC_AARCH64_16},
  {BFD_RELOC_64_PCREL, BFD_RELOC_AARCH64_64_PCREL},
  {BFD_RELOC_32_PCREL, BFD_RELOC_AARCH64_32_PCREL},
  {BFD_RELOC_16_PCREL, BFD_RELOC_AARCH64_16_PCREL},
};

/* Given the bfd internal relocation enumerator in CODE, return the
   corresponding howto entry.  */

static reloc_howto_type *
elf32_aarch64_howto_from_bfd_reloc (bfd_reloc_code_real_type code)
{
  unsigned int i;

  /* Convert bfd generic reloc to AArch64-specific reloc.  */
  if (code < BFD_RELOC_AARCH64_RELOC_START
      || code > BFD_RELOC_AARCH64_RELOC_END)
    for (i = 0; i < ARRAY_SIZE (elf_aarch64_reloc_map); i++)
      if (elf_aarch64_reloc_map[i].from == code)
	{
	  code = elf_aarch64_reloc_map[i].to;
	  break;
	}

  if (code > BFD_RELOC_AARCH64_RELOC_START
      && code < BFD_RELOC_AARCH64_RELOC_END)
    if (elf32_aarch64_howto_table[code - BFD_RELOC_AARCH64_RELOC_START].type)
      return &elf32_aarch64_howto_table[code - BFD_RELOC_AARCH64_RELOC_START];

  if (code == BFD_RELOC_AARCH64_NONE)
    return &elf32_aarch64_howto_none;

  if (code == BFD_RELOC_AARCH64_BRANCH9)
    return &elf32_aarch64_howto_none;

  return NULL;
}

static reloc_howto_type *
elf32_aarch64_howto_from_type (bfd *abfd, unsigned int r_type)
{
  bfd_reloc_code_real_type val;
  reloc_howto_type *howto;

#if ARCH_SIZE == 32
  if (r_type > 256)
    {
      bfd_set_error (bfd_error_bad_value);
      return NULL;
    }
#endif

  if (r_type == R_AARCH64_NONE)
    return &elf32_aarch64_howto_none;

  val = elf32_aarch64_bfd_reloc_from_type (abfd, r_type);
  howto = elf32_aarch64_howto_from_bfd_reloc (val);

  if (howto != NULL)
    return howto;

  bfd_set_error (bfd_error_bad_value);
  return NULL;
}

static bool
elf32_aarch64_info_to_howto (bfd *abfd, arelent *bfd_reloc,
			     Elf_Internal_Rela *elf_reloc)
{
  unsigned int r_type;

  r_type = ELF32_R_TYPE (elf_reloc->r_info);
  bfd_reloc->howto = elf32_aarch64_howto_from_type (abfd, r_type);

  if (bfd_reloc->howto == NULL)
    {
      /* xgettext:c-format */
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"), abfd, r_type);
      return false;
    }
  return true;
}

static reloc_howto_type *
elf32_aarch64_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
				 bfd_reloc_code_real_type code)
{
  reloc_howto_type *howto = elf32_aarch64_howto_from_bfd_reloc (code);

  if (howto != NULL)
    return howto;

  bfd_set_error (bfd_error_bad_value);
  return NULL;
}

static reloc_howto_type *
elf32_aarch64_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
				 const char *r_name)
{
  unsigned int i;

  for (i = 1; i < ARRAY_SIZE (elf32_aarch64_howto_table) - 1; ++i)
    if (elf32_aarch64_howto_table[i].name != NULL
	&& strcasecmp (elf32_aarch64_howto_table[i].name, r_name) == 0)
      return &elf32_aarch64_howto_table[i];

  return NULL;
}

#define TARGET_LITTLE_SYM		aarch64_elf32_le_vec
#define TARGET_LITTLE_NAME		"elf32-littleaarch64"
#define TARGET_BIG_SYM			aarch64_elf32_be_vec
#define TARGET_BIG_NAME			"elf32-bigaarch64"

/* The linker script knows the section names for placement.
   The entry_names are used to do simple name mangling on the stubs.
   Given a function name, and its type, the stub can be found. The
   name can be changed. The only requirement is the %s be present.  */
#define STUB_ENTRY_NAME   "__%s_veneer"

/* Stub name for a BTI landing stub.  */
#define BTI_STUB_ENTRY_NAME   "__%s_bti_veneer"

/* The name of the dynamic interpreter.  This is put in the .interp
   section.  */
#define ELF_DYNAMIC_INTERPRETER     "/lib/ld.so.1"

#define AARCH64_MAX_FWD_BRANCH_OFFSET \
  (((1 << 25) - 1) << 2)
#define AARCH64_MAX_BWD_BRANCH_OFFSET \
  (-((1 << 25) << 2))

#define AARCH64_MAX_ADRP_IMM ((1 << 20) - 1)
#define AARCH64_MIN_ADRP_IMM (-(1 << 20))

static int
aarch64_valid_for_adrp_p (bfd_vma value, bfd_vma place)
{
  bfd_signed_vma offset = (bfd_signed_vma) (PG (value) - PG (place)) >> 12;
  return offset <= AARCH64_MAX_ADRP_IMM && offset >= AARCH64_MIN_ADRP_IMM;
}

static int
aarch64_valid_branch_p (bfd_vma value, bfd_vma place)
{
  bfd_signed_vma offset = (bfd_signed_vma) (value - place);
  return (offset <= AARCH64_MAX_FWD_BRANCH_OFFSET
	  && offset >= AARCH64_MAX_BWD_BRANCH_OFFSET);
}

static const uint32_t aarch64_adrp_branch_stub [] =
{
  0x90000010,			/*	adrp	ip0, X */
				/*		R_AARCH64_ADR_HI21_PCREL(X) */
  0x91000210,			/*	add	ip0, ip0, :lo12:X */
				/*		R_AARCH64_ADD_ABS_LO12_NC(X) */
  0xd61f0200,			/*	br	ip0 */
};

static const uint32_t aarch64_long_branch_stub[] =
{
#if ARCH_SIZE == 64
  0x58000090,			/*	ldr   ip0, 1f */
#else
  0x18000090,			/*	ldr   wip0, 1f */
#endif
  0x10000011,			/*	adr   ip1, #0 */
  0x8b110210,			/*	add   ip0, ip0, ip1 */
  0xd61f0200,			/*	br	ip0 */
  0x00000000,			/* 1:	.xword or .word
				   R_AARCH64_PREL32(X) + 12
				 */
  0x00000000,
};

static const uint32_t aarch64_bti_direct_branch_stub[] =
{
  0xd503245f,			/*	bti	c */
  0x14000000,			/*	b	<label> */
};

static const uint32_t aarch64_erratum_835769_stub[] =
{
  0x00000000,    /* Placeholder for multiply accumulate.  */
  0x14000000,    /* b <label> */
};

static const uint32_t aarch64_erratum_843419_stub[] =
{
  0x00000000,    /* Placeholder for LDR instruction.  */
  0x14000000,    /* b <label> */
};

/* Section name for stubs is the associated section name plus this
   string.  */
#define STUB_SUFFIX ".stub"

enum elf_aarch64_stub_type
{
  aarch64_stub_none,
  aarch64_stub_adrp_branch,
  aarch64_stub_long_branch,
  aarch64_stub_bti_direct_branch,
  aarch64_stub_erratum_835769_veneer,
  aarch64_stub_erratum_843419_veneer,
};

struct elf_aarch64_stub_hash_entry
{
  /* Base hash table entry structure.  */
  struct bfd_hash_entry root;

  /* The stub section.  */
  asection *stub_sec;

  /* Offset within stub_sec of the beginning of this stub.  */
  bfd_vma stub_offset;

  /* Given the symbol's value and its section we can determine its final
     value when building the stubs (so the stub knows where to jump).  */
  bfd_vma target_value;
  asection *target_section;

  enum elf_aarch64_stub_type stub_type;

  /* The symbol table entry, if any, that this was derived from.  */
  struct elf_aarch64_link_hash_entry *h;

  /* Destination symbol type */
  unsigned char st_type;

  /* The target is also a stub.  */
  bool double_stub;

  /* Where this stub is being called from, or, in the case of combined
     stub sections, the first input section in the group.  */
  asection *id_sec;

  /* The name for the local symbol at the start of this stub.  The
     stub name in the hash table has to be unique; this does not, so
     it can be friendlier.  */
  char *output_name;

  /* The instruction which caused this stub to be generated (only valid for
     erratum 835769 workaround stubs at present).  */
  uint32_t veneered_insn;

  /* In an erratum 843419 workaround stub, the ADRP instruction offset.  */
  bfd_vma adrp_offset;
};

/* Used to build a map of a section.  This is required for mixed-endian
   code/data.  */

typedef struct elf_elf_section_map
{
  bfd_vma vma;
  char type;
}
elf_aarch64_section_map;


typedef struct _aarch64_elf_section_data
{
  struct bfd_elf_section_data elf;
  unsigned int mapcount;
  unsigned int mapsize;
  elf_aarch64_section_map *map;
}
_aarch64_elf_section_data;

#define elf_aarch64_section_data(sec) \
  ((_aarch64_elf_section_data *) elf_section_data (sec))

/* The size of the thread control block which is defined to be two pointers.  */
#define TCB_SIZE	(ARCH_SIZE/8)*2

struct elf_aarch64_local_symbol
{
  unsigned int got_type;
  bfd_signed_vma got_refcount;
  bfd_vma got_offset;

  /* Offset of the GOTPLT entry reserved for the TLS descriptor. The
     offset is from the end of the jump table and reserved entries
     within the PLTGOT.

     The magic value (bfd_vma) -1 indicates that an offset has not be
     allocated.  */
  bfd_vma tlsdesc_got_jump_table_offset;
};

#define elf_aarch64_locals(bfd) (elf_aarch64_tdata (bfd)->locals)

#define is_aarch64_elf(bfd)				\
  (bfd_get_flavour (bfd) == bfd_target_elf_flavour	\
   && elf_tdata (bfd) != NULL				\
   && elf_object_id (bfd) == AARCH64_ELF_DATA)

static bool
elf32_aarch64_mkobject (bfd *abfd)
{
  return bfd_elf_allocate_object (abfd, sizeof (struct elf_aarch64_obj_tdata));
}

#define elf_aarch64_hash_entry(ent) \
  ((struct elf_aarch64_link_hash_entry *)(ent))

#define GOT_UNKNOWN    0
#define GOT_NORMAL     1
#define GOT_TLS_GD     2
#define GOT_TLS_IE     4
#define GOT_TLSDESC_GD 8

#define GOT_TLS_GD_ANY_P(type)	((type & GOT_TLS_GD) || (type & GOT_TLSDESC_GD))

/* AArch64 ELF linker hash entry.  */
struct elf_aarch64_link_hash_entry
{
  struct elf_link_hash_entry root;

  /* Since PLT entries have variable size, we need to record the
     index into .got.plt instead of recomputing it from the PLT
     offset.  */
  bfd_signed_vma plt_got_offset;

  /* Bit mask representing the type of GOT entry(s) if any required by
     this symbol.  */
  unsigned int got_type;

  /* TRUE if symbol is defined as a protected symbol.  */
  unsigned int def_protected : 1;

  /* A pointer to the most recently used stub hash entry against this
     symbol.  */
  struct elf_aarch64_stub_hash_entry *stub_cache;

  /* Offset of the GOTPLT entry reserved for the TLS descriptor.  The offset
     is from the end of the jump table and reserved entries within the PLTGOT.

     The magic value (bfd_vma) -1 indicates that an offset has not
     be allocated.  */
  bfd_vma tlsdesc_got_jump_table_offset;
};

static unsigned int
elf32_aarch64_symbol_got_type (struct elf_link_hash_entry *h,
			       bfd *abfd,
			       unsigned long r_symndx)
{
  if (h)
    return elf_aarch64_hash_entry (h)->got_type;

  if (! elf_aarch64_locals (abfd))
    return GOT_UNKNOWN;

  return elf_aarch64_locals (abfd)[r_symndx].got_type;
}

/* Get the AArch64 elf linker hash table from a link_info structure.  */
#define elf_aarch64_hash_table(info)					\
  ((struct elf_aarch64_link_hash_table *) ((info)->hash))

#define aarch64_stub_hash_lookup(table, string, create, copy)		\
  ((struct elf_aarch64_stub_hash_entry *)				\
   bfd_hash_lookup ((table), (string), (create), (copy)))

/* AArch64 ELF linker hash table.  */
struct elf_aarch64_link_hash_table
{
  /* The main hash table.  */
  struct elf_link_hash_table root;

  /* Nonzero to force PIC branch veneers.  */
  int pic_veneer;

  /* Fix erratum 835769.  */
  int fix_erratum_835769;

  /* Fix erratum 843419.  */
  erratum_84319_opts fix_erratum_843419;

  /* Don't apply link-time values for dynamic relocations.  */
  int no_apply_dynamic_relocs;

  /* Memtag Extension mode of operation.  */
  aarch64_memtag_opts memtag_opts;

  /* The number of bytes in the initial entry in the PLT.  */
  bfd_size_type plt_header_size;

  /* The bytes of the initial PLT entry.  */
  const bfd_byte *plt0_entry;

  /* The number of bytes in the subsequent PLT entries.  */
  bfd_size_type plt_entry_size;

  /* The bytes of the subsequent PLT entry.  */
  const bfd_byte *plt_entry;

  /* PLT entries have a common shape, but may have some pre-amble
     instructions (such as BTI).  This delta is used to factor this
     out of the common code.  */
  int plt_entry_delta;

  /* For convenience in allocate_dynrelocs.  */
  bfd *obfd;

  /* The amount of space used by the reserved portion of the sgotplt
     section, plus whatever space is used by the jump slots.  */
  bfd_vma sgotplt_jump_table_size;

  /* The stub hash table.  */
  struct bfd_hash_table stub_hash_table;

  /* Linker stub bfd.  */
  bfd *stub_bfd;

  /* Linker call-backs.  */
  asection *(*add_stub_section) (const char *, asection *);
  void (*layout_sections_again) (void);

  /* Array to keep track of which stub sections have been created, and
     information on stub grouping.  */
  struct map_stub
  {
    /* This is the section to which stubs in the group will be
       attached.  */
    asection *link_sec;
    /* The stub section.  */
    asection *stub_sec;
  } *stub_group;

  /* Assorted information used by elf32_aarch64_size_stubs.  */
  unsigned int bfd_count;
  unsigned int top_index;
  asection **input_list;

  /* True when two stubs are added where one targets the other, happens
     when BTI stubs are inserted and then the stub layout must not change
     during elf32_aarch64_build_stubs.  */
  bool has_double_stub;

  /* JUMP_SLOT relocs for variant PCS symbols may be present.  */
  int variant_pcs;

  /* The number of bytes in the PLT enty for the TLS descriptor.  */
  bfd_size_type tlsdesc_plt_entry_size;

  /* Used by local STT_GNU_IFUNC symbols.  */
  htab_t loc_hash_table;
  void * loc_hash_memory;

  /* Array of relative relocs to be emitted in DT_RELR format.  */
  bfd_size_type relr_alloc;
  bfd_size_type relr_count;
  struct relr_entry
  {
    asection *sec;
    bfd_vma off;
  } *relr;
  /* Sorted output addresses of above relative relocs.  */
  bfd_vma *relr_sorted;
  /* Layout recomputation count.  */
  bfd_size_type relr_layout_iter;
};

/* Create an entry in an AArch64 ELF linker hash table.  */

static struct bfd_hash_entry *
elf32_aarch64_link_hash_newfunc (struct bfd_hash_entry *entry,
				 struct bfd_hash_table *table,
				 const char *string)
{
  struct elf_aarch64_link_hash_entry *ret =
    (struct elf_aarch64_link_hash_entry *) entry;

  /* Allocate the structure if it has not already been allocated by a
     subclass.  */
  if (ret == NULL)
    ret = bfd_hash_allocate (table,
			     sizeof (struct elf_aarch64_link_hash_entry));
  if (ret == NULL)
    return (struct bfd_hash_entry *) ret;

  /* Call the allocation method of the superclass.  */
  ret = ((struct elf_aarch64_link_hash_entry *)
	 _bfd_elf_link_hash_newfunc ((struct bfd_hash_entry *) ret,
				     table, string));
  if (ret != NULL)
    {
      ret->got_type = GOT_UNKNOWN;
      ret->def_protected = 0;
      ret->plt_got_offset = (bfd_vma) - 1;
      ret->stub_cache = NULL;
      ret->tlsdesc_got_jump_table_offset = (bfd_vma) - 1;
    }

  return (struct bfd_hash_entry *) ret;
}

/* Initialize an entry in the stub hash table.  */

static struct bfd_hash_entry *
stub_hash_newfunc (struct bfd_hash_entry *entry,
		   struct bfd_hash_table *table, const char *string)
{
  /* Allocate the structure if it has not already been allocated by a
     subclass.  */
  if (entry == NULL)
    {
      entry = bfd_hash_allocate (table,
				 sizeof (struct
					 elf_aarch64_stub_hash_entry));
      if (entry == NULL)
	return entry;
    }

  /* Call the allocation method of the superclass.  */
  entry = bfd_hash_newfunc (entry, table, string);
  if (entry != NULL)
    {
      struct elf_aarch64_stub_hash_entry *eh;

      /* Initialize the local fields.  */
      eh = (struct elf_aarch64_stub_hash_entry *) entry;
      memset (&eh->stub_sec, 0,
	      (sizeof (struct elf_aarch64_stub_hash_entry)
	       - offsetof (struct elf_aarch64_stub_hash_entry, stub_sec)));
    }

  return entry;
}

/* Compute a hash of a local hash entry.  We use elf_link_hash_entry
  for local symbol so that we can handle local STT_GNU_IFUNC symbols
  as global symbol.  We reuse indx and dynstr_index for local symbol
  hash since they aren't used by global symbols in this backend.  */

static hashval_t
elf32_aarch64_local_htab_hash (const void *ptr)
{
  struct elf_link_hash_entry *h
    = (struct elf_link_hash_entry *) ptr;
  return ELF_LOCAL_SYMBOL_HASH (h->indx, h->dynstr_index);
}

/* Compare local hash entries.  */

static int
elf32_aarch64_local_htab_eq (const void *ptr1, const void *ptr2)
{
  struct elf_link_hash_entry *h1
     = (struct elf_link_hash_entry *) ptr1;
  struct elf_link_hash_entry *h2
    = (struct elf_link_hash_entry *) ptr2;

  return h1->indx == h2->indx && h1->dynstr_index == h2->dynstr_index;
}

/* Find and/or create a hash entry for local symbol.  */

static struct elf_link_hash_entry *
elf32_aarch64_get_local_sym_hash (struct elf_aarch64_link_hash_table *htab,
				  bfd *abfd, const Elf_Internal_Rela *rel,
				  bool create)
{
  struct elf_aarch64_link_hash_entry e, *ret;
  asection *sec = abfd->sections;
  hashval_t h = ELF_LOCAL_SYMBOL_HASH (sec->id,
				       ELF32_R_SYM (rel->r_info));
  void **slot;

  e.root.indx = sec->id;
  e.root.dynstr_index = ELF32_R_SYM (rel->r_info);
  slot = htab_find_slot_with_hash (htab->loc_hash_table, &e, h,
				   create ? INSERT : NO_INSERT);

  if (!slot)
    return NULL;

  if (*slot)
    {
      ret = (struct elf_aarch64_link_hash_entry *) *slot;
      return &ret->root;
    }

  ret = (struct elf_aarch64_link_hash_entry *)
	objalloc_alloc ((struct objalloc *) htab->loc_hash_memory,
			sizeof (struct elf_aarch64_link_hash_entry));
  if (ret)
    {
      memset (ret, 0, sizeof (*ret));
      ret->root.indx = sec->id;
      ret->root.dynstr_index = ELF32_R_SYM (rel->r_info);
      ret->root.dynindx = -1;
      *slot = ret;
    }
  return &ret->root;
}

/* Copy the extra info we tack onto an elf_link_hash_entry.  */

static void
elf32_aarch64_copy_indirect_symbol (struct bfd_link_info *info,
				    struct elf_link_hash_entry *dir,
				    struct elf_link_hash_entry *ind)
{
  struct elf_aarch64_link_hash_entry *edir, *eind;

  edir = (struct elf_aarch64_link_hash_entry *) dir;
  eind = (struct elf_aarch64_link_hash_entry *) ind;

  if (ind->root.type == bfd_link_hash_indirect)
    {
      /* Copy over PLT info.  */
      if (dir->got.refcount <= 0)
	{
	  edir->got_type = eind->got_type;
	  eind->got_type = GOT_UNKNOWN;
	}
    }

  _bfd_elf_link_hash_copy_indirect (info, dir, ind);
}

/* Merge non-visibility st_other attributes.  */

static void
elf32_aarch64_merge_symbol_attribute (struct elf_link_hash_entry *h,
				      unsigned int st_other,
				      bool definition,
				      bool dynamic ATTRIBUTE_UNUSED)
{
  if (definition)
    {
      struct elf_aarch64_link_hash_entry *eh
	  = (struct elf_aarch64_link_hash_entry *)h;
      eh->def_protected = ELF_ST_VISIBILITY (st_other) == STV_PROTECTED;
    }

  unsigned int isym_sto = st_other & ~ELF_ST_VISIBILITY (-1);
  unsigned int h_sto = h->other & ~ELF_ST_VISIBILITY (-1);

  if (isym_sto == h_sto)
    return;

  if (isym_sto & ~STO_AARCH64_VARIANT_PCS)
    /* Not fatal, this callback cannot fail.  */
    _bfd_error_handler (_("unknown attribute for symbol `%s': 0x%02x"),
			h->root.root.string, isym_sto);

  /* Note: Ideally we would warn about any attribute mismatch, but
     this api does not allow that without substantial changes.  */
  if (isym_sto & STO_AARCH64_VARIANT_PCS)
    h->other |= STO_AARCH64_VARIANT_PCS;
}

/* Destroy an AArch64 elf linker hash table.  */

static void
elf32_aarch64_link_hash_table_free (bfd *obfd)
{
  struct elf_aarch64_link_hash_table *ret
    = (struct elf_aarch64_link_hash_table *) obfd->link.hash;

  if (ret->loc_hash_table)
    htab_delete (ret->loc_hash_table);
  if (ret->loc_hash_memory)
    objalloc_free ((struct objalloc *) ret->loc_hash_memory);

  bfd_hash_table_free (&ret->stub_hash_table);
  _bfd_elf_link_hash_table_free (obfd);
}

/* Create an AArch64 elf linker hash table.  */

static struct bfd_link_hash_table *
elf32_aarch64_link_hash_table_create (bfd *abfd)
{
  struct elf_aarch64_link_hash_table *ret;
  size_t amt = sizeof (struct elf_aarch64_link_hash_table);

  ret = bfd_zmalloc (amt);
  if (ret == NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init
      (&ret->root, abfd, elf32_aarch64_link_hash_newfunc,
       sizeof (struct elf_aarch64_link_hash_entry)))
    {
      free (ret);
      return NULL;
    }

  ret->plt_header_size = PLT_ENTRY_SIZE;
  ret->plt0_entry = elf32_aarch64_small_plt0_entry;
  ret->plt_entry_size = PLT_SMALL_ENTRY_SIZE;
  ret->plt_entry_delta = 0;
  ret->plt_entry = elf32_aarch64_small_plt_entry;
  ret->tlsdesc_plt_entry_size = PLT_TLSDESC_ENTRY_SIZE;
  ret->obfd = abfd;
  ret->root.tlsdesc_got = (bfd_vma) - 1;

  if (!bfd_hash_table_init (&ret->stub_hash_table, stub_hash_newfunc,
			    sizeof (struct elf_aarch64_stub_hash_entry)))
    {
      _bfd_elf_link_hash_table_free (abfd);
      return NULL;
    }

  ret->loc_hash_table = htab_try_create (1024,
					 elf32_aarch64_local_htab_hash,
					 elf32_aarch64_local_htab_eq,
					 NULL);
  ret->loc_hash_memory = objalloc_create ();
  if (!ret->loc_hash_table || !ret->loc_hash_memory)
    {
      elf32_aarch64_link_hash_table_free (abfd);
      return NULL;
    }
  ret->root.root.hash_table_free = elf32_aarch64_link_hash_table_free;

  return &ret->root.root;
}

/* Perform relocation R_TYPE.  Returns TRUE upon success, FALSE otherwise.  */

static bool
aarch64_relocate (unsigned int r_type, bfd *input_bfd, asection *input_section,
		  bfd_vma offset, bfd_vma value)
{
  reloc_howto_type *howto;
  bfd_vma place;

  howto = elf32_aarch64_howto_from_type (input_bfd, r_type);
  place = (input_section->output_section->vma + input_section->output_offset
	   + offset);

  r_type = elf32_aarch64_bfd_reloc_from_type (input_bfd, r_type);
  value = _bfd_aarch64_elf_resolve_relocation (input_bfd, r_type, place,
					       value, 0, false);
  return _bfd_aarch64_elf_put_addend (input_bfd,
				      input_section->contents + offset, r_type,
				      howto, value) == bfd_reloc_ok;
}

/* Determine the type of stub needed, if any, for a call.  */

static enum elf_aarch64_stub_type
aarch64_type_of_stub (asection *input_sec,
		      const Elf_Internal_Rela *rel,
		      asection *sym_sec,
		      unsigned char st_type,
		      bfd_vma destination)
{
  bfd_vma location;
  bfd_signed_vma branch_offset;
  unsigned int r_type;
  enum elf_aarch64_stub_type stub_type = aarch64_stub_none;

  if (st_type != STT_FUNC
      && (sym_sec == input_sec))
    return stub_type;

  /* Determine where the call point is.  */
  location = (input_sec->output_offset
	      + input_sec->output_section->vma + rel->r_offset);

  branch_offset = (bfd_signed_vma) (destination - location);

  r_type = ELF32_R_TYPE (rel->r_info);

  /* We don't want to redirect any old unconditional jump in this way,
     only one which is being used for a sibcall, where it is
     acceptable for the IP0 and IP1 registers to be clobbered.  */
  if ((r_type == AARCH64_R (CALL26) || r_type == AARCH64_R (JUMP26))
      && (branch_offset > AARCH64_MAX_FWD_BRANCH_OFFSET
	  || branch_offset < AARCH64_MAX_BWD_BRANCH_OFFSET))
    {
      stub_type = aarch64_stub_long_branch;
    }

  return stub_type;
}

/* Build a name for an entry in the stub hash table.  */

static char *
elf32_aarch64_stub_name (const asection *input_section,
			 const asection *sym_sec,
			 const struct elf_aarch64_link_hash_entry *hash,
			 const Elf_Internal_Rela *rel)
{
  char *stub_name;
  bfd_size_type len;

  if (hash)
    {
      len = 8 + 1 + strlen (hash->root.root.root.string) + 1 + 16 + 1;
      stub_name = bfd_malloc (len);
      if (stub_name != NULL)
	snprintf (stub_name, len, "%08x_%s+%" PRIx64,
		  (unsigned int) input_section->id,
		  hash->root.root.root.string,
		  (uint64_t) rel->r_addend);
    }
  else
    {
      len = 8 + 1 + 8 + 1 + 8 + 1 + 16 + 1;
      stub_name = bfd_malloc (len);
      if (stub_name != NULL)
	snprintf (stub_name, len, "%08x_%x:%x+%" PRIx64,
		  (unsigned int) input_section->id,
		  (unsigned int) sym_sec->id,
		  (unsigned int) ELF32_R_SYM (rel->r_info),
		  (uint64_t) rel->r_addend);
    }

  return stub_name;
}

/* Return TRUE if symbol H should be hashed in the `.gnu.hash' section.  For
   executable PLT slots where the executable never takes the address of those
   functions, the function symbols are not added to the hash table.  */

static bool
elf_aarch64_hash_symbol (struct elf_link_hash_entry *h)
{
  if (h->plt.offset != (bfd_vma) -1
      && !h->def_regular
      && !h->pointer_equality_needed)
    return false;

  return _bfd_elf_hash_symbol (h);
}


/* Look up an entry in the stub hash.  Stub entries are cached because
   creating the stub name takes a bit of time.  */

static struct elf_aarch64_stub_hash_entry *
elf32_aarch64_get_stub_entry (const asection *input_section,
			      const asection *sym_sec,
			      struct elf_link_hash_entry *hash,
			      const Elf_Internal_Rela *rel,
			      struct elf_aarch64_link_hash_table *htab)
{
  struct elf_aarch64_stub_hash_entry *stub_entry;
  struct elf_aarch64_link_hash_entry *h =
    (struct elf_aarch64_link_hash_entry *) hash;
  const asection *id_sec;

  if ((input_section->flags & SEC_CODE) == 0)
    return NULL;

  /* If this input section is part of a group of sections sharing one
     stub section, then use the id of the first section in the group.
     Stub names need to include a section id, as there may well be
     more than one stub used to reach say, printf, and we need to
     distinguish between them.  */
  id_sec = htab->stub_group[input_section->id].link_sec;

  if (h != NULL && h->stub_cache != NULL
      && h->stub_cache->h == h && h->stub_cache->id_sec == id_sec)
    {
      stub_entry = h->stub_cache;
    }
  else
    {
      char *stub_name;

      stub_name = elf32_aarch64_stub_name (id_sec, sym_sec, h, rel);
      if (stub_name == NULL)
	return NULL;

      stub_entry = aarch64_stub_hash_lookup (&htab->stub_hash_table,
					     stub_name, false, false);
      if (h != NULL)
	h->stub_cache = stub_entry;

      free (stub_name);
    }

  return stub_entry;
}


/* Create a stub section.  */

static asection *
_bfd_aarch64_create_stub_section (asection *section,
				  struct elf_aarch64_link_hash_table *htab)
{
  size_t namelen;
  bfd_size_type len;
  char *s_name;

  namelen = strlen (section->name);
  len = namelen + sizeof (STUB_SUFFIX);
  s_name = bfd_alloc (htab->stub_bfd, len);
  if (s_name == NULL)
    return NULL;

  memcpy (s_name, section->name, namelen);
  memcpy (s_name + namelen, STUB_SUFFIX, sizeof (STUB_SUFFIX));
  return (*htab->add_stub_section) (s_name, section);
}


/* Find or create a stub section for a link section.

   Fix or create the stub section used to collect stubs attached to
   the specified link section.  */

static asection *
_bfd_aarch64_get_stub_for_link_section (asection *link_section,
					struct elf_aarch64_link_hash_table *htab)
{
  if (htab->stub_group[link_section->id].stub_sec == NULL)
    htab->stub_group[link_section->id].stub_sec
      = _bfd_aarch64_create_stub_section (link_section, htab);
  return htab->stub_group[link_section->id].stub_sec;
}


/* Find or create a stub section in the stub group for an input
   section.  */

static asection *
_bfd_aarch64_create_or_find_stub_sec (asection *section,
				      struct elf_aarch64_link_hash_table *htab)
{
  asection *link_sec = htab->stub_group[section->id].link_sec;
  return _bfd_aarch64_get_stub_for_link_section (link_sec, htab);
}


/* Add a new stub entry in the stub group associated with an input
   section to the stub hash.  Not all fields of the new stub entry are
   initialised.  */

static struct elf_aarch64_stub_hash_entry *
_bfd_aarch64_add_stub_entry_in_group (const char *stub_name,
				      asection *section,
				      struct elf_aarch64_link_hash_table *htab)
{
  asection *link_sec;
  asection *stub_sec;
  struct elf_aarch64_stub_hash_entry *stub_entry;

  link_sec = htab->stub_group[section->id].link_sec;
  stub_sec = _bfd_aarch64_create_or_find_stub_sec (section, htab);

  /* Enter this entry into the linker stub hash table.  */
  stub_entry = aarch64_stub_hash_lookup (&htab->stub_hash_table, stub_name,
					 true, false);
  if (stub_entry == NULL)
    {
      /* xgettext:c-format */
      _bfd_error_handler (_("%pB: cannot create stub entry %s"),
			  section->owner, stub_name);
      return NULL;
    }

  stub_entry->stub_sec = stub_sec;
  stub_entry->stub_offset = 0;
  stub_entry->id_sec = link_sec;

  return stub_entry;
}

/* Add a new stub entry in the final stub section to the stub hash.
   Not all fields of the new stub entry are initialised.  */

static struct elf_aarch64_stub_hash_entry *
_bfd_aarch64_add_stub_entry_after (const char *stub_name,
				   asection *link_section,
				   struct elf_aarch64_link_hash_table *htab)
{
  asection *stub_sec;
  struct elf_aarch64_stub_hash_entry *stub_entry;

  stub_sec = NULL;
  /* Only create the actual stub if we will end up needing it.  */
  if (htab->fix_erratum_843419 & ERRAT_ADRP)
    stub_sec = _bfd_aarch64_get_stub_for_link_section (link_section, htab);
  stub_entry = aarch64_stub_hash_lookup (&htab->stub_hash_table, stub_name,
					 true, false);
  if (stub_entry == NULL)
    {
      _bfd_error_handler (_("cannot create stub entry %s"), stub_name);
      return NULL;
    }

  stub_entry->stub_sec = stub_sec;
  stub_entry->stub_offset = 0;
  stub_entry->id_sec = link_section;

  return stub_entry;
}


static bool
aarch64_build_one_stub (struct bfd_hash_entry *gen_entry,
			void *in_arg)
{
  struct elf_aarch64_stub_hash_entry *stub_entry;
  asection *stub_sec;
  bfd *stub_bfd;
  bfd_byte *loc;
  bfd_vma sym_value;
  bfd_vma veneered_insn_loc;
  bfd_vma veneer_entry_loc;
  bfd_signed_vma branch_offset = 0;
  unsigned int template_size;
  unsigned int pad_size = 0;
  const uint32_t *template;
  unsigned int i;
  struct bfd_link_info *info;
  struct elf_aarch64_link_hash_table *htab;

  /* Massage our args to the form they really have.  */
  stub_entry = (struct elf_aarch64_stub_hash_entry *) gen_entry;

  info = (struct bfd_link_info *) in_arg;
  htab = elf_aarch64_hash_table (info);

  /* Fail if the target section could not be assigned to an output
     section.  The user should fix his linker script.  */
  if (stub_entry->target_section->output_section == NULL
      && info->non_contiguous_regions)
    info->callbacks->fatal (_("%P: Could not assign `%pA' to an output section. "
			      "Retry without "
			      "--enable-non-contiguous-regions.\n"),
			    stub_entry->target_section);

  stub_sec = stub_entry->stub_sec;

  /* The layout must not change when a stub may be the target of another.  */
  if (htab->has_double_stub)
    BFD_ASSERT (stub_entry->stub_offset == stub_sec->size);

  /* Make a note of the offset within the stubs for this entry.  */
  stub_entry->stub_offset = stub_sec->size;
  loc = stub_sec->contents + stub_entry->stub_offset;

  stub_bfd = stub_sec->owner;

  /* This is the address of the stub destination.  */
  sym_value = (stub_entry->target_value
	       + stub_entry->target_section->output_offset
	       + stub_entry->target_section->output_section->vma);

  if (stub_entry->stub_type == aarch64_stub_long_branch)
    {
      bfd_vma place = (stub_entry->stub_offset + stub_sec->output_section->vma
		       + stub_sec->output_offset);

      /* See if we can relax the stub.  */
      if (aarch64_valid_for_adrp_p (sym_value, place))
	{
	  stub_entry->stub_type = aarch64_stub_adrp_branch;

	  /* Avoid the relaxation changing the layout.  */
	  if (htab->has_double_stub)
	    pad_size = sizeof (aarch64_long_branch_stub)
		       - sizeof (aarch64_adrp_branch_stub);
	}
    }

  switch (stub_entry->stub_type)
    {
    case aarch64_stub_adrp_branch:
      template = aarch64_adrp_branch_stub;
      template_size = sizeof (aarch64_adrp_branch_stub);
      break;
    case aarch64_stub_long_branch:
      template = aarch64_long_branch_stub;
      template_size = sizeof (aarch64_long_branch_stub);
      break;
    case aarch64_stub_bti_direct_branch:
      template = aarch64_bti_direct_branch_stub;
      template_size = sizeof (aarch64_bti_direct_branch_stub);
      break;
    case aarch64_stub_erratum_835769_veneer:
      template = aarch64_erratum_835769_stub;
      template_size = sizeof (aarch64_erratum_835769_stub);
      break;
    case aarch64_stub_erratum_843419_veneer:
      template = aarch64_erratum_843419_stub;
      template_size = sizeof (aarch64_erratum_843419_stub);
      break;
    default:
      abort ();
    }

  for (i = 0; i < (template_size / sizeof template[0]); i++)
    {
      bfd_putl32 (template[i], loc);
      loc += 4;
    }

  template_size += pad_size;
  template_size = (template_size + 7) & ~7;
  stub_sec->size += template_size;

  switch (stub_entry->stub_type)
    {
    case aarch64_stub_adrp_branch:
      if (!aarch64_relocate (AARCH64_R (ADR_PREL_PG_HI21), stub_bfd, stub_sec,
			     stub_entry->stub_offset, sym_value))
	/* The stub would not have been relaxed if the offset was out
	   of range.  */
	BFD_FAIL ();

      if (!aarch64_relocate (AARCH64_R (ADD_ABS_LO12_NC), stub_bfd, stub_sec,
			     stub_entry->stub_offset + 4, sym_value))
	BFD_FAIL ();
      break;

    case aarch64_stub_long_branch:
      /* We want the value relative to the address 12 bytes back from the
	 value itself.  */
      if (!aarch64_relocate (AARCH64_R (PREL32), stub_bfd, stub_sec,
			     stub_entry->stub_offset + 16, sym_value + 12))
	BFD_FAIL ();
      break;

    case aarch64_stub_bti_direct_branch:
      if (!aarch64_relocate (AARCH64_R (JUMP26), stub_bfd, stub_sec,
			     stub_entry->stub_offset + 4, sym_value))
	BFD_FAIL ();
      break;

    case aarch64_stub_erratum_835769_veneer:
      veneered_insn_loc = stub_entry->target_section->output_section->vma
			  + stub_entry->target_section->output_offset
			  + stub_entry->target_value;
      veneer_entry_loc = stub_entry->stub_sec->output_section->vma
			  + stub_entry->stub_sec->output_offset
			  + stub_entry->stub_offset;
      branch_offset = veneered_insn_loc - veneer_entry_loc;
      branch_offset >>= 2;
      branch_offset &= 0x3ffffff;
      bfd_putl32 (stub_entry->veneered_insn,
		  stub_sec->contents + stub_entry->stub_offset);
      bfd_putl32 (template[1] | branch_offset,
		  stub_sec->contents + stub_entry->stub_offset + 4);
      break;

    case aarch64_stub_erratum_843419_veneer:
      if (!aarch64_relocate (AARCH64_R (JUMP26), stub_bfd, stub_sec,
			     stub_entry->stub_offset + 4, sym_value + 4))
	BFD_FAIL ();
      break;

    default:
      abort ();
    }

  return true;
}

/* As above, but don't actually build the stub.  Just bump offset so
   we know stub section sizes and record the offset for each stub so
   a stub can target another stub (needed for BTI direct branch stub).  */

static bool
aarch64_size_one_stub (struct bfd_hash_entry *gen_entry, void *in_arg)
{
  struct elf_aarch64_stub_hash_entry *stub_entry;
  struct elf_aarch64_link_hash_table *htab;
  int size;

  /* Massage our args to the form they really have.  */
  stub_entry = (struct elf_aarch64_stub_hash_entry *) gen_entry;
  htab = (struct elf_aarch64_link_hash_table *) in_arg;

  switch (stub_entry->stub_type)
    {
    case aarch64_stub_adrp_branch:
      size = sizeof (aarch64_adrp_branch_stub);
      break;
    case aarch64_stub_long_branch:
      size = sizeof (aarch64_long_branch_stub);
      break;
    case aarch64_stub_bti_direct_branch:
      size = sizeof (aarch64_bti_direct_branch_stub);
      break;
    case aarch64_stub_erratum_835769_veneer:
      size = sizeof (aarch64_erratum_835769_stub);
      break;
    case aarch64_stub_erratum_843419_veneer:
      {
	if (htab->fix_erratum_843419 == ERRAT_ADR)
	  return true;
	size = sizeof (aarch64_erratum_843419_stub);
      }
      break;
    default:
      abort ();
    }

  size = (size + 7) & ~7;
  stub_entry->stub_offset = stub_entry->stub_sec->size;
  stub_entry->stub_sec->size += size;
  return true;
}

/* Output is BTI compatible.  */

static bool
elf_aarch64_bti_p (bfd *output_bfd)
{
  return elf_aarch64_tdata (output_bfd)->gnu_property_aarch64_feature_1_and
       & GNU_PROPERTY_AARCH64_FEATURE_1_BTI;
}

/* External entry points for sizing and building linker stubs.  */

/* Set up various things so that we can make a list of input sections
   for each output section included in the link.  Returns -1 on error,
   0 when no stubs will be needed, and 1 on success.  */

int
elf32_aarch64_setup_section_lists (bfd *output_bfd,
				   struct bfd_link_info *info)
{
  bfd *input_bfd;
  unsigned int bfd_count;
  unsigned int top_id, top_index;
  asection *section;
  asection **input_list, **list;
  size_t amt;
  struct elf_aarch64_link_hash_table *htab =
    elf_aarch64_hash_table (info);

  if (!is_elf_hash_table (&htab->root.root))
    return 0;

  /* Count the number of input BFDs and find the top input section id.  */
  for (input_bfd = info->input_bfds, bfd_count = 0, top_id = 0;
       input_bfd != NULL; input_bfd = input_bfd->link.next)
    {
      bfd_count += 1;
      for (section = input_bfd->sections;
	   section != NULL; section = section->next)
	{
	  if (top_id < section->id)
	    top_id = section->id;
	}
    }
  htab->bfd_count = bfd_count;

  amt = sizeof (struct map_stub) * (top_id + 1);
  htab->stub_group = bfd_zmalloc (amt);
  if (htab->stub_group == NULL)
    return -1;

  /* We can't use output_bfd->section_count here to find the top output
     section index as some sections may have been removed, and
     _bfd_strip_section_from_output doesn't renumber the indices.  */
  for (section = output_bfd->sections, top_index = 0;
       section != NULL; section = section->next)
    {
      if (top_index < section->index)
	top_index = section->index;
    }

  htab->top_index = top_index;
  amt = sizeof (asection *) * (top_index + 1);
  input_list = bfd_malloc (amt);
  htab->input_list = input_list;
  if (input_list == NULL)
    return -1;

  /* For sections we aren't interested in, mark their entries with a
     value we can check later.  */
  list = input_list + top_index;
  do
    *list = bfd_abs_section_ptr;
  while (list-- != input_list);

  for (section = output_bfd->sections;
       section != NULL; section = section->next)
    {
      if ((section->flags & SEC_CODE) != 0)
	input_list[section->index] = NULL;
    }

  return 1;
}

/* Used by elf32_aarch64_next_input_section and group_sections.  */
#define PREV_SEC(sec) (htab->stub_group[(sec)->id].link_sec)

/* The linker repeatedly calls this function for each input section,
   in the order that input sections are linked into output sections.
   Build lists of input sections to determine groupings between which
   we may insert linker stubs.  */

void
elf32_aarch64_next_input_section (struct bfd_link_info *info, asection *isec)
{
  struct elf_aarch64_link_hash_table *htab =
    elf_aarch64_hash_table (info);

  if (isec->output_section->index <= htab->top_index)
    {
      asection **list = htab->input_list + isec->output_section->index;

      if (*list != bfd_abs_section_ptr && (isec->flags & SEC_CODE) != 0)
	{
	  /* Steal the link_sec pointer for our list.  */
	  /* This happens to make the list in reverse order,
	     which is what we want.  */
	  PREV_SEC (isec) = *list;
	  *list = isec;
	}
    }
}

/* See whether we can group stub sections together.  Grouping stub
   sections may result in fewer stubs.  More importantly, we need to
   put all .init* and .fini* stubs at the beginning of the .init or
   .fini output sections respectively, because glibc splits the
   _init and _fini functions into multiple parts.  Putting a stub in
   the middle of a function is not a good idea.  */

static void
group_sections (struct elf_aarch64_link_hash_table *htab,
		bfd_size_type stub_group_size,
		bool stubs_always_after_branch)
{
  asection **list = htab->input_list;

  do
    {
      asection *tail = *list;
      asection *head;

      if (tail == bfd_abs_section_ptr)
	continue;

      /* Reverse the list: we must avoid placing stubs at the
	 beginning of the section because the beginning of the text
	 section may be required for an interrupt vector in bare metal
	 code.  */
#define NEXT_SEC PREV_SEC
      head = NULL;
      while (tail != NULL)
	{
	  /* Pop from tail.  */
	  asection *item = tail;
	  tail = PREV_SEC (item);

	  /* Push on head.  */
	  NEXT_SEC (item) = head;
	  head = item;
	}

      while (head != NULL)
	{
	  asection *curr;
	  asection *next;
	  bfd_vma stub_group_start = head->output_offset;
	  bfd_vma end_of_next;

	  curr = head;
	  while (NEXT_SEC (curr) != NULL)
	    {
	      next = NEXT_SEC (curr);
	      end_of_next = next->output_offset + next->size;
	      if (end_of_next - stub_group_start >= stub_group_size)
		/* End of NEXT is too far from start, so stop.  */
		break;
	      /* Add NEXT to the group.  */
	      curr = next;
	    }

	  /* OK, the size from the start to the start of CURR is less
	     than stub_group_size and thus can be handled by one stub
	     section.  (Or the head section is itself larger than
	     stub_group_size, in which case we may be toast.)
	     We should really be keeping track of the total size of
	     stubs added here, as stubs contribute to the final output
	     section size.  */
	  do
	    {
	      next = NEXT_SEC (head);
	      /* Set up this stub group.  */
	      htab->stub_group[head->id].link_sec = curr;
	    }
	  while (head != curr && (head = next) != NULL);

	  /* But wait, there's more!  Input sections up to stub_group_size
	     bytes after the stub section can be handled by it too.  */
	  if (!stubs_always_after_branch)
	    {
	      stub_group_start = curr->output_offset + curr->size;

	      while (next != NULL)
		{
		  end_of_next = next->output_offset + next->size;
		  if (end_of_next - stub_group_start >= stub_group_size)
		    /* End of NEXT is too far from stubs, so stop.  */
		    break;
		  /* Add NEXT to the stub group.  */
		  head = next;
		  next = NEXT_SEC (head);
		  htab->stub_group[head->id].link_sec = curr;
		}
	    }
	  head = next;
	}
    }
  while (list++ != htab->input_list + htab->top_index);

  free (htab->input_list);
}

#undef PREV_SEC
#undef PREV_SEC

#define AARCH64_HINT(insn) (((insn) & 0xfffff01f) == 0xd503201f)
#define AARCH64_PACIASP 0xd503233f
#define AARCH64_PACIBSP 0xd503237f
#define AARCH64_BTI_C   0xd503245f
#define AARCH64_BTI_J   0xd503249f
#define AARCH64_BTI_JC  0xd50324df

/* True if the inserted stub does not break BTI compatibility.  */

static bool
aarch64_bti_stub_p (struct bfd_link_info *info,
		    struct elf_aarch64_stub_hash_entry *stub_entry)
{
  /* Stubs without indirect branch are BTI compatible.  */
  if (stub_entry->stub_type != aarch64_stub_adrp_branch
      && stub_entry->stub_type != aarch64_stub_long_branch)
    return true;

  /* Return true if the target instruction is compatible with BR x16.  */

  struct elf_aarch64_link_hash_table *globals = elf_aarch64_hash_table (info);
  asection *section = stub_entry->target_section;
  bfd_byte loc[4];
  file_ptr off = stub_entry->target_value;
  bfd_size_type count = sizeof (loc);

  /* PLT code is not generated yet, so treat it specially.
     Note: Checking elf_aarch64_obj_tdata.plt_type & PLT_BTI is not
     enough because it only implies BTI in the PLT0 and tlsdesc PLT
     entries. Normal PLT entries don't have BTI in a shared library
     (because such PLT is normally not called indirectly and adding
     the BTI when a stub targets a PLT would change the PLT layout
     and it's too late for that here).  */
  if (section == globals->root.splt)
    memcpy (loc, globals->plt_entry, count);
  else if (!bfd_get_section_contents (section->owner, section, loc, off, count))
    return false;

  uint32_t insn = bfd_getl32 (loc);
  if (!AARCH64_HINT (insn))
    return false;
  return insn == AARCH64_BTI_C
	 || insn == AARCH64_PACIASP
	 || insn == AARCH64_BTI_JC
	 || insn == AARCH64_BTI_J
	 || insn == AARCH64_PACIBSP;
}

#define AARCH64_BITS(x, pos, n) (((x) >> (pos)) & ((1 << (n)) - 1))

#define AARCH64_RT(insn) AARCH64_BITS (insn, 0, 5)
#define AARCH64_RT2(insn) AARCH64_BITS (insn, 10, 5)
#define AARCH64_RA(insn) AARCH64_BITS (insn, 10, 5)
#define AARCH64_RD(insn) AARCH64_BITS (insn, 0, 5)
#define AARCH64_RN(insn) AARCH64_BITS (insn, 5, 5)
#define AARCH64_RM(insn) AARCH64_BITS (insn, 16, 5)

#define AARCH64_MAC(insn) (((insn) & 0xff000000) == 0x9b000000)
#define AARCH64_BIT(insn, n) AARCH64_BITS (insn, n, 1)
#define AARCH64_OP31(insn) AARCH64_BITS (insn, 21, 3)
#define AARCH64_ZR 0x1f

/* All ld/st ops.  See C4-182 of the ARM ARM.  The encoding space for
   LD_PCREL, LDST_RO, LDST_UI and LDST_UIMM cover prefetch ops.  */

#define AARCH64_LD(insn) (AARCH64_BIT (insn, 22) == 1)
#define AARCH64_LDST(insn) (((insn) & 0x0a000000) == 0x08000000)
#define AARCH64_LDST_EX(insn) (((insn) & 0x3f000000) == 0x08000000)
#define AARCH64_LDST_PCREL(insn) (((insn) & 0x3b000000) == 0x18000000)
#define AARCH64_LDST_NAP(insn) (((insn) & 0x3b800000) == 0x28000000)
#define AARCH64_LDSTP_PI(insn) (((insn) & 0x3b800000) == 0x28800000)
#define AARCH64_LDSTP_O(insn) (((insn) & 0x3b800000) == 0x29000000)
#define AARCH64_LDSTP_PRE(insn) (((insn) & 0x3b800000) == 0x29800000)
#define AARCH64_LDST_UI(insn) (((insn) & 0x3b200c00) == 0x38000000)
#define AARCH64_LDST_PIIMM(insn) (((insn) & 0x3b200c00) == 0x38000400)
#define AARCH64_LDST_U(insn) (((insn) & 0x3b200c00) == 0x38000800)
#define AARCH64_LDST_PREIMM(insn) (((insn) & 0x3b200c00) == 0x38000c00)
#define AARCH64_LDST_RO(insn) (((insn) & 0x3b200c00) == 0x38200800)
#define AARCH64_LDST_UIMM(insn) (((insn) & 0x3b000000) == 0x39000000)
#define AARCH64_LDST_SIMD_M(insn) (((insn) & 0xbfbf0000) == 0x0c000000)
#define AARCH64_LDST_SIMD_M_PI(insn) (((insn) & 0xbfa00000) == 0x0c800000)
#define AARCH64_LDST_SIMD_S(insn) (((insn) & 0xbf9f0000) == 0x0d000000)
#define AARCH64_LDST_SIMD_S_PI(insn) (((insn) & 0xbf800000) == 0x0d800000)

/* Classify an INSN if it is indeed a load/store.

   Return TRUE if INSN is a LD/ST instruction otherwise return FALSE.

   For scalar LD/ST instructions PAIR is FALSE, RT is returned and RT2
   is set equal to RT.

   For LD/ST pair instructions PAIR is TRUE, RT and RT2 are returned.  */

static bool
aarch64_mem_op_p (uint32_t insn, unsigned int *rt, unsigned int *rt2,
		  bool *pair, bool *load)
{
  uint32_t opcode;
  unsigned int r;
  uint32_t opc = 0;
  uint32_t v = 0;
  uint32_t opc_v = 0;

  /* Bail out quickly if INSN doesn't fall into the load-store
     encoding space.  */
  if (!AARCH64_LDST (insn))
    return false;

  *pair = false;
  *load = false;
  if (AARCH64_LDST_EX (insn))
    {
      *rt = AARCH64_RT (insn);
      *rt2 = *rt;
      if (AARCH64_BIT (insn, 21) == 1)
	{
	  *pair = true;
	  *rt2 = AARCH64_RT2 (insn);
	}
      *load = AARCH64_LD (insn);
      return true;
    }
  else if (AARCH64_LDST_NAP (insn)
	   || AARCH64_LDSTP_PI (insn)
	   || AARCH64_LDSTP_O (insn)
	   || AARCH64_LDSTP_PRE (insn))
    {
      *pair = true;
      *rt = AARCH64_RT (insn);
      *rt2 = AARCH64_RT2 (insn);
      *load = AARCH64_LD (insn);
      return true;
    }
  else if (AARCH64_LDST_PCREL (insn)
	   || AARCH64_LDST_UI (insn)
	   || AARCH64_LDST_PIIMM (insn)
	   || AARCH64_LDST_U (insn)
	   || AARCH64_LDST_PREIMM (insn)
	   || AARCH64_LDST_RO (insn)
	   || AARCH64_LDST_UIMM (insn))
   {
      *rt = AARCH64_RT (insn);
      *rt2 = *rt;
      if (AARCH64_LDST_PCREL (insn))
	*load = true;
      opc = AARCH64_BITS (insn, 22, 2);
      v = AARCH64_BIT (insn, 26);
      opc_v = opc | (v << 2);
      *load =  (opc_v == 1 || opc_v == 2 || opc_v == 3
		|| opc_v == 5 || opc_v == 7);
      return true;
   }
  else if (AARCH64_LDST_SIMD_M (insn)
	   || AARCH64_LDST_SIMD_M_PI (insn))
    {
      *rt = AARCH64_RT (insn);
      *load = AARCH64_BIT (insn, 22);
      opcode = (insn >> 12) & 0xf;
      switch (opcode)
	{
	case 0:
	case 2:
	  *rt2 = *rt + 3;
	  break;

	case 4:
	case 6:
	  *rt2 = *rt + 2;
	  break;

	case 7:
	  *rt2 = *rt;
	  break;

	case 8:
	case 10:
	  *rt2 = *rt + 1;
	  break;

	default:
	  return false;
	}
      return true;
    }
  else if (AARCH64_LDST_SIMD_S (insn)
	   || AARCH64_LDST_SIMD_S_PI (insn))
    {
      *rt = AARCH64_RT (insn);
      r = (insn >> 21) & 1;
      *load = AARCH64_BIT (insn, 22);
      opcode = (insn >> 13) & 0x7;
      switch (opcode)
	{
	case 0:
	case 2:
	case 4:
	  *rt2 = *rt + r;
	  break;

	case 1:
	case 3:
	case 5:
	  *rt2 = *rt + (r == 0 ? 2 : 3);
	  break;

	case 6:
	  *rt2 = *rt + r;
	  break;

	case 7:
	  *rt2 = *rt + (r == 0 ? 2 : 3);
	  break;

	default:
	  return false;
	}
      return true;
    }

  return false;
}

/* Return TRUE if INSN is multiply-accumulate.  */

static bool
aarch64_mlxl_p (uint32_t insn)
{
  uint32_t op31 = AARCH64_OP31 (insn);

  if (AARCH64_MAC (insn)
      && (op31 == 0 || op31 == 1 || op31 == 5)
      /* Exclude MUL instructions which are encoded as a multiple accumulate
	 with RA = XZR.  */
      && AARCH64_RA (insn) != AARCH64_ZR)
    return true;

  return false;
}

/* Some early revisions of the Cortex-A53 have an erratum (835769) whereby
   it is possible for a 64-bit multiply-accumulate instruction to generate an
   incorrect result.  The details are quite complex and hard to
   determine statically, since branches in the code may exist in some
   circumstances, but all cases end with a memory (load, store, or
   prefetch) instruction followed immediately by the multiply-accumulate
   operation.  We employ a linker patching technique, by moving the potentially
   affected multiply-accumulate instruction into a patch region and replacing
   the original instruction with a branch to the patch.  This function checks
   if INSN_1 is the memory operation followed by a multiply-accumulate
   operation (INSN_2).  Return TRUE if an erratum sequence is found, FALSE
   if INSN_1 and INSN_2 are safe.  */

static bool
aarch64_erratum_sequence (uint32_t insn_1, uint32_t insn_2)
{
  uint32_t rt;
  uint32_t rt2;
  uint32_t rn;
  uint32_t rm;
  uint32_t ra;
  bool pair;
  bool load;

  if (aarch64_mlxl_p (insn_2)
      && aarch64_mem_op_p (insn_1, &rt, &rt2, &pair, &load))
    {
      /* Any SIMD memory op is independent of the subsequent MLA
	 by definition of the erratum.  */
      if (AARCH64_BIT (insn_1, 26))
	return true;

      /* If not SIMD, check for integer memory ops and MLA relationship.  */
      rn = AARCH64_RN (insn_2);
      ra = AARCH64_RA (insn_2);
      rm = AARCH64_RM (insn_2);

      /* If this is a load and there's a true(RAW) dependency, we are safe
	 and this is not an erratum sequence.  */
      if (load &&
	  (rt == rn || rt == rm || rt == ra
	   || (pair && (rt2 == rn || rt2 == rm || rt2 == ra))))
	return false;

      /* We conservatively put out stubs for all other cases (including
	 writebacks).  */
      return true;
    }

  return false;
}

/* Used to order a list of mapping symbols by address.  */

static int
elf_aarch64_compare_mapping (const void *a, const void *b)
{
  const elf_aarch64_section_map *amap = (const elf_aarch64_section_map *) a;
  const elf_aarch64_section_map *bmap = (const elf_aarch64_section_map *) b;

  if (amap->vma > bmap->vma)
    return 1;
  else if (amap->vma < bmap->vma)
    return -1;
  else if (amap->type > bmap->type)
    /* Ensure results do not depend on the host qsort for objects with
       multiple mapping symbols at the same address by sorting on type
       after vma.  */
    return 1;
  else if (amap->type < bmap->type)
    return -1;
  else
    return 0;
}


static char *
_bfd_aarch64_erratum_835769_stub_name (unsigned num_fixes)
{
  char *stub_name = (char *) bfd_malloc
    (strlen ("__erratum_835769_veneer_") + 16);
  if (stub_name != NULL)
    sprintf (stub_name,"__erratum_835769_veneer_%d", num_fixes);
  return stub_name;
}

/* Scan for Cortex-A53 erratum 835769 sequence.

   Return TRUE else FALSE on abnormal termination.  */

static bool
_bfd_aarch64_erratum_835769_scan (bfd *input_bfd,
				  struct bfd_link_info *info,
				  unsigned int *num_fixes_p)
{
  asection *section;
  struct elf_aarch64_link_hash_table *htab = elf_aarch64_hash_table (info);
  unsigned int num_fixes = *num_fixes_p;

  if (htab == NULL)
    return true;

  for (section = input_bfd->sections;
       section != NULL;
       section = section->next)
    {
      bfd_byte *contents = NULL;
      struct _aarch64_elf_section_data *sec_data;
      unsigned int span;

      if (elf_section_type (section) != SHT_PROGBITS
	  || (elf_section_flags (section) & SHF_EXECINSTR) == 0
	  || (section->flags & SEC_EXCLUDE) != 0
	  || (section->sec_info_type == SEC_INFO_TYPE_JUST_SYMS)
	  || (section->output_section == bfd_abs_section_ptr))
	continue;

      if (elf_section_data (section)->this_hdr.contents != NULL)
	contents = elf_section_data (section)->this_hdr.contents;
      else if (! bfd_malloc_and_get_section (input_bfd, section, &contents))
	return false;

      sec_data = elf_aarch64_section_data (section);

      if (sec_data->mapcount)
	qsort (sec_data->map, sec_data->mapcount,
	       sizeof (elf_aarch64_section_map), elf_aarch64_compare_mapping);

      for (span = 0; span < sec_data->mapcount; span++)
	{
	  unsigned int span_start = sec_data->map[span].vma;
	  unsigned int span_end = ((span == sec_data->mapcount - 1)
				   ? sec_data->map[0].vma + section->size
				   : sec_data->map[span + 1].vma);
	  unsigned int i;
	  char span_type = sec_data->map[span].type;

	  if (span_type == 'd')
	    continue;

	  for (i = span_start; i + 4 < span_end; i += 4)
	    {
	      uint32_t insn_1 = bfd_getl32 (contents + i);
	      uint32_t insn_2 = bfd_getl32 (contents + i + 4);

	      if (aarch64_erratum_sequence (insn_1, insn_2))
		{
		  struct elf_aarch64_stub_hash_entry *stub_entry;
		  char *stub_name = _bfd_aarch64_erratum_835769_stub_name (num_fixes);
		  if (! stub_name)
		    return false;

		  stub_entry = _bfd_aarch64_add_stub_entry_in_group (stub_name,
								     section,
								     htab);
		  if (! stub_entry)
		    return false;

		  stub_entry->stub_type = aarch64_stub_erratum_835769_veneer;
		  stub_entry->target_section = section;
		  stub_entry->target_value = i + 4;
		  stub_entry->veneered_insn = insn_2;
		  stub_entry->output_name = stub_name;
		  num_fixes++;
		}
	    }
	}
      if (elf_section_data (section)->this_hdr.contents == NULL)
	free (contents);
    }

  *num_fixes_p = num_fixes;

  return true;
}


/* Test if instruction INSN is ADRP.  */

static bool
_bfd_aarch64_adrp_p (uint32_t insn)
{
  return ((insn & AARCH64_ADRP_OP_MASK) == AARCH64_ADRP_OP);
}


/* Helper predicate to look for cortex-a53 erratum 843419 sequence 1.  */

static bool
_bfd_aarch64_erratum_843419_sequence_p (uint32_t insn_1, uint32_t insn_2,
					uint32_t insn_3)
{
  uint32_t rt;
  uint32_t rt2;
  bool pair;
  bool load;

  return (aarch64_mem_op_p (insn_2, &rt, &rt2, &pair, &load)
	  && (!pair
	      || (pair && !load))
	  && AARCH64_LDST_UIMM (insn_3)
	  && AARCH64_RN (insn_3) == AARCH64_RD (insn_1));
}


/* Test for the presence of Cortex-A53 erratum 843419 instruction sequence.

   Return TRUE if section CONTENTS at offset I contains one of the
   erratum 843419 sequences, otherwise return FALSE.  If a sequence is
   seen set P_VENEER_I to the offset of the final LOAD/STORE
   instruction in the sequence.
 */

static bool
_bfd_aarch64_erratum_843419_p (bfd_byte *contents, bfd_vma vma,
			       bfd_vma i, bfd_vma span_end,
			       bfd_vma *p_veneer_i)
{
  uint32_t insn_1 = bfd_getl32 (contents + i);

  if (!_bfd_aarch64_adrp_p (insn_1))
    return false;

  if (span_end < i + 12)
    return false;

  uint32_t insn_2 = bfd_getl32 (contents + i + 4);
  uint32_t insn_3 = bfd_getl32 (contents + i + 8);

  if ((vma & 0xfff) != 0xff8 && (vma & 0xfff) != 0xffc)
    return false;

  if (_bfd_aarch64_erratum_843419_sequence_p (insn_1, insn_2, insn_3))
    {
      *p_veneer_i = i + 8;
      return true;
    }

  if (span_end < i + 16)
    return false;

  uint32_t insn_4 = bfd_getl32 (contents + i + 12);

  if (_bfd_aarch64_erratum_843419_sequence_p (insn_1, insn_2, insn_4))
    {
      *p_veneer_i = i + 12;
      return true;
    }

  return false;
}


/* Resize all stub sections.  */

static void
_bfd_aarch64_resize_stubs (struct elf_aarch64_link_hash_table *htab)
{
  asection *section;

  /* OK, we've added some stubs.  Find out the new size of the
     stub sections.  */
  for (section = htab->stub_bfd->sections;
       section != NULL; section = section->next)
    {
      /* Ignore non-stub sections.  */
      if (!strstr (section->name, STUB_SUFFIX))
	continue;

      /* Add space for a branch.  Add 8 bytes to keep section 8 byte aligned,
	 as long branch stubs contain a 64-bit address.  */
      section->size = 8;
    }

  bfd_hash_traverse (&htab->stub_hash_table, aarch64_size_one_stub, htab);

  for (section = htab->stub_bfd->sections;
       section != NULL; section = section->next)
    {
      if (!strstr (section->name, STUB_SUFFIX))
	continue;

      /* Empty stub section.  */
      if (section->size == 8)
	section->size = 0;

      /* Ensure all stub sections have a size which is a multiple of
	 4096.  This is important in order to ensure that the insertion
	 of stub sections does not in itself move existing code around
	 in such a way that new errata sequences are created.  We only do this
	 when the ADRP workaround is enabled.  If only the ADR workaround is
	 enabled then the stubs workaround won't ever be used.  */
      if (htab->fix_erratum_843419 & ERRAT_ADRP)
	if (section->size)
	  section->size = BFD_ALIGN (section->size, 0x1000);
    }
}

/* Construct an erratum 843419 workaround stub name.  */

static char *
_bfd_aarch64_erratum_843419_stub_name (asection *input_section,
				       bfd_vma offset)
{
  const bfd_size_type len = 8 + 4 + 1 + 8 + 1 + 16 + 1;
  char *stub_name = bfd_malloc (len);

  if (stub_name != NULL)
    snprintf (stub_name, len, "e843419@%04x_%08x_%" PRIx64,
	      input_section->owner->id,
	      input_section->id,
	      (uint64_t) offset);
  return stub_name;
}

/*  Build a stub_entry structure describing an 843419 fixup.

    The stub_entry constructed is populated with the bit pattern INSN
    of the instruction located at OFFSET within input SECTION.

    Returns TRUE on success.  */

static bool
_bfd_aarch64_erratum_843419_fixup (uint32_t insn,
				   bfd_vma adrp_offset,
				   bfd_vma ldst_offset,
				   asection *section,
				   struct bfd_link_info *info)
{
  struct elf_aarch64_link_hash_table *htab = elf_aarch64_hash_table (info);
  char *stub_name;
  struct elf_aarch64_stub_hash_entry *stub_entry;

  stub_name = _bfd_aarch64_erratum_843419_stub_name (section, ldst_offset);
  if (stub_name == NULL)
    return false;
  stub_entry = aarch64_stub_hash_lookup (&htab->stub_hash_table, stub_name,
					 false, false);
  if (stub_entry)
    {
      free (stub_name);
      return true;
    }

  /* We always place an 843419 workaround veneer in the stub section
     attached to the input section in which an erratum sequence has
     been found.  This ensures that later in the link process (in
     elf32_aarch64_write_section) when we copy the veneered
     instruction from the input section into the stub section the
     copied instruction will have had any relocations applied to it.
     If we placed workaround veneers in any other stub section then we
     could not assume that all relocations have been processed on the
     corresponding input section at the point we output the stub
     section.  */

  stub_entry = _bfd_aarch64_add_stub_entry_after (stub_name, section, htab);
  if (stub_entry == NULL)
    {
      free (stub_name);
      return false;
    }

  stub_entry->adrp_offset = adrp_offset;
  stub_entry->target_value = ldst_offset;
  stub_entry->target_section = section;
  stub_entry->stub_type = aarch64_stub_erratum_843419_veneer;
  stub_entry->veneered_insn = insn;
  stub_entry->output_name = stub_name;

  return true;
}


/* Scan an input section looking for the signature of erratum 843419.

   Scans input SECTION in INPUT_BFD looking for erratum 843419
   signatures, for each signature found a stub_entry is created
   describing the location of the erratum for subsequent fixup.

   Return TRUE on successful scan, FALSE on failure to scan.
 */

static bool
_bfd_aarch64_erratum_843419_scan (bfd *input_bfd, asection *section,
				  struct bfd_link_info *info)
{
  struct elf_aarch64_link_hash_table *htab = elf_aarch64_hash_table (info);

  if (htab == NULL)
    return true;

  if (elf_section_type (section) != SHT_PROGBITS
      || (elf_section_flags (section) & SHF_EXECINSTR) == 0
      || (section->flags & SEC_EXCLUDE) != 0
      || (section->sec_info_type == SEC_INFO_TYPE_JUST_SYMS)
      || (section->output_section == bfd_abs_section_ptr))
    return true;

  do
    {
      bfd_byte *contents = NULL;
      struct _aarch64_elf_section_data *sec_data;
      unsigned int span;

      if (elf_section_data (section)->this_hdr.contents != NULL)
	contents = elf_section_data (section)->this_hdr.contents;
      else if (! bfd_malloc_and_get_section (input_bfd, section, &contents))
	return false;

      sec_data = elf_aarch64_section_data (section);

      if (sec_data->mapcount)
	qsort (sec_data->map, sec_data->mapcount,
	       sizeof (elf_aarch64_section_map), elf_aarch64_compare_mapping);

      for (span = 0; span < sec_data->mapcount; span++)
	{
	  unsigned int span_start = sec_data->map[span].vma;
	  unsigned int span_end = ((span == sec_data->mapcount - 1)
				   ? sec_data->map[0].vma + section->size
				   : sec_data->map[span + 1].vma);
	  unsigned int i;
	  char span_type = sec_data->map[span].type;

	  if (span_type == 'd')
	    continue;

	  for (i = span_start; i + 8 < span_end; i += 4)
	    {
	      bfd_vma vma = (section->output_section->vma
			     + section->output_offset
			     + i);
	      bfd_vma veneer_i;

	      if (_bfd_aarch64_erratum_843419_p
		  (contents, vma, i, span_end, &veneer_i))
		{
		  uint32_t insn = bfd_getl32 (contents + veneer_i);

		  if (!_bfd_aarch64_erratum_843419_fixup (insn, i, veneer_i,
							  section, info))
		    return false;
		}
	    }
	}

      if (elf_section_data (section)->this_hdr.contents == NULL)
	free (contents);
    }
  while (0);

  return true;
}


/* Add stub entries for calls.

   The basic idea here is to examine all the relocations looking for
   PC-relative calls to a target that is unreachable with a "bl"
   instruction.  */

static bool
_bfd_aarch64_add_call_stub_entries (bool *stub_changed, bfd *output_bfd,
				    struct bfd_link_info *info)
{
  struct elf_aarch64_link_hash_table *htab = elf_aarch64_hash_table (info);
  bool need_bti = elf_aarch64_bti_p (output_bfd);
  bfd *input_bfd;

  for (input_bfd = info->input_bfds; input_bfd != NULL;
       input_bfd = input_bfd->link.next)
    {
      Elf_Internal_Shdr *symtab_hdr;
      asection *section;
      Elf_Internal_Sym *local_syms = NULL;

      if (!is_aarch64_elf (input_bfd)
	  || (input_bfd->flags & BFD_LINKER_CREATED) != 0)
	continue;

      /* We'll need the symbol table in a second.  */
      symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
      if (symtab_hdr->sh_info == 0)
	continue;

      /* Walk over each section attached to the input bfd.  */
      for (section = input_bfd->sections;
	   section != NULL; section = section->next)
	{
	  Elf_Internal_Rela *internal_relocs, *irelaend, *irela;

	  /* If there aren't any relocs, then there's nothing more to do.  */
	  if ((section->flags & SEC_RELOC) == 0
	      || section->reloc_count == 0
	      || (section->flags & SEC_CODE) == 0)
	    continue;

	  /* If this section is a link-once section that will be
	     discarded, then don't create any stubs.  */
	  if (section->output_section == NULL
	      || section->output_section->owner != output_bfd)
	    continue;

	  /* Get the relocs.  */
	  internal_relocs
	    = _bfd_elf_link_read_relocs (input_bfd, section, NULL,
					 NULL, info->keep_memory);
	  if (internal_relocs == NULL)
	    goto error_ret_free_local;

	  /* Now examine each relocation.  */
	  irela = internal_relocs;
	  irelaend = irela + section->reloc_count;
	  for (; irela < irelaend; irela++)
	    {
	      unsigned int r_type, r_indx;
	      enum elf_aarch64_stub_type stub_type;
	      struct elf_aarch64_stub_hash_entry *stub_entry;
	      struct elf_aarch64_stub_hash_entry *stub_entry_bti;
	      asection *sym_sec;
	      bfd_vma sym_value;
	      bfd_vma destination;
	      struct elf_aarch64_link_hash_entry *hash;
	      const char *sym_name;
	      char *stub_name;
	      char *stub_name_bti;
	      const asection *id_sec;
	      const asection *id_sec_bti;
	      unsigned char st_type;
	      bfd_size_type len;

	      r_type = ELF32_R_TYPE (irela->r_info);
	      r_indx = ELF32_R_SYM (irela->r_info);

	      if (r_type >= (unsigned int) R_AARCH64_end)
		{
		  bfd_set_error (bfd_error_bad_value);
		error_ret_free_internal:
		  if (elf_section_data (section)->relocs == NULL)
		    free (internal_relocs);
		  goto error_ret_free_local;
		}

	      /* Only look for stubs on unconditional branch and
		 branch and link instructions.  */
	      if (r_type != (unsigned int) AARCH64_R (CALL26)
		  && r_type != (unsigned int) AARCH64_R (JUMP26))
		continue;

	      /* Now determine the call target, its name, value,
		 section.  */
	      sym_sec = NULL;
	      sym_value = 0;
	      destination = 0;
	      hash = NULL;
	      sym_name = NULL;
	      if (r_indx < symtab_hdr->sh_info)
		{
		  /* It's a local symbol.  */
		  Elf_Internal_Sym *sym;
		  Elf_Internal_Shdr *hdr;

		  if (local_syms == NULL)
		    {
		      local_syms
			= (Elf_Internal_Sym *) symtab_hdr->contents;
		      if (local_syms == NULL)
			local_syms
			  = bfd_elf_get_elf_syms (input_bfd, symtab_hdr,
						  symtab_hdr->sh_info, 0,
						  NULL, NULL, NULL);
		      if (local_syms == NULL)
			goto error_ret_free_internal;
		    }

		  sym = local_syms + r_indx;
		  hdr = elf_elfsections (input_bfd)[sym->st_shndx];
		  sym_sec = hdr->bfd_section;
		  if (!sym_sec)
		    /* This is an undefined symbol.  It can never
		       be resolved.  */
		    continue;

		  if (ELF_ST_TYPE (sym->st_info) != STT_SECTION)
		    sym_value = sym->st_value;
		  destination = (sym_value + irela->r_addend
				 + sym_sec->output_offset
				 + sym_sec->output_section->vma);
		  st_type = ELF_ST_TYPE (sym->st_info);
		  sym_name
		    = bfd_elf_string_from_elf_section (input_bfd,
						       symtab_hdr->sh_link,
						       sym->st_name);
		}
	      else
		{
		  int e_indx;

		  e_indx = r_indx - symtab_hdr->sh_info;
		  hash = ((struct elf_aarch64_link_hash_entry *)
			  elf_sym_hashes (input_bfd)[e_indx]);

		  while (hash->root.root.type == bfd_link_hash_indirect
			 || hash->root.root.type == bfd_link_hash_warning)
		    hash = ((struct elf_aarch64_link_hash_entry *)
			    hash->root.root.u.i.link);

		  if (hash->root.root.type == bfd_link_hash_defined
		      || hash->root.root.type == bfd_link_hash_defweak)
		    {
		      struct elf_aarch64_link_hash_table *globals =
			elf_aarch64_hash_table (info);
		      sym_sec = hash->root.root.u.def.section;
		      sym_value = hash->root.root.u.def.value;
		      /* For a destination in a shared library,
			 use the PLT stub as target address to
			 decide whether a branch stub is
			 needed.  */
		      if (globals->root.splt != NULL && hash != NULL
			  && hash->root.plt.offset != (bfd_vma) - 1)
			{
			  sym_sec = globals->root.splt;
			  sym_value = hash->root.plt.offset;
			  if (sym_sec->output_section != NULL)
			    destination = (sym_value
					   + sym_sec->output_offset
					   + sym_sec->output_section->vma);
			}
		      else if (sym_sec->output_section != NULL)
			destination = (sym_value + irela->r_addend
				       + sym_sec->output_offset
				       + sym_sec->output_section->vma);
		    }
		  else if (hash->root.root.type == bfd_link_hash_undefined
			   || (hash->root.root.type
			       == bfd_link_hash_undefweak))
		    {
		      /* For a shared library, use the PLT stub as
			 target address to decide whether a long
			 branch stub is needed.
			 For absolute code, they cannot be handled.  */
		      struct elf_aarch64_link_hash_table *globals =
			elf_aarch64_hash_table (info);

		      if (globals->root.splt != NULL && hash != NULL
			  && hash->root.plt.offset != (bfd_vma) - 1)
			{
			  sym_sec = globals->root.splt;
			  sym_value = hash->root.plt.offset;
			  if (sym_sec->output_section != NULL)
			    destination = (sym_value
					   + sym_sec->output_offset
					   + sym_sec->output_section->vma);
			}
		      else
			continue;
		    }
		  else
		    {
		      bfd_set_error (bfd_error_bad_value);
		      goto error_ret_free_internal;
		    }
		  st_type = ELF_ST_TYPE (hash->root.type);
		  sym_name = hash->root.root.root.string;
		}

	      /* Determine what (if any) linker stub is needed.  */
	      stub_type = aarch64_type_of_stub (section, irela, sym_sec,
						st_type, destination);
	      if (stub_type == aarch64_stub_none)
		continue;

	      /* Support for grouping stub sections.  */
	      id_sec = htab->stub_group[section->id].link_sec;

	      /* Get the name of this stub.  */
	      stub_name = elf32_aarch64_stub_name (id_sec, sym_sec, hash,
						   irela);
	      if (!stub_name)
		goto error_ret_free_internal;

	      stub_entry =
		aarch64_stub_hash_lookup (&htab->stub_hash_table,
					  stub_name, false, false);
	      if (stub_entry != NULL)
		{
		  /* The proper stub has already been created.  */
		  free (stub_name);

		  /* Always update this stub's target since it may have
		     changed after layout.  */
		  stub_entry->target_value = sym_value + irela->r_addend;

		  if (stub_entry->double_stub)
		    {
		      /* Update the target of both stubs.  */

		      id_sec_bti = htab->stub_group[sym_sec->id].link_sec;
		      stub_name_bti =
			elf32_aarch64_stub_name (id_sec_bti, sym_sec, hash,
						 irela);
		      if (!stub_name_bti)
			goto error_ret_free_internal;
		      stub_entry_bti =
			aarch64_stub_hash_lookup (&htab->stub_hash_table,
						  stub_name_bti, false, false);
		      BFD_ASSERT (stub_entry_bti != NULL);
		      free (stub_name_bti);
		      stub_entry_bti->target_value = stub_entry->target_value;
		      stub_entry->target_value = stub_entry_bti->stub_offset;
		    }
		  continue;
		}

	      stub_entry = _bfd_aarch64_add_stub_entry_in_group
		(stub_name, section, htab);
	      if (stub_entry == NULL)
		{
		  free (stub_name);
		  goto error_ret_free_internal;
		}

	      stub_entry->target_value = sym_value + irela->r_addend;
	      stub_entry->target_section = sym_sec;
	      stub_entry->stub_type = stub_type;
	      stub_entry->h = hash;
	      stub_entry->st_type = st_type;

	      if (sym_name == NULL)
		sym_name = "unnamed";
	      len = sizeof (STUB_ENTRY_NAME) + strlen (sym_name);
	      stub_entry->output_name = bfd_alloc (htab->stub_bfd, len);
	      if (stub_entry->output_name == NULL)
		{
		  free (stub_name);
		  goto error_ret_free_internal;
		}

	      snprintf (stub_entry->output_name, len, STUB_ENTRY_NAME,
			sym_name);

	      /* A stub with indirect jump may break BTI compatibility, so
		 insert another stub with direct jump near the target then.  */
	      if (need_bti && !aarch64_bti_stub_p (info, stub_entry))
		{
		  id_sec_bti = htab->stub_group[sym_sec->id].link_sec;

		  /* If the stub with indirect jump and the BTI stub are in
		     the same stub group: change the indirect jump stub into
		     a BTI stub since a direct branch can reach the target.
		     The BTI landing pad is still needed in case another
		     stub indirectly jumps to it.  */
		  if (id_sec_bti == id_sec)
		    {
		      stub_entry->stub_type = aarch64_stub_bti_direct_branch;
		      goto skip_double_stub;
		    }

		  stub_entry->double_stub = true;
		  htab->has_double_stub = true;

		  stub_name_bti =
		    elf32_aarch64_stub_name (id_sec_bti, sym_sec, hash, irela);
		  if (!stub_name_bti)
		    {
		      free (stub_name);
		      goto error_ret_free_internal;
		    }

		  stub_entry_bti =
		    aarch64_stub_hash_lookup (&htab->stub_hash_table,
					      stub_name_bti, false, false);
		  if (stub_entry_bti != NULL)
		    BFD_ASSERT (stub_entry_bti->stub_type
				== aarch64_stub_bti_direct_branch);
		  else
		    {
		      stub_entry_bti =
			_bfd_aarch64_add_stub_entry_in_group (stub_name_bti,
							      sym_sec, htab);
		      if (stub_entry_bti == NULL)
			{
			  free (stub_name);
			  free (stub_name_bti);
			  goto error_ret_free_internal;
			}

		      stub_entry_bti->target_value =
			sym_value + irela->r_addend;
		      stub_entry_bti->target_section = sym_sec;
		      stub_entry_bti->stub_type =
			aarch64_stub_bti_direct_branch;
		      stub_entry_bti->h = hash;
		      stub_entry_bti->st_type = st_type;

		      len = sizeof (BTI_STUB_ENTRY_NAME) + strlen (sym_name);
		      stub_entry_bti->output_name = bfd_alloc (htab->stub_bfd,
							       len);
		      if (stub_entry_bti->output_name == NULL)
			{
			  free (stub_name);
			  free (stub_name_bti);
			  goto error_ret_free_internal;
			}
		      snprintf (stub_entry_bti->output_name, len,
				BTI_STUB_ENTRY_NAME, sym_name);
		    }

		  /* Update the indirect call stub to target the BTI stub.  */
		  stub_entry->target_value = 0;
		  stub_entry->target_section = stub_entry_bti->stub_sec;
		  stub_entry->stub_type = stub_type;
		  stub_entry->h = NULL;
		  stub_entry->st_type = STT_FUNC;
		}
skip_double_stub:
	      *stub_changed = true;
	    }

	  /* We're done with the internal relocs, free them.  */
	  if (elf_section_data (section)->relocs == NULL)
	    free (internal_relocs);
	}
    }
  return true;
 error_ret_free_local:
  return false;
}


/* Determine and set the size of the stub section for a final link.  */

bool
elf32_aarch64_size_stubs (bfd *output_bfd,
			  bfd *stub_bfd,
			  struct bfd_link_info *info,
			  bfd_signed_vma group_size,
			  asection * (*add_stub_section) (const char *,
							  asection *),
			  void (*layout_sections_again) (void))
{
  bfd_size_type stub_group_size;
  bool stubs_always_before_branch;
  struct elf_aarch64_link_hash_table *htab = elf_aarch64_hash_table (info);
  unsigned int num_erratum_835769_fixes = 0;

  /* Propagate mach to stub bfd, because it may not have been
     finalized when we created stub_bfd.  */
  bfd_set_arch_mach (stub_bfd, bfd_get_arch (output_bfd),
		     bfd_get_mach (output_bfd));

  /* Stash our params away.  */
  htab->stub_bfd = stub_bfd;
  htab->add_stub_section = add_stub_section;
  htab->layout_sections_again = layout_sections_again;
  stubs_always_before_branch = group_size < 0;
  if (group_size < 0)
    stub_group_size = -group_size;
  else
    stub_group_size = group_size;

  if (stub_group_size == 1)
    {
      /* Default values.  */
      /* AArch64 branch range is +-128MB. The value used is 1MB less.  */
      stub_group_size = 127 * 1024 * 1024;
    }

  group_sections (htab, stub_group_size, stubs_always_before_branch);

  (*htab->layout_sections_again) ();

  if (htab->fix_erratum_835769)
    {
      bfd *input_bfd;

      for (input_bfd = info->input_bfds;
	   input_bfd != NULL; input_bfd = input_bfd->link.next)
	{
	  if (!is_aarch64_elf (input_bfd)
	      || (input_bfd->flags & BFD_LINKER_CREATED) != 0)
	    continue;

	  if (!_bfd_aarch64_erratum_835769_scan (input_bfd, info,
						 &num_erratum_835769_fixes))
	    return false;
	}

      _bfd_aarch64_resize_stubs (htab);
      (*htab->layout_sections_again) ();
    }

  if (htab->fix_erratum_843419 != ERRAT_NONE)
    {
      bfd *input_bfd;

      for (input_bfd = info->input_bfds;
	   input_bfd != NULL;
	   input_bfd = input_bfd->link.next)
	{
	  asection *section;

	  if (!is_aarch64_elf (input_bfd)
	      || (input_bfd->flags & BFD_LINKER_CREATED) != 0)
	    continue;

	  for (section = input_bfd->sections;
	       section != NULL;
	       section = section->next)
	    if (!_bfd_aarch64_erratum_843419_scan (input_bfd, section, info))
	      return false;
	}

      _bfd_aarch64_resize_stubs (htab);
      (*htab->layout_sections_again) ();
    }

  for (;;)
    {
      bool stub_changed = false;

      if (!_bfd_aarch64_add_call_stub_entries (&stub_changed, output_bfd, info))
	return false;

      if (!stub_changed)
	return true;

      _bfd_aarch64_resize_stubs (htab);
      (*htab->layout_sections_again) ();
    }
}

/* Build all the stubs associated with the current output file.  The
   stubs are kept in a hash table attached to the main linker hash
   table.  We also set up the .plt entries for statically linked PIC
   functions here.  This function is called via aarch64_elf_finish in the
   linker.  */

bool
elf32_aarch64_build_stubs (struct bfd_link_info *info)
{
  asection *stub_sec;
  struct bfd_hash_table *table;
  struct elf_aarch64_link_hash_table *htab;

  htab = elf_aarch64_hash_table (info);

  for (stub_sec = htab->stub_bfd->sections;
       stub_sec != NULL; stub_sec = stub_sec->next)
    {
      bfd_size_type size;

      /* Ignore non-stub sections.  */
      if (!strstr (stub_sec->name, STUB_SUFFIX))
	continue;

      /* Allocate memory to hold the linker stubs.  */
      size = stub_sec->size;
      stub_sec->contents = bfd_zalloc (htab->stub_bfd, size);
      if (stub_sec->contents == NULL && size != 0)
	return false;
      stub_sec->alloced = 1;
      stub_sec->size = 0;

      /* Add a branch around the stub section, and a nop, to keep it 8 byte
	 aligned, as long branch stubs contain a 64-bit address.  */
      bfd_putl32 (0x14000000 | (size >> 2), stub_sec->contents);
      bfd_putl32 (INSN_NOP, stub_sec->contents + 4);
      stub_sec->size += 8;
    }

  /* Build the stubs as directed by the stub hash table.  */
  table = &htab->stub_hash_table;
  bfd_hash_traverse (table, aarch64_build_one_stub, info);

  return true;
}


/* Add an entry to the code/data map for section SEC.  */

static void
elf32_aarch64_section_map_add (asection *sec, char type, bfd_vma vma)
{
  struct _aarch64_elf_section_data *sec_data =
    elf_aarch64_section_data (sec);
  unsigned int newidx;

  if (sec_data->map == NULL)
    {
      sec_data->map = bfd_malloc (sizeof (elf_aarch64_section_map));
      sec_data->mapcount = 0;
      sec_data->mapsize = 1;
    }

  newidx = sec_data->mapcount++;

  if (sec_data->mapcount > sec_data->mapsize)
    {
      sec_data->mapsize *= 2;
      sec_data->map = bfd_realloc_or_free
	(sec_data->map, sec_data->mapsize * sizeof (elf_aarch64_section_map));
    }

  if (sec_data->map)
    {
      sec_data->map[newidx].vma = vma;
      sec_data->map[newidx].type = type;
    }
}


/* Initialise maps of insn/data for input BFDs.  */
void
bfd_elf32_aarch64_init_maps (bfd *abfd)
{
  Elf_Internal_Sym *isymbuf;
  Elf_Internal_Shdr *hdr;
  unsigned int i, localsyms;

  /* Make sure that we are dealing with an AArch64 elf binary.  */
  if (!is_aarch64_elf (abfd))
    return;

  if ((abfd->flags & DYNAMIC) != 0)
   return;

  hdr = &elf_symtab_hdr (abfd);
  localsyms = hdr->sh_info;

  /* Obtain a buffer full of symbols for this BFD. The hdr->sh_info field
     should contain the number of local symbols, which should come before any
     global symbols.  Mapping symbols are always local.  */
  isymbuf = bfd_elf_get_elf_syms (abfd, hdr, localsyms, 0, NULL, NULL, NULL);

  /* No internal symbols read?  Skip this BFD.  */
  if (isymbuf == NULL)
    return;

  for (i = 0; i < localsyms; i++)
    {
      Elf_Internal_Sym *isym = &isymbuf[i];
      asection *sec = bfd_section_from_elf_index (abfd, isym->st_shndx);
      const char *name;

      if (sec != NULL && ELF_ST_BIND (isym->st_info) == STB_LOCAL)
	{
	  name = bfd_elf_string_from_elf_section (abfd,
						  hdr->sh_link,
						  isym->st_name);

	  if (bfd_is_aarch64_special_symbol_name
	      (name, BFD_AARCH64_SPECIAL_SYM_TYPE_MAP))
	    elf32_aarch64_section_map_add (sec, name[1], isym->st_value);
	}
    }
}

static void
setup_plt_values (struct bfd_link_info *link_info,
		  aarch64_plt_type plt_type)
{
  struct elf_aarch64_link_hash_table *globals;
  globals = elf_aarch64_hash_table (link_info);

  if (plt_type == PLT_BTI_PAC)
    {
      globals->plt0_entry = elf32_aarch64_small_plt0_bti_entry;

      /* Only in ET_EXEC we need PLTn with BTI.  */
      if (bfd_link_executable (link_info))
	{
	  globals->plt_entry_size = PLT_BTI_PAC_SMALL_ENTRY_SIZE;
	  globals->plt_entry = elf32_aarch64_small_plt_bti_pac_entry;
	  globals->plt_entry_delta = 4;
	}
      else
	{
	  globals->plt_entry_size = PLT_PAC_SMALL_ENTRY_SIZE;
	  globals->plt_entry = elf32_aarch64_small_plt_pac_entry;
	  globals->plt_entry_delta = 0;
	}
    }
  else if (plt_type == PLT_BTI)
    {
      globals->plt0_entry = elf32_aarch64_small_plt0_bti_entry;

      /* Only in ET_EXEC we need PLTn with BTI.  */
      if (bfd_link_executable (link_info))
	{
	  globals->plt_entry_size = PLT_BTI_SMALL_ENTRY_SIZE;
	  globals->plt_entry = elf32_aarch64_small_plt_bti_entry;
	  globals->plt_entry_delta = 4;
	}
    }
  else if (plt_type == PLT_PAC)
    {
      globals->plt_entry_size = PLT_PAC_SMALL_ENTRY_SIZE;
      globals->plt_entry = elf32_aarch64_small_plt_pac_entry;
    }
}

/* Set option values needed during linking.  */
void
bfd_elf32_aarch64_set_options (struct bfd *output_bfd,
			       struct bfd_link_info *link_info,
			       int no_enum_warn,
			       int no_wchar_warn, int pic_veneer,
			       int fix_erratum_835769,
			       erratum_84319_opts fix_erratum_843419,
			       int no_apply_dynamic_relocs,
			       const aarch64_protection_opts *sw_protections,
			       const aarch64_memtag_opts *memtag_opts)
{
  struct elf_aarch64_link_hash_table *globals;

  globals = elf_aarch64_hash_table (link_info);
  globals->pic_veneer = pic_veneer;
  globals->fix_erratum_835769 = fix_erratum_835769;
  globals->memtag_opts = *memtag_opts;
  /* If the default options are used, then ERRAT_ADR will be set by default
     which will enable the ADRP->ADR workaround for the erratum 843419
     workaround.  */
  globals->fix_erratum_843419 = fix_erratum_843419;
  globals->no_apply_dynamic_relocs = no_apply_dynamic_relocs;

  BFD_ASSERT (is_aarch64_elf (output_bfd));
  elf_aarch64_tdata (output_bfd)->no_enum_size_warning = no_enum_warn;
  elf_aarch64_tdata (output_bfd)->no_wchar_size_warning = no_wchar_warn;

  /* Note: gnu_property_aarch64_feature_1_and was initialized to 0 by
     bfd_zalloc().  */
  if (sw_protections->plt_type & PLT_BTI)
    elf_aarch64_tdata (output_bfd)->gnu_property_aarch64_feature_1_and
      |= GNU_PROPERTY_AARCH64_FEATURE_1_BTI;

  switch (sw_protections->gcs_type)
    {
    case GCS_ALWAYS:
      elf_aarch64_tdata (output_bfd)->gnu_property_aarch64_feature_1_and
	|= GNU_PROPERTY_AARCH64_FEATURE_1_GCS;
      break;
    case GCS_NEVER:
      elf_aarch64_tdata (output_bfd)->gnu_property_aarch64_feature_1_and
	&= ~GNU_PROPERTY_AARCH64_FEATURE_1_GCS;
      break;
    case GCS_IMPLICIT:
      /* GCS feature on the output bfd will be deduced from input objects.  */
      break;
    }

  elf_aarch64_tdata (output_bfd)->sw_protections = *sw_protections;
  /* Inherit the value from '-z gcs-report' if the option '-z gcs-report-dynamic'
     was not set on the command line.  However, the inheritance mechanism is
     capped to avoid inheriting the error level from -g gcs-report as the user
     might want to continue to build a module without rebuilding all the shared
     libraries.  If a user also wants to error GCS issues in the shared
     libraries, '-z gcs-report-dynamic=error' will have to be specified
     explicitly.  */
  if (sw_protections->gcs_report_dynamic == MARKING_UNSET)
    elf_aarch64_tdata (output_bfd)->sw_protections.gcs_report_dynamic
      = (sw_protections->gcs_report == MARKING_ERROR)
      ? MARKING_WARN
      : sw_protections->gcs_report;

  elf_aarch64_tdata (output_bfd)->n_bti_issues = 0;
  elf_aarch64_tdata (output_bfd)->n_gcs_issues = 0;
  elf_aarch64_tdata (output_bfd)->n_gcs_dynamic_issues = 0;

  setup_plt_values (link_info, sw_protections->plt_type);
}

static bfd_vma
aarch64_calculate_got_entry_vma (struct elf_link_hash_entry *h,
				 struct elf_aarch64_link_hash_table
				 *globals, struct bfd_link_info *info,
				 bfd_vma value, bfd *output_bfd,
				 bool *unresolved_reloc_p)
{
  bfd_vma off = (bfd_vma) - 1;
  asection *basegot = globals->root.sgot;
  bool dyn = globals->root.dynamic_sections_created;

  if (h != NULL)
    {
      BFD_ASSERT (basegot != NULL);
      off = h->got.offset;
      BFD_ASSERT (off != (bfd_vma) - 1);
      if (!WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, bfd_link_pic (info), h)
	  || (bfd_link_pic (info)
	      && SYMBOL_REFERENCES_LOCAL (info, h))
	  || (ELF_ST_VISIBILITY (h->other)
	      && h->root.type == bfd_link_hash_undefweak))
	{
	  /* This is actually a static link, or it is a -Bsymbolic link
	     and the symbol is defined locally.  We must initialize this
	     entry in the global offset table.  Since the offset must
	     always be a multiple of 8 (4 in the case of ILP32), we use
	     the least significant bit to record whether we have
	     initialized it already.
	     When doing a dynamic link, we create a .rel(a).got relocation
	     entry to initialize the value.  This is done in the
	     finish_dynamic_symbol routine.  */
	  if ((off & 1) != 0)
	    off &= ~1;
	  else
	    {
	      bfd_put_32 (output_bfd, value, basegot->contents + off);
	      h->got.offset |= 1;
	    }
	}
      else
	*unresolved_reloc_p = false;

      off = off + basegot->output_section->vma + basegot->output_offset;
    }

  return off;
}

/* Change R_TYPE to a more efficient access model where possible,
   return the new reloc type.  */

static bfd_reloc_code_real_type
aarch64_tls_transition_without_check (bfd_reloc_code_real_type r_type,
				      struct elf_link_hash_entry *h,
				      struct bfd_link_info *info)
{
  bool local_exec = bfd_link_executable (info)
    && SYMBOL_REFERENCES_LOCAL (info, h);

  switch (r_type)
    {
    case BFD_RELOC_AARCH64_TLSDESC_ADR_PAGE21:
    case BFD_RELOC_AARCH64_TLSGD_ADR_PAGE21:
      return (local_exec
	      ? BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G1
	      : BFD_RELOC_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21);

    case BFD_RELOC_AARCH64_TLSDESC_ADR_PREL21:
      return (local_exec
	      ? BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G0_NC
	      : r_type);

    case BFD_RELOC_AARCH64_TLSDESC_LD_PREL19:
      return (local_exec
	      ? BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G1
	      : BFD_RELOC_AARCH64_TLSIE_LD_GOTTPREL_PREL19);

    case BFD_RELOC_AARCH64_TLSDESC_LDR:
      return (local_exec
	      ? BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G0_NC
	      : BFD_RELOC_AARCH64_NONE);

    case BFD_RELOC_AARCH64_TLSDESC_OFF_G0_NC:
      return (local_exec
	      ? BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G1_NC
	      : BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC);

    case BFD_RELOC_AARCH64_TLSDESC_OFF_G1:
      return (local_exec
	      ? BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G2
	      : BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G1);

    case BFD_RELOC_AARCH64_TLSDESC_LD32_LO12_NC:
    case BFD_RELOC_AARCH64_TLSGD_ADD_LO12_NC:
      return (local_exec
	      ? BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G0_NC
	      : BFD_RELOC_AARCH64_TLSIE_LD32_GOTTPREL_LO12_NC);

    case BFD_RELOC_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21:
      return local_exec ? BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G1 : r_type;

    case BFD_RELOC_AARCH64_TLSIE_LD32_GOTTPREL_LO12_NC:
      return local_exec ? BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G0_NC : r_type;

    case BFD_RELOC_AARCH64_TLSIE_LD_GOTTPREL_PREL19:
      return r_type;

    case BFD_RELOC_AARCH64_TLSGD_ADR_PREL21:
      return (local_exec
	      ? BFD_RELOC_AARCH64_TLSLE_ADD_TPREL_HI12
	      : BFD_RELOC_AARCH64_TLSIE_LD_GOTTPREL_PREL19);

    case BFD_RELOC_AARCH64_TLSDESC_ADD:
    case BFD_RELOC_AARCH64_TLSDESC_ADD_LO12:
    case BFD_RELOC_AARCH64_TLSDESC_CALL:
      /* Instructions with these relocations will become NOPs.  */
      return BFD_RELOC_AARCH64_NONE;

    case BFD_RELOC_AARCH64_TLSLD_ADD_LO12_NC:
    case BFD_RELOC_AARCH64_TLSLD_ADR_PAGE21:
    case BFD_RELOC_AARCH64_TLSLD_ADR_PREL21:
      return local_exec ? BFD_RELOC_AARCH64_NONE : r_type;

#if ARCH_SIZE == 64
    case BFD_RELOC_AARCH64_TLSGD_MOVW_G0_NC:
      return local_exec
	? BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G1_NC
	: BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC;

    case BFD_RELOC_AARCH64_TLSGD_MOVW_G1:
      return local_exec
	? BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G2
	: BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G1;
#endif

    default:
      break;
    }

  return r_type;
}

static unsigned int
aarch64_reloc_got_type (bfd_reloc_code_real_type r_type)
{
  switch (r_type)
    {
    case BFD_RELOC_AARCH64_ADR_GOT_PAGE:
    case BFD_RELOC_AARCH64_GOT_LD_PREL19:
    case BFD_RELOC_AARCH64_LD32_GOTPAGE_LO14:
    case BFD_RELOC_AARCH64_LD32_GOT_LO12_NC:
    case BFD_RELOC_AARCH64_LD64_GOTOFF_LO15:
    case BFD_RELOC_AARCH64_LD64_GOTPAGE_LO15:
    case BFD_RELOC_AARCH64_LD64_GOT_LO12_NC:
    case BFD_RELOC_AARCH64_MOVW_GOTOFF_G0_NC:
    case BFD_RELOC_AARCH64_MOVW_GOTOFF_G1:
      return GOT_NORMAL;

    case BFD_RELOC_AARCH64_TLSGD_ADD_LO12_NC:
    case BFD_RELOC_AARCH64_TLSGD_ADR_PAGE21:
    case BFD_RELOC_AARCH64_TLSGD_ADR_PREL21:
    case BFD_RELOC_AARCH64_TLSGD_MOVW_G0_NC:
    case BFD_RELOC_AARCH64_TLSGD_MOVW_G1:
    case BFD_RELOC_AARCH64_TLSLD_ADD_LO12_NC:
    case BFD_RELOC_AARCH64_TLSLD_ADR_PAGE21:
    case BFD_RELOC_AARCH64_TLSLD_ADR_PREL21:
      return GOT_TLS_GD;

    case BFD_RELOC_AARCH64_TLSDESC_ADD:
    case BFD_RELOC_AARCH64_TLSDESC_ADD_LO12:
    case BFD_RELOC_AARCH64_TLSDESC_ADR_PAGE21:
    case BFD_RELOC_AARCH64_TLSDESC_ADR_PREL21:
    case BFD_RELOC_AARCH64_TLSDESC_CALL:
    case BFD_RELOC_AARCH64_TLSDESC_LD32_LO12_NC:
    case BFD_RELOC_AARCH64_TLSDESC_LD64_LO12:
    case BFD_RELOC_AARCH64_TLSDESC_LD_PREL19:
    case BFD_RELOC_AARCH64_TLSDESC_LDR:
    case BFD_RELOC_AARCH64_TLSDESC_OFF_G0_NC:
    case BFD_RELOC_AARCH64_TLSDESC_OFF_G1:
      return GOT_TLSDESC_GD;

    case BFD_RELOC_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21:
    case BFD_RELOC_AARCH64_TLSIE_LD32_GOTTPREL_LO12_NC:
    case BFD_RELOC_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC:
    case BFD_RELOC_AARCH64_TLSIE_LD_GOTTPREL_PREL19:
    case BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC:
    case BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G1:
      return GOT_TLS_IE;

    default:
      break;
    }
  return GOT_UNKNOWN;
}

static bool
aarch64_can_relax_tls (bfd *input_bfd,
		       struct bfd_link_info *info,
		       bfd_reloc_code_real_type r_type,
		       struct elf_link_hash_entry *h,
		       unsigned long r_symndx)
{
  unsigned int symbol_got_type;
  unsigned int reloc_got_type;

  if (! IS_AARCH64_TLS_RELAX_RELOC (r_type))
    return false;

  symbol_got_type = elf32_aarch64_symbol_got_type (h, input_bfd, r_symndx);
  reloc_got_type = aarch64_reloc_got_type (r_type);

  if (symbol_got_type == GOT_TLS_IE && GOT_TLS_GD_ANY_P (reloc_got_type))
    return true;

  if (!bfd_link_executable (info))
    return false;

  if  (h && h->root.type == bfd_link_hash_undefweak)
    return false;

  return true;
}

/* Given the relocation code R_TYPE, return the relaxed bfd reloc
   enumerator.  */

static bfd_reloc_code_real_type
aarch64_tls_transition (bfd *input_bfd,
			struct bfd_link_info *info,
			unsigned int r_type,
			struct elf_link_hash_entry *h,
			unsigned long r_symndx)
{
  bfd_reloc_code_real_type bfd_r_type
    = elf32_aarch64_bfd_reloc_from_type (input_bfd, r_type);

  if (! aarch64_can_relax_tls (input_bfd, info, bfd_r_type, h, r_symndx))
    return bfd_r_type;

  return aarch64_tls_transition_without_check (bfd_r_type, h, info);
}

/* Return the base VMA address which should be subtracted from real addresses
   when resolving R_AARCH64_TLS_DTPREL relocation.  */

static bfd_vma
dtpoff_base (struct bfd_link_info *info)
{
  /* If tls_sec is NULL, we should have signalled an error already.  */
  BFD_ASSERT (elf_hash_table (info)->tls_sec != NULL);
  return elf_hash_table (info)->tls_sec->vma;
}

/* Return the base VMA address which should be subtracted from real addresses
   when resolving R_AARCH64_TLS_GOTTPREL64 relocations.  */

static bfd_vma
tpoff_base (struct bfd_link_info *info)
{
  struct elf_link_hash_table *htab = elf_hash_table (info);

  /* If tls_sec is NULL, we should have signalled an error already.  */
  BFD_ASSERT (htab->tls_sec != NULL);

  bfd_vma base = align_power ((bfd_vma) TCB_SIZE,
			      htab->tls_sec->alignment_power);
  return htab->tls_sec->vma - base;
}

static bfd_vma *
symbol_got_offset_ref (bfd *input_bfd, struct elf_link_hash_entry *h,
		       unsigned long r_symndx)
{
  /* Calculate the address of the GOT entry for symbol
     referred to in h.  */
  if (h != NULL)
    return &h->got.offset;
  else
    {
      /* local symbol */
      struct elf_aarch64_local_symbol *l;

      l = elf_aarch64_locals (input_bfd);
      return &l[r_symndx].got_offset;
    }
}

static void
symbol_got_offset_mark (bfd *input_bfd, struct elf_link_hash_entry *h,
			unsigned long r_symndx)
{
  bfd_vma *p;
  p = symbol_got_offset_ref (input_bfd, h, r_symndx);
  *p |= 1;
}

static int
symbol_got_offset_mark_p (bfd *input_bfd, struct elf_link_hash_entry *h,
			  unsigned long r_symndx)
{
  bfd_vma value;
  value = * symbol_got_offset_ref (input_bfd, h, r_symndx);
  return value & 1;
}

static bfd_vma
symbol_got_offset (bfd *input_bfd, struct elf_link_hash_entry *h,
		   unsigned long r_symndx)
{
  bfd_vma value;
  value = * symbol_got_offset_ref (input_bfd, h, r_symndx);
  value &= ~1;
  return value;
}

static bfd_vma *
symbol_tlsdesc_got_offset_ref (bfd *input_bfd, struct elf_link_hash_entry *h,
			       unsigned long r_symndx)
{
  /* Calculate the address of the GOT entry for symbol
     referred to in h.  */
  if (h != NULL)
    {
      struct elf_aarch64_link_hash_entry *eh;
      eh = (struct elf_aarch64_link_hash_entry *) h;
      return &eh->tlsdesc_got_jump_table_offset;
    }
  else
    {
      /* local symbol */
      struct elf_aarch64_local_symbol *l;

      l = elf_aarch64_locals (input_bfd);
      return &l[r_symndx].tlsdesc_got_jump_table_offset;
    }
}

static void
symbol_tlsdesc_got_offset_mark (bfd *input_bfd, struct elf_link_hash_entry *h,
				unsigned long r_symndx)
{
  bfd_vma *p;
  p = symbol_tlsdesc_got_offset_ref (input_bfd, h, r_symndx);
  *p |= 1;
}

static int
symbol_tlsdesc_got_offset_mark_p (bfd *input_bfd,
				  struct elf_link_hash_entry *h,
				  unsigned long r_symndx)
{
  bfd_vma value;
  value = * symbol_tlsdesc_got_offset_ref (input_bfd, h, r_symndx);
  return value & 1;
}

static bfd_vma
symbol_tlsdesc_got_offset (bfd *input_bfd, struct elf_link_hash_entry *h,
			  unsigned long r_symndx)
{
  bfd_vma value;
  value = * symbol_tlsdesc_got_offset_ref (input_bfd, h, r_symndx);
  value &= ~1;
  return value;
}

/* Data for make_branch_to_erratum_835769_stub().  */

struct erratum_835769_branch_to_stub_data
{
  struct bfd_link_info *info;
  asection *output_section;
  bfd_byte *contents;
};

/* Helper to insert branches to erratum 835769 stubs in the right
   places for a particular section.  */

static bool
make_branch_to_erratum_835769_stub (struct bfd_hash_entry *gen_entry,
				    void *in_arg)
{
  struct elf_aarch64_stub_hash_entry *stub_entry;
  struct erratum_835769_branch_to_stub_data *data;
  bfd_byte *contents;
  unsigned long branch_insn = 0;
  bfd_vma veneered_insn_loc, veneer_entry_loc;
  bfd_signed_vma branch_offset;
  unsigned int target;
  bfd *abfd;

  stub_entry = (struct elf_aarch64_stub_hash_entry *) gen_entry;
  data = (struct erratum_835769_branch_to_stub_data *) in_arg;

  if (stub_entry->target_section != data->output_section
      || stub_entry->stub_type != aarch64_stub_erratum_835769_veneer)
    return true;

  contents = data->contents;
  veneered_insn_loc = stub_entry->target_section->output_section->vma
		      + stub_entry->target_section->output_offset
		      + stub_entry->target_value;
  veneer_entry_loc = stub_entry->stub_sec->output_section->vma
		     + stub_entry->stub_sec->output_offset
		     + stub_entry->stub_offset;
  branch_offset = veneer_entry_loc - veneered_insn_loc;

  abfd = stub_entry->target_section->owner;
  if (!aarch64_valid_branch_p (veneer_entry_loc, veneered_insn_loc))
    _bfd_error_handler
      (_("%pB: error: erratum 835769 stub out "
	 "of range (input file too large)"), abfd);

  target = stub_entry->target_value;
  branch_insn = 0x14000000;
  branch_offset >>= 2;
  branch_offset &= 0x3ffffff;
  branch_insn |= branch_offset;
  bfd_putl32 (branch_insn, &contents[target]);

  return true;
}


static bool
_bfd_aarch64_erratum_843419_branch_to_stub (struct bfd_hash_entry *gen_entry,
					    void *in_arg)
{
  struct elf_aarch64_stub_hash_entry *stub_entry
    = (struct elf_aarch64_stub_hash_entry *) gen_entry;
  struct erratum_835769_branch_to_stub_data *data
    = (struct erratum_835769_branch_to_stub_data *) in_arg;
  struct bfd_link_info *info;
  struct elf_aarch64_link_hash_table *htab;
  bfd_byte *contents;
  asection *section;
  bfd *abfd;
  bfd_vma place;
  uint32_t insn;

  info = data->info;
  contents = data->contents;
  section = data->output_section;

  htab = elf_aarch64_hash_table (info);

  if (stub_entry->target_section != section
      || stub_entry->stub_type != aarch64_stub_erratum_843419_veneer)
    return true;

  BFD_ASSERT (((htab->fix_erratum_843419 & ERRAT_ADRP) && stub_entry->stub_sec)
	      || (htab->fix_erratum_843419 & ERRAT_ADR));

  /* Only update the stub section if we have one.  We should always have one if
     we're allowed to use the ADRP errata workaround, otherwise it is not
     required.  */
  if (stub_entry->stub_sec)
    {
      insn = bfd_getl32 (contents + stub_entry->target_value);
      bfd_putl32 (insn,
		  stub_entry->stub_sec->contents + stub_entry->stub_offset);
    }

  place = (section->output_section->vma + section->output_offset
	   + stub_entry->adrp_offset);
  insn = bfd_getl32 (contents + stub_entry->adrp_offset);

  if (!_bfd_aarch64_adrp_p (insn))
    abort ();

  bfd_signed_vma imm =
    (_bfd_aarch64_sign_extend
     ((bfd_vma) _bfd_aarch64_decode_adrp_imm (insn) << 12, 33)
     - (place & 0xfff));

  if ((htab->fix_erratum_843419 & ERRAT_ADR)
      && (imm >= AARCH64_MIN_ADRP_IMM  && imm <= AARCH64_MAX_ADRP_IMM))
    {
      insn = (_bfd_aarch64_reencode_adr_imm (AARCH64_ADR_OP, imm)
	      | AARCH64_RT (insn));
      bfd_putl32 (insn, contents + stub_entry->adrp_offset);
      /* Stub is not needed, don't map it out.  */
      stub_entry->stub_type = aarch64_stub_none;
    }
  else if (htab->fix_erratum_843419 & ERRAT_ADRP)
    {
      bfd_vma veneered_insn_loc;
      bfd_vma veneer_entry_loc;
      bfd_signed_vma branch_offset;
      uint32_t branch_insn;

      veneered_insn_loc = stub_entry->target_section->output_section->vma
	+ stub_entry->target_section->output_offset
	+ stub_entry->target_value;
      veneer_entry_loc = stub_entry->stub_sec->output_section->vma
	+ stub_entry->stub_sec->output_offset
	+ stub_entry->stub_offset;
      branch_offset = veneer_entry_loc - veneered_insn_loc;

      abfd = stub_entry->target_section->owner;
      if (!aarch64_valid_branch_p (veneer_entry_loc, veneered_insn_loc))
	_bfd_error_handler
	  (_("%pB: error: erratum 843419 stub out "
	     "of range (input file too large)"), abfd);

      branch_insn = 0x14000000;
      branch_offset >>= 2;
      branch_offset &= 0x3ffffff;
      branch_insn |= branch_offset;
      bfd_putl32 (branch_insn, contents + stub_entry->target_value);
    }
  else
    {
      abfd = stub_entry->target_section->owner;
      _bfd_error_handler
	(_("%pB: error: erratum 843419 immediate 0x%" PRIx64
	   " out of range for ADR (input file too large) and "
	   "--fix-cortex-a53-843419=adr used.  Run the linker with "
	   "--fix-cortex-a53-843419=full instead"),
	 abfd, (uint64_t) (bfd_vma) imm);
      bfd_set_error (bfd_error_bad_value);
      /* This function is called inside a hashtable traversal and the error
	 handlers called above turn into non-fatal errors.  Which means this
	 case ld returns an exit code 0 and also produces a broken object file.
	 To prevent this, issue a hard abort.  */
      BFD_FAIL ();
    }
  return true;
}


static bool
elf32_aarch64_write_section (bfd *output_bfd  ATTRIBUTE_UNUSED,
			     struct bfd_link_info *link_info,
			     asection *sec,
			     bfd_byte *contents)

{
  struct elf_aarch64_link_hash_table *globals =
    elf_aarch64_hash_table (link_info);

  if (globals == NULL)
    return false;

  /* Fix code to point to erratum 835769 stubs.  */
  if (globals->fix_erratum_835769)
    {
      struct erratum_835769_branch_to_stub_data data;

      data.info = link_info;
      data.output_section = sec;
      data.contents = contents;
      bfd_hash_traverse (&globals->stub_hash_table,
			 make_branch_to_erratum_835769_stub, &data);
    }

  if (globals->fix_erratum_843419)
    {
      struct erratum_835769_branch_to_stub_data data;

      data.info = link_info;
      data.output_section = sec;
      data.contents = contents;
      bfd_hash_traverse (&globals->stub_hash_table,
			 _bfd_aarch64_erratum_843419_branch_to_stub, &data);
    }

  return false;
}

/* Return TRUE if RELOC is a relocation against the base of GOT table.  */

static bool
aarch64_relocation_aginst_gp_p (bfd_reloc_code_real_type reloc)
{
  return (reloc == BFD_RELOC_AARCH64_LD32_GOTPAGE_LO14
	  || reloc == BFD_RELOC_AARCH64_LD64_GOTPAGE_LO15
	  || reloc == BFD_RELOC_AARCH64_LD64_GOTOFF_LO15
	  || reloc == BFD_RELOC_AARCH64_MOVW_GOTOFF_G0_NC
	  || reloc == BFD_RELOC_AARCH64_MOVW_GOTOFF_G1);
}

/* Perform a relocation as part of a final link.  The input relocation type
   should be TLS relaxed.  */

static bfd_reloc_status_type
elf32_aarch64_final_link_relocate (reloc_howto_type *howto,
				   bfd *input_bfd,
				   bfd *output_bfd,
				   asection *input_section,
				   bfd_byte *contents,
				   Elf_Internal_Rela *rel,
				   bfd_vma value,
				   struct bfd_link_info *info,
				   asection *sym_sec,
				   struct elf_link_hash_entry *h,
				   bool *unresolved_reloc_p,
				   bool save_addend,
				   bfd_vma *saved_addend,
				   Elf_Internal_Sym *sym)
{
  Elf_Internal_Shdr *symtab_hdr;
  unsigned int r_type = howto->type;
  bfd_reloc_code_real_type bfd_r_type
    = elf32_aarch64_bfd_reloc_from_howto (howto);
  unsigned long r_symndx;
  bfd_byte *hit_data = contents + rel->r_offset;
  bfd_vma place, off, got_entry_addr = 0;
  bfd_signed_vma signed_addend;
  struct elf_aarch64_link_hash_table *globals;
  bool weak_undef_p;
  bool relative_reloc;
  asection *base_got;
  bfd_vma orig_value = value;
  bool resolved_to_zero;
  bool abs_symbol_p;

  globals = elf_aarch64_hash_table (info);

  symtab_hdr = &elf_symtab_hdr (input_bfd);

  BFD_ASSERT (is_aarch64_elf (input_bfd));

  r_symndx = ELF32_R_SYM (rel->r_info);

  place = input_section->output_section->vma
    + input_section->output_offset + rel->r_offset;

  /* Get addend, accumulating the addend for consecutive relocs
     which refer to the same offset.  */
  signed_addend = saved_addend ? *saved_addend : 0;
  signed_addend += rel->r_addend;

  weak_undef_p = (h ? h->root.type == bfd_link_hash_undefweak
		  : bfd_is_und_section (sym_sec));
  abs_symbol_p = h != NULL && bfd_is_abs_symbol (&h->root);


  /* Since STT_GNU_IFUNC symbol must go through PLT, we handle
     it here if it is defined in a non-shared object.  */
  if (h != NULL
      && h->type == STT_GNU_IFUNC
      && h->def_regular)
    {
      asection *plt;
      const char *name;
      bfd_vma addend = 0;

      if ((input_section->flags & SEC_ALLOC) == 0)
	{
	  /* If this is a SHT_NOTE section without SHF_ALLOC, treat
	     STT_GNU_IFUNC symbol as STT_FUNC.  */
	  if (elf_section_type (input_section) == SHT_NOTE)
	    goto skip_ifunc;

	  /* Dynamic relocs are not propagated for SEC_DEBUGGING
	     sections because such sections are not SEC_ALLOC and
	     thus ld.so will not process them.  */
	  if ((input_section->flags & SEC_DEBUGGING) != 0)
	    return bfd_reloc_ok;

	  if (h->root.root.string)
	    name = h->root.root.string;
	  else
	    name = bfd_elf_sym_name (input_bfd, symtab_hdr, sym, NULL);
	  _bfd_error_handler
	    /* xgettext:c-format */
	    (_("%pB(%pA+%#" PRIx64 "): "
	       "unresolvable %s relocation against symbol `%s'"),
	     input_bfd, input_section, (uint64_t) rel->r_offset,
	     howto->name, name);
	  bfd_set_error (bfd_error_bad_value);
	  return bfd_reloc_notsupported;
	}
      else if (h->plt.offset == (bfd_vma) -1)
	goto bad_ifunc_reloc;

      /* STT_GNU_IFUNC symbol must go through PLT.  */
      plt = globals->root.splt ? globals->root.splt : globals->root.iplt;
      value = (plt->output_section->vma + plt->output_offset + h->plt.offset);

      switch (bfd_r_type)
	{
	default:
	bad_ifunc_reloc:
	  if (h->root.root.string)
	    name = h->root.root.string;
	  else
	    name = bfd_elf_sym_name (input_bfd, symtab_hdr, sym,
				     NULL);
	  _bfd_error_handler
	    /* xgettext:c-format */
	    (_("%pB: relocation %s against STT_GNU_IFUNC "
	       "symbol `%s' isn't handled by %s"), input_bfd,
	     howto->name, name, __func__);
	  bfd_set_error (bfd_error_bad_value);
	  return bfd_reloc_notsupported;

	case BFD_RELOC_AARCH64_32:
	  if (rel->r_addend != 0)
	    {
	      if (h->root.root.string)
		name = h->root.root.string;
	      else
		name = bfd_elf_sym_name (input_bfd, symtab_hdr,
					 sym, NULL);
	      _bfd_error_handler
		/* xgettext:c-format */
		(_("%pB: relocation %s against STT_GNU_IFUNC "
		   "symbol `%s' has non-zero addend: %" PRId64),
		 input_bfd, howto->name, name, (int64_t) rel->r_addend);
	      bfd_set_error (bfd_error_bad_value);
	      return bfd_reloc_notsupported;
	    }

	  /* Generate dynamic relocation only when there is a
	     non-GOT reference in a shared object.  */
	  if (bfd_link_pic (info) && h->non_got_ref)
	    {
	      Elf_Internal_Rela outrel;
	      asection *sreloc;

	      /* Need a dynamic relocation to get the real function
		 address.  */
	      outrel.r_offset = _bfd_elf_section_offset (output_bfd,
							 info,
							 input_section,
							 rel->r_offset);
	      if (outrel.r_offset == (bfd_vma) -1
		  || outrel.r_offset == (bfd_vma) -2)
		abort ();

	      outrel.r_offset += (input_section->output_section->vma
				  + input_section->output_offset);

	      if (h->dynindx == -1
		  || h->forced_local
		  || bfd_link_executable (info))
		{
		  /* This symbol is resolved locally.  */
		  outrel.r_info = ELF32_R_INFO (0, AARCH64_R (IRELATIVE));
		  outrel.r_addend = (h->root.u.def.value
				     + h->root.u.def.section->output_section->vma
				     + h->root.u.def.section->output_offset);
		}
	      else
		{
		  outrel.r_info = ELF32_R_INFO (h->dynindx, r_type);
		  outrel.r_addend = 0;
		}

	      sreloc = globals->root.irelifunc;
	      elf_append_rela (output_bfd, sreloc, &outrel);

	      /* If this reloc is against an external symbol, we
		 do not want to fiddle with the addend.  Otherwise,
		 we need to include the symbol value so that it
		 becomes an addend for the dynamic reloc.  For an
		 internal symbol, we have updated addend.  */
	      return bfd_reloc_ok;
	    }
	  /* FALLTHROUGH */
	case BFD_RELOC_AARCH64_CALL26:
	case BFD_RELOC_AARCH64_JUMP26:
	  value = _bfd_aarch64_elf_resolve_relocation (input_bfd, bfd_r_type,
						       place, value,
						       signed_addend,
						       weak_undef_p);
	  return _bfd_aarch64_elf_put_addend (input_bfd, hit_data, bfd_r_type,
					      howto, value);
	case BFD_RELOC_AARCH64_ADR_GOT_PAGE:
	case BFD_RELOC_AARCH64_GOT_LD_PREL19:
	case BFD_RELOC_AARCH64_LD32_GOTPAGE_LO14:
	case BFD_RELOC_AARCH64_LD32_GOT_LO12_NC:
	case BFD_RELOC_AARCH64_LD64_GOTPAGE_LO15:
	case BFD_RELOC_AARCH64_MOVW_GOTOFF_G0_NC:
	case BFD_RELOC_AARCH64_MOVW_GOTOFF_G1:
	case BFD_RELOC_AARCH64_LD64_GOTOFF_LO15:
	case BFD_RELOC_AARCH64_LD64_GOT_LO12_NC:
	  base_got = globals->root.sgot;
	  off = h->got.offset;

	  if (base_got == NULL)
	    abort ();

	  if (off == (bfd_vma) -1)
	    {
	      bfd_vma plt_index;

	      /* We can't use h->got.offset here to save state, or
		 even just remember the offset, as finish_dynamic_symbol
		 would use that as offset into .got.  */

	      if (globals->root.splt != NULL)
		{
		  plt_index = ((h->plt.offset - globals->plt_header_size) /
			       globals->plt_entry_size);
		  off = (plt_index + 3) * GOT_ENTRY_SIZE;
		  base_got = globals->root.sgotplt;
		}
	      else
		{
		  plt_index = h->plt.offset / globals->plt_entry_size;
		  off = plt_index * GOT_ENTRY_SIZE;
		  base_got = globals->root.igotplt;
		}

	      if (h->dynindx == -1
		  || h->forced_local
		  || info->symbolic)
		{
		  /* This references the local definition.  We must
		     initialize this entry in the global offset table.
		     Since the offset must always be a multiple of 8,
		     we use the least significant bit to record
		     whether we have initialized it already.

		     When doing a dynamic link, we create a .rela.got
		     relocation entry to initialize the value.  This
		     is done in the finish_dynamic_symbol routine.	 */
		  if ((off & 1) != 0)
		    off &= ~1;
		  else
		    {
		      bfd_put_32 (output_bfd, value,
				  base_got->contents + off);
		      /* Note that this is harmless as -1 | 1 still is -1.  */
		      h->got.offset |= 1;
		    }
		}
	      value = (base_got->output_section->vma
		       + base_got->output_offset + off);
	    }
	  else
	    value = aarch64_calculate_got_entry_vma (h, globals, info,
						     value, output_bfd,
						     unresolved_reloc_p);

	  if (aarch64_relocation_aginst_gp_p (bfd_r_type))
	    addend = (globals->root.sgot->output_section->vma
		      + globals->root.sgot->output_offset);

	  value = _bfd_aarch64_elf_resolve_relocation (input_bfd, bfd_r_type,
						       place, value,
						       addend, weak_undef_p);
	  return _bfd_aarch64_elf_put_addend (input_bfd, hit_data, bfd_r_type, howto, value);
	case BFD_RELOC_AARCH64_ADD_LO12:
	case BFD_RELOC_AARCH64_ADR_HI21_PCREL:
	  break;
	}
    }

 skip_ifunc:
  resolved_to_zero = (h != NULL
		      && UNDEFWEAK_NO_DYNAMIC_RELOC (info, h));

  switch (bfd_r_type)
    {
    case BFD_RELOC_AARCH64_NONE:
    case BFD_RELOC_AARCH64_TLSDESC_ADD:
    case BFD_RELOC_AARCH64_TLSDESC_CALL:
    case BFD_RELOC_AARCH64_TLSDESC_LDR:
      *unresolved_reloc_p = false;
      return bfd_reloc_ok;

    case BFD_RELOC_AARCH64_32:

      /* When generating a shared library or PIE, these relocations
	 are copied into the output file to be resolved at run time.  */
      if ((bfd_link_pic (info)
	   && (input_section->flags & SEC_ALLOC)
	   && (h == NULL
	       || (ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
		   && !resolved_to_zero)
	       || h->root.type != bfd_link_hash_undefweak))
	  /* Or we are creating an executable, we may need to keep relocations
	     for symbols satisfied by a dynamic library if we manage to avoid
	     copy relocs for the symbol.  */
	  || (ELIMINATE_COPY_RELOCS
	      && !bfd_link_pic (info)
	      && h != NULL
	      && (input_section->flags & SEC_ALLOC)
	      && h->dynindx != -1
	      && !h->non_got_ref
	      && ((h->def_dynamic
		   && !h->def_regular)
		  || h->root.type == bfd_link_hash_undefweak
		  || h->root.type == bfd_link_hash_undefined)))
	{
	  Elf_Internal_Rela outrel;
	  bfd_byte *loc;
	  bool skip, relocate;
	  asection *sreloc;

	  *unresolved_reloc_p = false;

	  skip = false;
	  relocate = false;

	  outrel.r_addend = signed_addend;
	  outrel.r_offset =
	    _bfd_elf_section_offset (output_bfd, info, input_section,
				     rel->r_offset);
	  if (outrel.r_offset == (bfd_vma) - 1)
	    skip = true;
	  else if (outrel.r_offset == (bfd_vma) - 2)
	    {
	      skip = true;
	      relocate = true;
	    }
	  else if (abs_symbol_p)
	    {
	      /* Local absolute symbol.  */
	      skip = (h->forced_local || (h->dynindx == -1));
	      relocate = skip;
	    }

	  outrel.r_offset += (input_section->output_section->vma
			      + input_section->output_offset);

	  if (skip)
	    memset (&outrel, 0, sizeof outrel);
	  else if (h != NULL
		   && h->dynindx != -1
		   && (!bfd_link_pic (info)
		       || !(bfd_link_pie (info) || SYMBOLIC_BIND (info, h))
		       || !h->def_regular))
	    outrel.r_info = ELF32_R_INFO (h->dynindx, r_type);
	  else if (info->enable_dt_relr
		   && input_section->alignment_power != 0
		   && rel->r_offset % 2 == 0)
	    {
	      /* Don't emit a relative relocation that is packed, only
		 apply the addend.  */
	      return _bfd_final_link_relocate (howto, input_bfd, input_section,
					       contents, rel->r_offset, value,
					       signed_addend);
	    }
	  else
	    {
	      int symbol;

	      /* On SVR4-ish systems, the dynamic loader cannot
		 relocate the text and data segments independently,
		 so the symbol does not matter.  */
	      symbol = 0;
	      relocate = !globals->no_apply_dynamic_relocs;
	      outrel.r_info = ELF32_R_INFO (symbol, AARCH64_R (RELATIVE));
	      outrel.r_addend += value;
	    }

	  sreloc = elf_section_data (input_section)->sreloc;
	  if (sreloc == NULL || sreloc->contents == NULL)
	    return bfd_reloc_notsupported;

	  loc = sreloc->contents + sreloc->reloc_count++ * RELOC_SIZE (globals);
	  bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);

	  if (sreloc->reloc_count * RELOC_SIZE (globals) > sreloc->size)
	    {
	      /* Sanity to check that we have previously allocated
		 sufficient space in the relocation section for the
		 number of relocations we actually want to emit.  */
	      abort ();
	    }

	  /* If this reloc is against an external symbol, we do not want to
	     fiddle with the addend.  Otherwise, we need to include the symbol
	     value so that it becomes an addend for the dynamic reloc.  */
	  if (!relocate)
	    return bfd_reloc_ok;

	  return _bfd_final_link_relocate (howto, input_bfd, input_section,
					   contents, rel->r_offset, value,
					   signed_addend);
	}
      else
	value += signed_addend;
      break;

    case BFD_RELOC_AARCH64_CALL26:
    case BFD_RELOC_AARCH64_JUMP26:
      {
	asection *splt = globals->root.splt;
	bool via_plt_p =
	  splt != NULL && h != NULL && h->plt.offset != (bfd_vma) - 1;

	/* A call to an undefined weak symbol is converted to a jump to
	   the next instruction unless a PLT entry will be created.
	   The jump to the next instruction is optimized as a NOP.
	   Do the same for local undefined symbols.  */
	if (weak_undef_p && ! via_plt_p)
	  {
	    bfd_putl32 (INSN_NOP, hit_data);
	    return bfd_reloc_ok;
	  }

	/* If the call goes through a PLT entry, make sure to
	   check distance to the right destination address.  */
	if (via_plt_p)
	  value = (splt->output_section->vma
		   + splt->output_offset + h->plt.offset);

	/* Check if a stub has to be inserted because the destination
	   is too far away.  */
	struct elf_aarch64_stub_hash_entry *stub_entry = NULL;

	/* If the branch destination is directed to plt stub, "value" will be
	   the final destination, otherwise we should plus signed_addend, it may
	   contain non-zero value, for example call to local function symbol
	   which are turned into "sec_sym + sec_off", and sec_off is kept in
	   signed_addend.  */
	if (! aarch64_valid_branch_p (via_plt_p ? value : value + signed_addend,
				      place))
	  /* The target is out of reach, so redirect the branch to
	     the local stub for this function.  */
	stub_entry = elf32_aarch64_get_stub_entry (input_section, sym_sec, h,
						   rel, globals);
	if (stub_entry != NULL)
	  {
	    value = (stub_entry->stub_offset
		     + stub_entry->stub_sec->output_offset
		     + stub_entry->stub_sec->output_section->vma);

	    /* We have redirected the destination to stub entry address,
	       so ignore any addend record in the original rela entry.  */
	    signed_addend = 0;
	  }
      }
      value = _bfd_aarch64_elf_resolve_relocation (input_bfd, bfd_r_type,
						   place, value,
						   signed_addend, weak_undef_p);
      *unresolved_reloc_p = false;
      break;

    case BFD_RELOC_AARCH64_16_PCREL:
    case BFD_RELOC_AARCH64_32_PCREL:
    case BFD_RELOC_AARCH64_64_PCREL:
    case BFD_RELOC_AARCH64_ADR_HI21_NC_PCREL:
    case BFD_RELOC_AARCH64_ADR_HI21_PCREL:
    case BFD_RELOC_AARCH64_ADR_LO21_PCREL:
    case BFD_RELOC_AARCH64_LD_LO19_PCREL:
    case BFD_RELOC_AARCH64_MOVW_PREL_G0:
    case BFD_RELOC_AARCH64_MOVW_PREL_G0_NC:
    case BFD_RELOC_AARCH64_MOVW_PREL_G1:
    case BFD_RELOC_AARCH64_MOVW_PREL_G1_NC:
    case BFD_RELOC_AARCH64_MOVW_PREL_G2:
    case BFD_RELOC_AARCH64_MOVW_PREL_G2_NC:
    case BFD_RELOC_AARCH64_MOVW_PREL_G3:
      if (bfd_link_pic (info)
	  && (input_section->flags & SEC_ALLOC) != 0
	  && (input_section->flags & SEC_READONLY) != 0
	  && !_bfd_elf_symbol_refs_local_p (h, info, 1))
	{
	  int howto_index = bfd_r_type - BFD_RELOC_AARCH64_RELOC_START;

	  _bfd_error_handler
	    /* xgettext:c-format */
	    (_("%pB: relocation %s against symbol `%s' which may bind "
	       "externally can not be used when making a shared object; "
	       "recompile with -fPIC"),
	     input_bfd, elf32_aarch64_howto_table[howto_index].name,
	     h->root.root.string);
	  bfd_set_error (bfd_error_bad_value);
	  return bfd_reloc_notsupported;
	}
      value = _bfd_aarch64_elf_resolve_relocation (input_bfd, bfd_r_type,
						   place, value,
						   signed_addend,
						   weak_undef_p);
      break;

    case BFD_RELOC_AARCH64_BRANCH19:
    case BFD_RELOC_AARCH64_TSTBR14:
      if (h && h->root.type == bfd_link_hash_undefined)
	{
	  _bfd_error_handler
	    /* xgettext:c-format */
	    (_("%pB: conditional branch to undefined symbol `%s' "
	       "not allowed"), input_bfd, h->root.root.string);
	  bfd_set_error (bfd_error_bad_value);
	  return bfd_reloc_notsupported;
	}
      /* Fall through.  */

    case BFD_RELOC_AARCH64_16:
#if ARCH_SIZE == 64
    case BFD_RELOC_AARCH64_32:
#endif
    case BFD_RELOC_AARCH64_ADD_LO12:
    case BFD_RELOC_AARCH64_LDST128_LO12:
    case BFD_RELOC_AARCH64_LDST16_LO12:
    case BFD_RELOC_AARCH64_LDST32_LO12:
    case BFD_RELOC_AARCH64_LDST64_LO12:
    case BFD_RELOC_AARCH64_LDST8_LO12:
    case BFD_RELOC_AARCH64_MOVW_G0:
    case BFD_RELOC_AARCH64_MOVW_G0_NC:
    case BFD_RELOC_AARCH64_MOVW_G0_S:
    case BFD_RELOC_AARCH64_MOVW_G1:
    case BFD_RELOC_AARCH64_MOVW_G1_NC:
    case BFD_RELOC_AARCH64_MOVW_G1_S:
    case BFD_RELOC_AARCH64_MOVW_G2:
    case BFD_RELOC_AARCH64_MOVW_G2_NC:
    case BFD_RELOC_AARCH64_MOVW_G2_S:
    case BFD_RELOC_AARCH64_MOVW_G3:
      value = _bfd_aarch64_elf_resolve_relocation (input_bfd, bfd_r_type,
						   place, value,
						   signed_addend, weak_undef_p);
      break;

    case BFD_RELOC_AARCH64_ADR_GOT_PAGE:
    case BFD_RELOC_AARCH64_GOT_LD_PREL19:
    case BFD_RELOC_AARCH64_LD32_GOTPAGE_LO14:
    case BFD_RELOC_AARCH64_LD32_GOT_LO12_NC:
    case BFD_RELOC_AARCH64_LD64_GOTPAGE_LO15:
    case BFD_RELOC_AARCH64_LD64_GOT_LO12_NC:
    case BFD_RELOC_AARCH64_LD64_GOTOFF_LO15:
    case BFD_RELOC_AARCH64_MOVW_GOTOFF_G0_NC:
    case BFD_RELOC_AARCH64_MOVW_GOTOFF_G1:
      if (globals->root.sgot == NULL)
	BFD_ASSERT (h != NULL);

      relative_reloc = false;
      if (h != NULL)
	{
	  bfd_vma addend = 0;

	  /* If a symbol is not dynamic and is not undefined weak, bind it
	     locally and generate a RELATIVE relocation under PIC mode.

	     NOTE: one symbol may be referenced by several relocations, we
	     should only generate one RELATIVE relocation for that symbol.
	     Therefore, check GOT offset mark first.  */
	  if (h->dynindx == -1
	      && !h->forced_local
	      && h->root.type != bfd_link_hash_undefweak
	      && bfd_link_pic (info)
	      && !symbol_got_offset_mark_p (input_bfd, h, r_symndx))
	    relative_reloc = true;

	  value = aarch64_calculate_got_entry_vma (h, globals, info, value,
						   output_bfd,
						   unresolved_reloc_p);
	  /* Record the GOT entry address which will be used when generating
	     RELATIVE relocation.  */
	  if (relative_reloc)
	    got_entry_addr = value;

	  if (aarch64_relocation_aginst_gp_p (bfd_r_type))
	    addend = (globals->root.sgot->output_section->vma
		      + globals->root.sgot->output_offset);
	  value = _bfd_aarch64_elf_resolve_relocation (input_bfd, bfd_r_type,
						       place, value,
						       addend, weak_undef_p);
	}
      else
      {
	bfd_vma addend = 0;
	struct elf_aarch64_local_symbol *locals
	  = elf_aarch64_locals (input_bfd);

	if (locals == NULL)
	  {
	    int howto_index = bfd_r_type - BFD_RELOC_AARCH64_RELOC_START;
	    _bfd_error_handler
	      /* xgettext:c-format */
	      (_("%pB: local symbol descriptor table be NULL when applying "
		 "relocation %s against local symbol"),
	       input_bfd, elf32_aarch64_howto_table[howto_index].name);
	    abort ();
	  }

	off = symbol_got_offset (input_bfd, h, r_symndx);
	base_got = globals->root.sgot;
	got_entry_addr = (base_got->output_section->vma
			  + base_got->output_offset + off);

	if (!symbol_got_offset_mark_p (input_bfd, h, r_symndx))
	  {
	    bfd_put_64 (output_bfd, value, base_got->contents + off);

	    /* For local symbol, we have done absolute relocation in static
	       linking stage.  While for shared library, we need to update the
	       content of GOT entry according to the shared object's runtime
	       base address.  So, we need to generate a R_AARCH64_RELATIVE reloc
	       for dynamic linker.  */
	    if (bfd_link_pic (info))
	      relative_reloc = true;

	    symbol_got_offset_mark (input_bfd, h, r_symndx);
	  }

	/* Update the relocation value to GOT entry addr as we have transformed
	   the direct data access into indirect data access through GOT.  */
	value = got_entry_addr;

	if (aarch64_relocation_aginst_gp_p (bfd_r_type))
	  addend = base_got->output_section->vma + base_got->output_offset;

	value = _bfd_aarch64_elf_resolve_relocation (input_bfd, bfd_r_type,
						     place, value,
						     addend, weak_undef_p);
      }

      /* Emit relative relocations, but not if they are packed (DT_RELR).  */
      if (relative_reloc && !info->enable_dt_relr)
	{
	  asection *s;
	  Elf_Internal_Rela outrel;

	  s = globals->root.srelgot;
	  if (s == NULL)
	    abort ();

	  outrel.r_offset = got_entry_addr;
	  outrel.r_info = ELF32_R_INFO (0, AARCH64_R (RELATIVE));
	  outrel.r_addend = orig_value;
	  elf_append_rela (output_bfd, s, &outrel);
	}
      break;

    case BFD_RELOC_AARCH64_TLSGD_ADD_LO12_NC:
    case BFD_RELOC_AARCH64_TLSGD_ADR_PAGE21:
    case BFD_RELOC_AARCH64_TLSGD_ADR_PREL21:
    case BFD_RELOC_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21:
    case BFD_RELOC_AARCH64_TLSIE_LD32_GOTTPREL_LO12_NC:
    case BFD_RELOC_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC:
    case BFD_RELOC_AARCH64_TLSIE_LD_GOTTPREL_PREL19:
    case BFD_RELOC_AARCH64_TLSLD_ADD_LO12_NC:
    case BFD_RELOC_AARCH64_TLSLD_ADR_PAGE21:
    case BFD_RELOC_AARCH64_TLSLD_ADR_PREL21:
      if (globals->root.sgot == NULL)
	return bfd_reloc_notsupported;

      value = (symbol_got_offset (input_bfd, h, r_symndx)
	       + globals->root.sgot->output_section->vma
	       + globals->root.sgot->output_offset);

      value = _bfd_aarch64_elf_resolve_relocation (input_bfd, bfd_r_type,
						   place, value,
						   0, weak_undef_p);
      *unresolved_reloc_p = false;
      break;

    case BFD_RELOC_AARCH64_TLSGD_MOVW_G0_NC:
    case BFD_RELOC_AARCH64_TLSGD_MOVW_G1:
    case BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC:
    case BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G1:
      if (globals->root.sgot == NULL)
	return bfd_reloc_notsupported;

      value = symbol_got_offset (input_bfd, h, r_symndx);
      value = _bfd_aarch64_elf_resolve_relocation (input_bfd, bfd_r_type,
						   place, value,
						   0, weak_undef_p);
      *unresolved_reloc_p = false;
      break;

    case BFD_RELOC_AARCH64_TLSLD_ADD_DTPREL_HI12:
    case BFD_RELOC_AARCH64_TLSLD_ADD_DTPREL_LO12:
    case BFD_RELOC_AARCH64_TLSLD_ADD_DTPREL_LO12_NC:
    case BFD_RELOC_AARCH64_TLSLD_LDST16_DTPREL_LO12:
    case BFD_RELOC_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC:
    case BFD_RELOC_AARCH64_TLSLD_LDST32_DTPREL_LO12:
    case BFD_RELOC_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC:
    case BFD_RELOC_AARCH64_TLSLD_LDST64_DTPREL_LO12:
    case BFD_RELOC_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC:
    case BFD_RELOC_AARCH64_TLSLD_LDST8_DTPREL_LO12:
    case BFD_RELOC_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC:
    case BFD_RELOC_AARCH64_TLSLD_MOVW_DTPREL_G0:
    case BFD_RELOC_AARCH64_TLSLD_MOVW_DTPREL_G0_NC:
    case BFD_RELOC_AARCH64_TLSLD_MOVW_DTPREL_G1:
    case BFD_RELOC_AARCH64_TLSLD_MOVW_DTPREL_G1_NC:
    case BFD_RELOC_AARCH64_TLSLD_MOVW_DTPREL_G2:
      {
	if (!(weak_undef_p || elf_hash_table (info)->tls_sec))
	  {
	    int howto_index = bfd_r_type - BFD_RELOC_AARCH64_RELOC_START;
	    _bfd_error_handler
	      /* xgettext:c-format */
	      (_("%pB: TLS relocation %s against undefined symbol `%s'"),
		 input_bfd, elf32_aarch64_howto_table[howto_index].name,
		 h->root.root.string);
	    bfd_set_error (bfd_error_bad_value);
	    return bfd_reloc_notsupported;
	  }

	bfd_vma def_value
	  = weak_undef_p ? 0 : signed_addend - dtpoff_base (info);
	value = _bfd_aarch64_elf_resolve_relocation (input_bfd, bfd_r_type,
						     place, value,
						     def_value, weak_undef_p);
	break;
      }

    case BFD_RELOC_AARCH64_TLSLE_ADD_TPREL_HI12:
    case BFD_RELOC_AARCH64_TLSLE_ADD_TPREL_LO12:
    case BFD_RELOC_AARCH64_TLSLE_ADD_TPREL_LO12_NC:
    case BFD_RELOC_AARCH64_TLSLE_LDST16_TPREL_LO12:
    case BFD_RELOC_AARCH64_TLSLE_LDST16_TPREL_LO12_NC:
    case BFD_RELOC_AARCH64_TLSLE_LDST32_TPREL_LO12:
    case BFD_RELOC_AARCH64_TLSLE_LDST32_TPREL_LO12_NC:
    case BFD_RELOC_AARCH64_TLSLE_LDST64_TPREL_LO12:
    case BFD_RELOC_AARCH64_TLSLE_LDST64_TPREL_LO12_NC:
    case BFD_RELOC_AARCH64_TLSLE_LDST8_TPREL_LO12:
    case BFD_RELOC_AARCH64_TLSLE_LDST8_TPREL_LO12_NC:
    case BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G0:
    case BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G0_NC:
    case BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G1:
    case BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G1_NC:
    case BFD_RELOC_AARCH64_TLSLE_MOVW_TPREL_G2:
      {
	if (!(weak_undef_p || elf_hash_table (info)->tls_sec))
	  {
	    int howto_index = bfd_r_type - BFD_RELOC_AARCH64_RELOC_START;
	    _bfd_error_handler
	      /* xgettext:c-format */
	      (_("%pB: TLS relocation %s against undefined symbol `%s'"),
		 input_bfd, elf32_aarch64_howto_table[howto_index].name,
		 h->root.root.string);
	    bfd_set_error (bfd_error_bad_value);
	    return bfd_reloc_notsupported;
	  }

	bfd_vma def_value
	  = weak_undef_p ? 0 : signed_addend - tpoff_base (info);
	value = _bfd_aarch64_elf_resolve_relocation (input_bfd, bfd_r_type,
						     place, value,
						     def_value, weak_undef_p);
        *unresolved_reloc_p = false;
	break;
      }

    case BFD_RELOC_AARCH64_TLSDESC_ADD_LO12:
    case BFD_RELOC_AARCH64_TLSDESC_ADR_PAGE21:
    case BFD_RELOC_AARCH64_TLSDESC_ADR_PREL21:
    case BFD_RELOC_AARCH64_TLSDESC_LD32_LO12_NC:
    case BFD_RELOC_AARCH64_TLSDESC_LD64_LO12:
    case BFD_RELOC_AARCH64_TLSDESC_LD_PREL19:
      if (globals->root.sgot == NULL)
	return bfd_reloc_notsupported;
      value = (symbol_tlsdesc_got_offset (input_bfd, h, r_symndx)
	       + globals->root.sgotplt->output_section->vma
	       + globals->root.sgotplt->output_offset
	       + globals->sgotplt_jump_table_size);

      value = _bfd_aarch64_elf_resolve_relocation (input_bfd, bfd_r_type,
						   place, value,
						   0, weak_undef_p);
      *unresolved_reloc_p = false;
      break;

    case BFD_RELOC_AARCH64_TLSDESC_OFF_G0_NC:
    case BFD_RELOC_AARCH64_TLSDESC_OFF_G1:
      if (globals->root.sgot == NULL)
	return bfd_reloc_notsupported;

      value = (symbol_tlsdesc_got_offset (input_bfd, h, r_symndx)
	       + globals->root.sgotplt->output_section->vma
	       + globals->root.sgotplt->output_offset
	       + globals->sgotplt_jump_table_size);

      value -= (globals->root.sgot->output_section->vma
		+ globals->root.sgot->output_offset);

      value = _bfd_aarch64_elf_resolve_relocation (input_bfd, bfd_r_type,
						   place, value,
						   0, weak_undef_p);
      *unresolved_reloc_p = false;
      break;

    default:
      return bfd_reloc_notsupported;
    }

  if (saved_addend)
    *saved_addend = value;

  /* Only apply the final relocation in a sequence.  */
  if (save_addend)
    return bfd_reloc_continue;

  return _bfd_aarch64_elf_put_addend (input_bfd, hit_data, bfd_r_type,
				      howto, value);
}

/* LP64 and ILP32 operates on x- and w-registers respectively.
   Next definitions take into account the difference between
   corresponding machine codes. R means x-register if the target
   arch is LP64, and w-register if the target is ILP32.  */

#if ARCH_SIZE == 64
# define add_R0_R0	(0x91000000)
# define add_R0_R0_R1	(0x8b000020)
# define add_R0_R1	(0x91400020)
# define ldr_R0		(0x58000000)
# define ldr_R0_mask(i)	(i & 0xffffffe0)
# define ldr_R0_x0	(0xf9400000)
# define ldr_hw_R0	(0xf2a00000)
# define movk_R0	(0xf2800000)
# define movz_R0	(0xd2a00000)
# define movz_hw_R0	(0xd2c00000)
#else /*ARCH_SIZE == 32 */
# define add_R0_R0	(0x11000000)
# define add_R0_R0_R1	(0x0b000020)
# define add_R0_R1	(0x11400020)
# define ldr_R0		(0x18000000)
# define ldr_R0_mask(i)	(i & 0xbfffffe0)
# define ldr_R0_x0	(0xb9400000)
# define ldr_hw_R0	(0x72a00000)
# define movk_R0	(0x72800000)
# define movz_R0	(0x52a00000)
# define movz_hw_R0	(0x52c00000)
#endif

/* Structure to hold payload for _bfd_aarch64_erratum_843419_clear_stub,
   it is used to identify the stub information to reset.  */

struct erratum_843419_branch_to_stub_clear_data
{
  bfd_vma adrp_offset;
  asection *output_section;
};

/* Clear the erratum information for GEN_ENTRY if the ADRP_OFFSET and
   section inside IN_ARG matches.  The clearing is done by setting the
   stub_type to none.  */

static bool
_bfd_aarch64_erratum_843419_clear_stub (struct bfd_hash_entry *gen_entry,
					void *in_arg)
{
  struct elf_aarch64_stub_hash_entry *stub_entry
    = (struct elf_aarch64_stub_hash_entry *) gen_entry;
  struct erratum_843419_branch_to_stub_clear_data *data
    = (struct erratum_843419_branch_to_stub_clear_data *) in_arg;

  if (stub_entry->target_section != data->output_section
      || stub_entry->stub_type != aarch64_stub_erratum_843419_veneer
      || stub_entry->adrp_offset != data->adrp_offset)
    return true;

  /* Change the stub type instead of removing the entry, removing from the hash
     table would be slower and we have already reserved the memory for the entry
     so there wouldn't be much gain.  Changing the stub also keeps around a
     record of what was there before.  */
  stub_entry->stub_type = aarch64_stub_none;

  /* We're done and there could have been only one matching stub at that
     particular offset, so abort further traversal.  */
  return false;
}

/* TLS Relaxations may relax an adrp sequence that matches the erratum 843419
   sequence.  In this case the erratum no longer applies and we need to remove
   the entry from the pending stub generation.  This clears matching adrp insn
   at ADRP_OFFSET in INPUT_SECTION in the stub table defined in GLOBALS.  */

static void
clear_erratum_843419_entry (struct elf_aarch64_link_hash_table *globals,
			    bfd_vma adrp_offset, asection *input_section)
{
  if (globals->fix_erratum_843419 & ERRAT_ADRP)
    {
      struct erratum_843419_branch_to_stub_clear_data data;
      data.adrp_offset = adrp_offset;
      data.output_section = input_section;

      bfd_hash_traverse (&globals->stub_hash_table,
			 _bfd_aarch64_erratum_843419_clear_stub, &data);
    }
}

/* Handle TLS relaxations.  Relaxing is possible for symbols that use
   R_AARCH64_TLSDESC_ADR_{PAGE, LD64_LO12_NC, ADD_LO12_NC} during a static
   link.

   Return bfd_reloc_ok if we're done, bfd_reloc_continue if the caller
   is to then call final_link_relocate.  Return other values in the
   case of error.  */

static bfd_reloc_status_type
elf32_aarch64_tls_relax (struct elf_aarch64_link_hash_table *globals,
			 bfd *input_bfd, asection *input_section,
			 bfd_byte *contents, Elf_Internal_Rela *rel,
			 struct elf_link_hash_entry *h,
			 struct bfd_link_info *info)
{
  bool local_exec = bfd_link_executable (info)
    && SYMBOL_REFERENCES_LOCAL (info, h);
  unsigned int r_type = ELF32_R_TYPE (rel->r_info);
  unsigned long insn;

  BFD_ASSERT (globals && input_bfd && contents && rel);

  switch (elf32_aarch64_bfd_reloc_from_type (input_bfd, r_type))
    {
    case BFD_RELOC_AARCH64_TLSDESC_ADR_PAGE21:
    case BFD_RELOC_AARCH64_TLSGD_ADR_PAGE21:
      if (local_exec)
	{
	  /* GD->LE relaxation:
	     adrp x0, :tlsgd:var     =>   movz R0, :tprel_g1:var
	     or
	     adrp x0, :tlsdesc:var   =>   movz R0, :tprel_g1:var

	     Where R is x for LP64, and w for ILP32.  */
	  bfd_putl32 (movz_R0, contents + rel->r_offset);
	  /* We have relaxed the adrp into a mov, we may have to clear any
	     pending erratum fixes.  */
	  clear_erratum_843419_entry (globals, rel->r_offset, input_section);
	  return bfd_reloc_continue;
	}
      else
	{
	  /* GD->IE relaxation:
	     adrp x0, :tlsgd:var     =>   adrp x0, :gottprel:var
	     or
	     adrp x0, :tlsdesc:var   =>   adrp x0, :gottprel:var
	   */
	  return bfd_reloc_continue;
	}

    case BFD_RELOC_AARCH64_TLSDESC_ADR_PREL21:
      BFD_ASSERT (0);
      break;

    case BFD_RELOC_AARCH64_TLSDESC_LD_PREL19:
      if (local_exec)
	{
	  /* Tiny TLSDESC->LE relaxation:
	     ldr   x1, :tlsdesc:var	 =>  movz  R0, #:tprel_g1:var
	     adr   x0, :tlsdesc:var	 =>  movk  R0, #:tprel_g0_nc:var
	     .tlsdesccall var
	     blr   x1			 =>  nop

	     Where R is x for LP64, and w for ILP32.  */
	  BFD_ASSERT (ELF32_R_TYPE (rel[1].r_info) == AARCH64_R (TLSDESC_ADR_PREL21));
	  BFD_ASSERT (ELF32_R_TYPE (rel[2].r_info) == AARCH64_R (TLSDESC_CALL));

	  rel[1].r_info = ELF32_R_INFO (ELF32_R_SYM (rel->r_info),
					AARCH64_R (TLSLE_MOVW_TPREL_G0_NC));
	  rel[2].r_info = ELF32_R_INFO (STN_UNDEF, R_AARCH64_NONE);

	  bfd_putl32 (movz_R0, contents + rel->r_offset);
	  bfd_putl32 (movk_R0, contents + rel->r_offset + 4);
	  bfd_putl32 (INSN_NOP, contents + rel->r_offset + 8);
	  return bfd_reloc_continue;
	}
      else
	{
	  /* Tiny TLSDESC->IE relaxation:
	     ldr   x1, :tlsdesc:var	 =>  ldr   x0, :gottprel:var
	     adr   x0, :tlsdesc:var	 =>  nop
	     .tlsdesccall var
	     blr   x1			 =>  nop
	   */
	  BFD_ASSERT (ELF32_R_TYPE (rel[1].r_info) == AARCH64_R (TLSDESC_ADR_PREL21));
	  BFD_ASSERT (ELF32_R_TYPE (rel[2].r_info) == AARCH64_R (TLSDESC_CALL));

	  rel[1].r_info = ELF32_R_INFO (STN_UNDEF, R_AARCH64_NONE);
	  rel[2].r_info = ELF32_R_INFO (STN_UNDEF, R_AARCH64_NONE);

	  bfd_putl32 (ldr_R0, contents + rel->r_offset);
	  bfd_putl32 (INSN_NOP, contents + rel->r_offset + 4);
	  bfd_putl32 (INSN_NOP, contents + rel->r_offset + 8);
	  return bfd_reloc_continue;
	}

    case BFD_RELOC_AARCH64_TLSGD_ADR_PREL21:
      if (local_exec)
	{
	  /* Tiny GD->LE relaxation:
	     adr x0, :tlsgd:var	     =>	  mrs  x1, tpidr_el0
	     bl	  __tls_get_addr     =>	  add  R0, R1, #:tprel_hi12:x, lsl #12
	     nop		     =>	  add  R0, R0, #:tprel_lo12_nc:x

	     Where R is x for LP64, and x for Ilp32.  */

	  /* First kill the tls_get_addr reloc on the bl instruction.  */
	  BFD_ASSERT (rel->r_offset + 4 == rel[1].r_offset);

	  bfd_putl32 (0xd53bd041, contents + rel->r_offset + 0);
	  bfd_putl32 (add_R0_R1, contents + rel->r_offset + 4);
	  bfd_putl32 (add_R0_R0, contents + rel->r_offset + 8);

	  rel[1].r_info = ELF32_R_INFO (ELF32_R_SYM (rel->r_info),
					AARCH64_R (TLSLE_ADD_TPREL_LO12_NC));
	  rel[1].r_offset = rel->r_offset + 8;

	  /* Move the current relocation to the second instruction in
	     the sequence.  */
	  rel->r_offset += 4;
	  rel->r_info = ELF32_R_INFO (ELF32_R_SYM (rel->r_info),
				      AARCH64_R (TLSLE_ADD_TPREL_HI12));
	  return bfd_reloc_continue;
	}
      else
	{
	  /* Tiny GD->IE relaxation:
	     adr x0, :tlsgd:var	     =>	  ldr  R0, :gottprel:var
	     bl	  __tls_get_addr     =>	  mrs  x1, tpidr_el0
	     nop		     =>	  add  R0, R0, R1

	     Where R is x for LP64, and w for Ilp32.  */

	  /* First kill the tls_get_addr reloc on the bl instruction.  */
	  BFD_ASSERT (rel->r_offset + 4 == rel[1].r_offset);
	  rel[1].r_info = ELF32_R_INFO (STN_UNDEF, R_AARCH64_NONE);

	  bfd_putl32 (ldr_R0, contents + rel->r_offset);
	  bfd_putl32 (0xd53bd041, contents + rel->r_offset + 4);
	  bfd_putl32 (add_R0_R0_R1, contents + rel->r_offset + 8);
	  return bfd_reloc_continue;
	}

#if ARCH_SIZE == 64
    case BFD_RELOC_AARCH64_TLSGD_MOVW_G1:
      BFD_ASSERT (ELF32_R_TYPE (rel[1].r_info) == AARCH64_R (TLSGD_MOVW_G0_NC));
      BFD_ASSERT (rel->r_offset + 12 == rel[2].r_offset);
      BFD_ASSERT (ELF32_R_TYPE (rel[2].r_info) == AARCH64_R (CALL26));

      if (local_exec)
	{
	  /* Large GD->LE relaxation:
	     movz x0, #:tlsgd_g1:var	=> movz x0, #:tprel_g2:var, lsl #32
	     movk x0, #:tlsgd_g0_nc:var => movk x0, #:tprel_g1_nc:var, lsl #16
	     add x0, gp, x0		=> movk x0, #:tprel_g0_nc:var
	     bl __tls_get_addr		=> mrs x1, tpidr_el0
	     nop			=> add x0, x0, x1
	   */
	  rel[2].r_info = ELF32_R_INFO (ELF32_R_SYM (rel->r_info),
					AARCH64_R (TLSLE_MOVW_TPREL_G0_NC));
	  rel[2].r_offset = rel->r_offset + 8;

	  bfd_putl32 (movz_hw_R0, contents + rel->r_offset + 0);
	  bfd_putl32 (ldr_hw_R0, contents + rel->r_offset + 4);
	  bfd_putl32 (movk_R0, contents + rel->r_offset + 8);
	  bfd_putl32 (0xd53bd041, contents + rel->r_offset + 12);
	  bfd_putl32 (add_R0_R0_R1, contents + rel->r_offset + 16);
	}
      else
	{
	  /* Large GD->IE relaxation:
	     movz x0, #:tlsgd_g1:var	=> movz x0, #:gottprel_g1:var, lsl #16
	     movk x0, #:tlsgd_g0_nc:var => movk x0, #:gottprel_g0_nc:var
	     add x0, gp, x0		=> ldr x0, [gp, x0]
	     bl __tls_get_addr		=> mrs x1, tpidr_el0
	     nop			=> add x0, x0, x1
	   */
	  rel[2].r_info = ELF32_R_INFO (STN_UNDEF, R_AARCH64_NONE);
	  bfd_putl32 (0xd2a80000, contents + rel->r_offset + 0);
	  bfd_putl32 (ldr_R0, contents + rel->r_offset + 8);
	  bfd_putl32 (0xd53bd041, contents + rel->r_offset + 12);
	  bfd_putl32 (add_R0_R0_R1, contents + rel->r_offset + 16);
	}
      return bfd_reloc_continue;

    case BFD_RELOC_AARCH64_TLSGD_MOVW_G0_NC:
      return bfd_reloc_continue;
#endif

    case BFD_RELOC_AARCH64_TLSIE_LD_GOTTPREL_PREL19:
      return bfd_reloc_continue;

    case BFD_RELOC_AARCH64_TLSDESC_LD32_LO12_NC:
      if (local_exec)
	{
	  /* GD->LE relaxation:
	     ldr xd, [x0, #:tlsdesc_lo12:var]   =>   movk x0, :tprel_g0_nc:var

	     Where R is x for lp64 mode, and w for ILP32 mode.  */
	  bfd_putl32 (movk_R0, contents + rel->r_offset);
	  return bfd_reloc_continue;
	}
      else
	{
	  /* GD->IE relaxation:
	     ldr xd, [x0, #:tlsdesc_lo12:var] => ldr R0, [x0, #:gottprel_lo12:var]

	     Where R is x for lp64 mode, and w for ILP32 mode.  */
	  insn = bfd_getl32 (contents + rel->r_offset);
	  bfd_putl32 (ldr_R0_mask (insn), contents + rel->r_offset);
	  return bfd_reloc_continue;
	}

    case BFD_RELOC_AARCH64_TLSGD_ADD_LO12_NC:
      if (local_exec)
	{
	  /* GD->LE relaxation
	     add  x0, #:tlsgd_lo12:var	=> movk R0, :tprel_g0_nc:var
	     bl	  __tls_get_addr	=> mrs	x1, tpidr_el0
	     nop			=> add	R0, R1, R0

	     Where R is x for lp64 mode, and w for ILP32 mode.  */

	  /* First kill the tls_get_addr reloc on the bl instruction.  */
	  BFD_ASSERT (rel->r_offset + 4 == rel[1].r_offset);
	  rel[1].r_info = ELF32_R_INFO (STN_UNDEF, R_AARCH64_NONE);

	  bfd_putl32 (movk_R0, contents + rel->r_offset);
	  bfd_putl32 (0xd53bd041, contents + rel->r_offset + 4);
	  bfd_putl32 (add_R0_R0_R1, contents + rel->r_offset + 8);
	  return bfd_reloc_continue;
	}
      else
	{
	  /* GD->IE relaxation
	     ADD  x0, #:tlsgd_lo12:var	=> ldr	R0, [x0, #:gottprel_lo12:var]
	     BL	  __tls_get_addr	=> mrs	x1, tpidr_el0
	       R_AARCH64_CALL26
	     NOP			=> add	R0, R1, R0

	     Where R is x for lp64 mode, and w for ilp32 mode.  */

	  BFD_ASSERT (ELF32_R_TYPE (rel[1].r_info) == AARCH64_R (CALL26));

	  /* Remove the relocation on the BL instruction.  */
	  rel[1].r_info = ELF32_R_INFO (STN_UNDEF, R_AARCH64_NONE);

	  /* We choose to fixup the BL and NOP instructions using the
	     offset from the second relocation to allow flexibility in
	     scheduling instructions between the ADD and BL.  */
	  bfd_putl32 (ldr_R0_x0, contents + rel->r_offset);
	  bfd_putl32 (0xd53bd041, contents + rel[1].r_offset);
	  bfd_putl32 (add_R0_R0_R1, contents + rel[1].r_offset + 4);
	  return bfd_reloc_continue;
	}

    case BFD_RELOC_AARCH64_TLSDESC_ADD:
    case BFD_RELOC_AARCH64_TLSDESC_ADD_LO12:
    case BFD_RELOC_AARCH64_TLSDESC_CALL:
      /* GD->IE/LE relaxation:
	 add x0, x0, #:tlsdesc_lo12:var	  =>   nop
	 blr xd				  =>   nop
       */
      bfd_putl32 (INSN_NOP, contents + rel->r_offset);
      return bfd_reloc_ok;

    case BFD_RELOC_AARCH64_TLSDESC_LDR:
      if (local_exec)
	{
	  /* GD->LE relaxation:
	     ldr xd, [gp, xn]   =>   movk R0, #:tprel_g0_nc:var

	     Where R is x for lp64 mode, and w for ILP32 mode.  */
	  bfd_putl32 (movk_R0, contents + rel->r_offset);
	  return bfd_reloc_continue;
	}
      else
	{
	  /* GD->IE relaxation:
	     ldr xd, [gp, xn]   =>   ldr R0, [gp, xn]

	     Where R is x for lp64 mode, and w for ILP32 mode.  */
	  insn = bfd_getl32 (contents + rel->r_offset);
	  bfd_putl32 (ldr_R0_mask (insn), contents + rel->r_offset);
	  return bfd_reloc_ok;
	}

    case BFD_RELOC_AARCH64_TLSDESC_OFF_G0_NC:
      /* GD->LE relaxation:
	 movk xd, #:tlsdesc_off_g0_nc:var => movk R0, #:tprel_g1_nc:var, lsl #16
	 GD->IE relaxation:
	 movk xd, #:tlsdesc_off_g0_nc:var => movk Rd, #:gottprel_g0_nc:var

	 Where R is x for lp64 mode, and w for ILP32 mode.  */
      if (local_exec)
	bfd_putl32 (ldr_hw_R0, contents + rel->r_offset);
      return bfd_reloc_continue;

    case BFD_RELOC_AARCH64_TLSDESC_OFF_G1:
      if (local_exec)
	{
	  /* GD->LE relaxation:
	     movz xd, #:tlsdesc_off_g1:var => movz R0, #:tprel_g2:var, lsl #32

	     Where R is x for lp64 mode, and w for ILP32 mode.  */
	  bfd_putl32 (movz_hw_R0, contents + rel->r_offset);
	  return bfd_reloc_continue;
	}
      else
	{
	  /*  GD->IE relaxation:
	      movz xd, #:tlsdesc_off_g1:var => movz Rd, #:gottprel_g1:var, lsl #16

	     Where R is x for lp64 mode, and w for ILP32 mode.  */
	  insn = bfd_getl32 (contents + rel->r_offset);
	  bfd_putl32 (movz_R0 | (insn & 0x1f), contents + rel->r_offset);
	  return bfd_reloc_continue;
	}

    case BFD_RELOC_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21:
      /* IE->LE relaxation:
	 adrp xd, :gottprel:var   =>   movz Rd, :tprel_g1:var

	 Where R is x for lp64 mode, and w for ILP32 mode.  */
      if (local_exec)
	{
	  insn = bfd_getl32 (contents + rel->r_offset);
	  bfd_putl32 (movz_R0 | (insn & 0x1f), contents + rel->r_offset);
	  /* We have relaxed the adrp into a mov, we may have to clear any
	     pending erratum fixes.  */
	  clear_erratum_843419_entry (globals, rel->r_offset, input_section);
	}
      return bfd_reloc_continue;

    case BFD_RELOC_AARCH64_TLSIE_LD32_GOTTPREL_LO12_NC:
      /* IE->LE relaxation:
	 ldr  xd, [xm, #:gottprel_lo12:var]   =>   movk Rd, :tprel_g0_nc:var

	 Where R is x for lp64 mode, and w for ILP32 mode.  */
      if (local_exec)
	{
	  insn = bfd_getl32 (contents + rel->r_offset);
	  bfd_putl32 (movk_R0 | (insn & 0x1f), contents + rel->r_offset);
	}
      return bfd_reloc_continue;

    case BFD_RELOC_AARCH64_TLSLD_ADR_PREL21:
      /* LD->LE relaxation (tiny):
	 adr  x0, :tlsldm:x  => mrs x0, tpidr_el0
	 bl   __tls_get_addr => add R0, R0, TCB_SIZE

	 Where R is x for lp64 mode, and w for ilp32 mode.  */
      if (local_exec)
	{
	  BFD_ASSERT (rel->r_offset + 4 == rel[1].r_offset);
	  BFD_ASSERT (ELF32_R_TYPE (rel[1].r_info) == AARCH64_R (CALL26));
	  /* No need of CALL26 relocation for tls_get_addr.  */
	  rel[1].r_info = ELF32_R_INFO (STN_UNDEF, R_AARCH64_NONE);
	  bfd_putl32 (0xd53bd040, contents + rel->r_offset + 0);
	  bfd_putl32 (add_R0_R0 | (TCB_SIZE << 10),
		      contents + rel->r_offset + 4);
	  return bfd_reloc_ok;
	}
      return bfd_reloc_continue;

    case BFD_RELOC_AARCH64_TLSLD_ADR_PAGE21:
      /* LD->LE relaxation (small):
	 adrp  x0, :tlsldm:x       => mrs x0, tpidr_el0
       */
      if (local_exec)
	{
	  bfd_putl32 (0xd53bd040, contents + rel->r_offset);
	  return bfd_reloc_ok;
	}
      return bfd_reloc_continue;

    case BFD_RELOC_AARCH64_TLSLD_ADD_LO12_NC:
      /* LD->LE relaxation (small):
	 add   x0, #:tlsldm_lo12:x => add R0, R0, TCB_SIZE
	 bl   __tls_get_addr       => nop

	 Where R is x for lp64 mode, and w for ilp32 mode.  */
      if (local_exec)
	{
	  BFD_ASSERT (rel->r_offset + 4 == rel[1].r_offset);
	  BFD_ASSERT (ELF32_R_TYPE (rel[1].r_info) == AARCH64_R (CALL26));
	  /* No need of CALL26 relocation for tls_get_addr.  */
	  rel[1].r_info = ELF32_R_INFO (STN_UNDEF, R_AARCH64_NONE);
	  bfd_putl32 (add_R0_R0 | (TCB_SIZE << 10),
		      contents + rel->r_offset + 0);
	  bfd_putl32 (INSN_NOP, contents + rel->r_offset + 4);
	  return bfd_reloc_ok;
	}
      return bfd_reloc_continue;

    default:
      return bfd_reloc_continue;
    }

  return bfd_reloc_ok;
}

/* Relocate an AArch64 ELF section.  */

static int
elf32_aarch64_relocate_section (bfd *output_bfd,
				struct bfd_link_info *info,
				bfd *input_bfd,
				asection *input_section,
				bfd_byte *contents,
				Elf_Internal_Rela *relocs,
				Elf_Internal_Sym *local_syms,
				asection **local_sections)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;
  const char *name;
  struct elf_aarch64_link_hash_table *globals;
  bool save_addend = false;
  bfd_vma addend = 0;

  globals = elf_aarch64_hash_table (info);

  symtab_hdr = &elf_symtab_hdr (input_bfd);
  sym_hashes = elf_sym_hashes (input_bfd);

  rel = relocs;
  relend = relocs + input_section->reloc_count;
  for (; rel < relend; rel++)
    {
      unsigned int r_type;
      bfd_reloc_code_real_type bfd_r_type;
      bfd_reloc_code_real_type relaxed_bfd_r_type;
      reloc_howto_type *howto;
      unsigned long r_symndx;
      Elf_Internal_Sym *sym;
      asection *sec;
      struct elf_link_hash_entry *h;
      bfd_vma relocation;
      bfd_reloc_status_type r;
      arelent bfd_reloc;
      char sym_type;
      bool unresolved_reloc = false;
      char *error_message = NULL;

      r_symndx = ELF32_R_SYM (rel->r_info);
      r_type = ELF32_R_TYPE (rel->r_info);

      bfd_reloc.howto = elf32_aarch64_howto_from_type (input_bfd, r_type);
      howto = bfd_reloc.howto;

      if (howto == NULL)
	return _bfd_unrecognized_reloc (input_bfd, input_section, r_type);

      bfd_r_type = elf32_aarch64_bfd_reloc_from_howto (howto);

      h = NULL;
      sym = NULL;
      sec = NULL;

      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sym_type = ELF32_ST_TYPE (sym->st_info);
	  sec = local_sections[r_symndx];

	  /* An object file might have a reference to a local
	     undefined symbol.  This is a daft object file, but we
	     should at least do something about it.  NONE and NULL
	     relocations do not use the symbol and are explicitly
	     allowed to use an undefined one, so allow those.
	     Likewise for relocations against STN_UNDEF.  */
	  if (r_type != R_AARCH64_NONE && r_type != R_AARCH64_NULL
	      && r_symndx != STN_UNDEF
	      && bfd_is_und_section (sec)
	      && ELF_ST_BIND (sym->st_info) != STB_WEAK)
	    (*info->callbacks->undefined_symbol)
	      (info, bfd_elf_string_from_elf_section
	       (input_bfd, symtab_hdr->sh_link, sym->st_name),
	       input_bfd, input_section, rel->r_offset, true);

	  relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);

	  /* Relocate against local STT_GNU_IFUNC symbol.  */
	  if (!bfd_link_relocatable (info)
	      && ELF_ST_TYPE (sym->st_info) == STT_GNU_IFUNC)
	    {
	      h = elf32_aarch64_get_local_sym_hash (globals, input_bfd,
						    rel, false);
	      if (h == NULL)
		abort ();

	      /* Set STT_GNU_IFUNC symbol value.  */
	      h->root.u.def.value = sym->st_value;
	      h->root.u.def.section = sec;
	    }
	}
      else
	{
	  bool warned, ignored;

	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation,
				   unresolved_reloc, warned, ignored);

	  sym_type = h->type;
	}

      if (sec != NULL && discarded_section (sec))
	RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					 rel, 1, relend, R_AARCH64_NONE,
					 howto, 0, contents);

      if (bfd_link_relocatable (info))
	continue;

      if (h != NULL)
	name = h->root.root.string;
      else
	{
	  name = (bfd_elf_string_from_elf_section
		  (input_bfd, symtab_hdr->sh_link, sym->st_name));
	  if (name == NULL || *name == '\0')
	    name = bfd_section_name (sec);
	}

      if (r_symndx != 0
	  && r_type != R_AARCH64_NONE
	  && r_type != R_AARCH64_NULL
	  && (h == NULL
	      || h->root.type == bfd_link_hash_defined
	      || h->root.type == bfd_link_hash_defweak)
	  && IS_AARCH64_TLS_RELOC (bfd_r_type) != (sym_type == STT_TLS))
	{
	  _bfd_error_handler
	    ((sym_type == STT_TLS
	      /* xgettext:c-format */
	      ? _("%pB(%pA+%#" PRIx64 "): %s used with TLS symbol %s")
	      /* xgettext:c-format */
	      : _("%pB(%pA+%#" PRIx64 "): %s used with non-TLS symbol %s")),
	     input_bfd,
	     input_section, (uint64_t) rel->r_offset, howto->name, name);
	}

      /* We relax only if we can see that there can be a valid transition
	 from a reloc type to another.
	 We call elf32_aarch64_final_link_relocate unless we're completely
	 done, i.e., the relaxation produced the final output we want.  */

      relaxed_bfd_r_type = aarch64_tls_transition (input_bfd, info, r_type,
						   h, r_symndx);
      if (relaxed_bfd_r_type != bfd_r_type)
	{
	  bfd_r_type = relaxed_bfd_r_type;
	  howto = elf32_aarch64_howto_from_bfd_reloc (bfd_r_type);
	  BFD_ASSERT (howto != NULL);
	  r_type = howto->type;
	  r = elf32_aarch64_tls_relax (globals, input_bfd, input_section,
				       contents, rel, h, info);
	  unresolved_reloc = 0;
	}
      else
	r = bfd_reloc_continue;

      /* There may be multiple consecutive relocations for the
	 same offset.  In that case we are supposed to treat the
	 output of each relocation as the addend for the next.  */
      if (rel + 1 < relend
	  && rel->r_offset == rel[1].r_offset
	  && ELF32_R_TYPE (rel[1].r_info) != R_AARCH64_NONE
	  && ELF32_R_TYPE (rel[1].r_info) != R_AARCH64_NULL)
	save_addend = true;
      else
	save_addend = false;

      if (r == bfd_reloc_continue)
	r = elf32_aarch64_final_link_relocate (howto, input_bfd, output_bfd,
					       input_section, contents, rel,
					       relocation, info, sec,
					       h, &unresolved_reloc,
					       save_addend, &addend, sym);

      switch (elf32_aarch64_bfd_reloc_from_type (input_bfd, r_type))
	{
	case BFD_RELOC_AARCH64_TLSGD_ADD_LO12_NC:
	case BFD_RELOC_AARCH64_TLSGD_ADR_PAGE21:
	case BFD_RELOC_AARCH64_TLSGD_ADR_PREL21:
	case BFD_RELOC_AARCH64_TLSGD_MOVW_G0_NC:
	case BFD_RELOC_AARCH64_TLSGD_MOVW_G1:
	case BFD_RELOC_AARCH64_TLSLD_ADD_LO12_NC:
	case BFD_RELOC_AARCH64_TLSLD_ADR_PAGE21:
	case BFD_RELOC_AARCH64_TLSLD_ADR_PREL21:
	  if (! symbol_got_offset_mark_p (input_bfd, h, r_symndx))
	    {
	      bool need_relocs = false;
	      bfd_byte *loc;
	      int indx;
	      bfd_vma off;

	      off = symbol_got_offset (input_bfd, h, r_symndx);
	      indx = h && h->dynindx != -1 ? h->dynindx : 0;

	      need_relocs =
		(!bfd_link_executable (info) || indx != 0) &&
		(h == NULL
		 || ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
		 || h->root.type != bfd_link_hash_undefweak);

	      BFD_ASSERT (globals->root.srelgot != NULL);

	      if (need_relocs)
		{
		  Elf_Internal_Rela rela;
		  rela.r_info = ELF32_R_INFO (indx, AARCH64_R (TLS_DTPMOD));
		  rela.r_addend = 0;
		  rela.r_offset = globals->root.sgot->output_section->vma +
		    globals->root.sgot->output_offset + off;


		  loc = globals->root.srelgot->contents;
		  loc += globals->root.srelgot->reloc_count++
		    * RELOC_SIZE (htab);
		  bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);

		  bfd_reloc_code_real_type real_type =
		    elf32_aarch64_bfd_reloc_from_type (input_bfd, r_type);

		  if (real_type == BFD_RELOC_AARCH64_TLSLD_ADR_PREL21
		      || real_type == BFD_RELOC_AARCH64_TLSLD_ADR_PAGE21
		      || real_type == BFD_RELOC_AARCH64_TLSLD_ADD_LO12_NC)
		    {
		      /* For local dynamic, don't generate DTPREL in any case.
			 Initialize the DTPREL slot into zero, so we get module
			 base address when invoke runtime TLS resolver.  */
		      bfd_put_32 (output_bfd, 0,
				  globals->root.sgot->contents + off
				  + GOT_ENTRY_SIZE);
		    }
		  else if (indx == 0)
		    {
		      bfd_put_32 (output_bfd,
				  relocation - dtpoff_base (info),
				  globals->root.sgot->contents + off
				  + GOT_ENTRY_SIZE);
		    }
		  else
		    {
		      /* This TLS symbol is global. We emit a
			 relocation to fixup the tls offset at load
			 time.  */
		      rela.r_info =
			ELF32_R_INFO (indx, AARCH64_R (TLS_DTPREL));
		      rela.r_addend = 0;
		      rela.r_offset =
			(globals->root.sgot->output_section->vma
			 + globals->root.sgot->output_offset + off
			 + GOT_ENTRY_SIZE);

		      loc = globals->root.srelgot->contents;
		      loc += globals->root.srelgot->reloc_count++
			* RELOC_SIZE (globals);
		      bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
		      bfd_put_32 (output_bfd, (bfd_vma) 0,
				  globals->root.sgot->contents + off
				  + GOT_ENTRY_SIZE);
		    }
		}
	      else
		{
		  bfd_put_32 (output_bfd, (bfd_vma) 1,
			      globals->root.sgot->contents + off);
		  bfd_put_32 (output_bfd,
			      relocation - dtpoff_base (info),
			      globals->root.sgot->contents + off
			      + GOT_ENTRY_SIZE);
		}

	      symbol_got_offset_mark (input_bfd, h, r_symndx);
	    }
	  break;

	case BFD_RELOC_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21:
	case BFD_RELOC_AARCH64_TLSIE_LD32_GOTTPREL_LO12_NC:
	case BFD_RELOC_AARCH64_TLSIE_LD_GOTTPREL_PREL19:
	case BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC:
	case BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G1:
	  if (! symbol_got_offset_mark_p (input_bfd, h, r_symndx))
	    {
	      bool need_relocs = false;
	      bfd_byte *loc;
	      int indx;
	      bfd_vma off;

	      off = symbol_got_offset (input_bfd, h, r_symndx);

	      indx = h && h->dynindx != -1 ? h->dynindx : 0;

	      need_relocs =
		(!bfd_link_executable (info) || indx != 0) &&
		(h == NULL
		 || ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
		 || h->root.type != bfd_link_hash_undefweak);

	      BFD_ASSERT (globals->root.srelgot != NULL);

	      if (need_relocs)
		{
		  Elf_Internal_Rela rela;

		  if (indx == 0)
		    rela.r_addend = relocation - dtpoff_base (info);
		  else
		    rela.r_addend = 0;

		  rela.r_info = ELF32_R_INFO (indx, AARCH64_R (TLS_TPREL));
		  rela.r_offset = globals->root.sgot->output_section->vma +
		    globals->root.sgot->output_offset + off;

		  loc = globals->root.srelgot->contents;
		  loc += globals->root.srelgot->reloc_count++
		    * RELOC_SIZE (htab);

		  bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);

		  bfd_put_32 (output_bfd, rela.r_addend,
			      globals->root.sgot->contents + off);
		}
	      else
		bfd_put_32 (output_bfd, relocation - tpoff_base (info),
			    globals->root.sgot->contents + off);

	      symbol_got_offset_mark (input_bfd, h, r_symndx);
	    }
	  break;

	case BFD_RELOC_AARCH64_TLSDESC_ADD_LO12:
	case BFD_RELOC_AARCH64_TLSDESC_ADR_PAGE21:
	case BFD_RELOC_AARCH64_TLSDESC_ADR_PREL21:
	case BFD_RELOC_AARCH64_TLSDESC_LD32_LO12_NC:
	case BFD_RELOC_AARCH64_TLSDESC_LD_PREL19:
	case BFD_RELOC_AARCH64_TLSDESC_OFF_G0_NC:
	case BFD_RELOC_AARCH64_TLSDESC_OFF_G1:
	  if (! symbol_tlsdesc_got_offset_mark_p (input_bfd, h, r_symndx))
	    {
	      bool need_relocs = false;
	      int indx = h && h->dynindx != -1 ? h->dynindx : 0;
	      bfd_vma off = symbol_tlsdesc_got_offset (input_bfd, h, r_symndx);

	      need_relocs = (h == NULL
			     || ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
			     || h->root.type != bfd_link_hash_undefweak);

	      BFD_ASSERT (globals->root.srelgot != NULL);
	      BFD_ASSERT (globals->root.sgot != NULL);

	      if (need_relocs)
		{
		  bfd_byte *loc;
		  Elf_Internal_Rela rela;
		  rela.r_info = ELF32_R_INFO (indx, AARCH64_R (TLSDESC));

		  rela.r_addend = 0;
		  rela.r_offset = (globals->root.sgotplt->output_section->vma
				   + globals->root.sgotplt->output_offset
				   + off + globals->sgotplt_jump_table_size);

		  if (indx == 0)
		    rela.r_addend = relocation - dtpoff_base (info);

		  /* Allocate the next available slot in the PLT reloc
		     section to hold our R_AARCH64_TLSDESC, the next
		     available slot is determined from reloc_count,
		     which we step. But note, reloc_count was
		     artifically moved down while allocating slots for
		     real PLT relocs such that all of the PLT relocs
		     will fit above the initial reloc_count and the
		     extra stuff will fit below.  */
		  loc = globals->root.srelplt->contents;
		  loc += globals->root.srelplt->reloc_count++
		    * RELOC_SIZE (globals);

		  bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);

		  bfd_put_32 (output_bfd, (bfd_vma) 0,
			      globals->root.sgotplt->contents + off +
			      globals->sgotplt_jump_table_size);
		  bfd_put_32 (output_bfd, (bfd_vma) 0,
			      globals->root.sgotplt->contents + off +
			      globals->sgotplt_jump_table_size +
			      GOT_ENTRY_SIZE);
		}

	      symbol_tlsdesc_got_offset_mark (input_bfd, h, r_symndx);
	    }
	  break;
	default:
	  break;
	}

      /* Dynamic relocs are not propagated for SEC_DEBUGGING sections
	 because such sections are not SEC_ALLOC and thus ld.so will
	 not process them.  */
      if (unresolved_reloc
	  && !((input_section->flags & SEC_DEBUGGING) != 0
	       && h->def_dynamic)
	  && _bfd_elf_section_offset (output_bfd, info, input_section,
				      +rel->r_offset) != (bfd_vma) - 1)
	{
	  _bfd_error_handler
	    /* xgettext:c-format */
	    (_("%pB(%pA+%#" PRIx64 "): "
	       "unresolvable %s relocation against symbol `%s'"),
	     input_bfd, input_section, (uint64_t) rel->r_offset, howto->name,
	     h->root.root.string);
	  return false;
	}

      if (r != bfd_reloc_ok && r != bfd_reloc_continue)
	{
	  bfd_reloc_code_real_type real_r_type
	    = elf32_aarch64_bfd_reloc_from_type (input_bfd, r_type);

	  switch (r)
	    {
	    case bfd_reloc_overflow:
	      (*info->callbacks->reloc_overflow)
		(info, (h ? &h->root : NULL), name, howto->name, (bfd_vma) 0,
		 input_bfd, input_section, rel->r_offset);
	      if (real_r_type == BFD_RELOC_AARCH64_LD64_GOTPAGE_LO15
		  || real_r_type == BFD_RELOC_AARCH64_LD32_GOTPAGE_LO14)
		{
		  (*info->callbacks->warning)
		    (info,
		     _("too many GOT entries for -fpic, "
		       "please recompile with -fPIC"),
		     name, input_bfd, input_section, rel->r_offset);
		  return false;
		}
	      /* Overflow can occur when a variable is referenced with a type
		 that has a larger alignment than the type with which it was
		 declared. eg:
		   file1.c: extern int foo; int a (void) { return foo; }
		   file2.c: char bar, foo, baz;
		 If the variable is placed into a data section at an offset
		 that is incompatible with the larger alignment requirement
		 overflow will occur.  (Strictly speaking this is not overflow
		 but rather an alignment problem, but the bfd_reloc_ error
		 enum does not have a value to cover that situation).

		 Try to catch this situation here and provide a more helpful
		 error message to the user.  */
	      if (addend & (((bfd_vma) 1 << howto->rightshift) - 1)
		  /* FIXME: Are we testing all of the appropriate reloc
		     types here ?  */
		  && (real_r_type == BFD_RELOC_AARCH64_LD_LO19_PCREL
		      || real_r_type == BFD_RELOC_AARCH64_LDST16_LO12
		      || real_r_type == BFD_RELOC_AARCH64_LDST32_LO12
		      || real_r_type == BFD_RELOC_AARCH64_LDST64_LO12
		      || real_r_type == BFD_RELOC_AARCH64_LDST128_LO12))
		{
		  info->callbacks->warning
		    (info, _("one possible cause of this error is that the \
symbol is being referenced in the indicated code as if it had a larger \
alignment than was declared where it was defined"),
		     name, input_bfd, input_section, rel->r_offset);
		}
	      break;

	    case bfd_reloc_undefined:
	      (*info->callbacks->undefined_symbol)
		(info, name, input_bfd, input_section, rel->r_offset, true);
	      break;

	    case bfd_reloc_outofrange:
	      error_message = _("out of range");
	      goto common_error;

	    case bfd_reloc_notsupported:
	      error_message = _("unsupported relocation");
	      goto common_error;

	    case bfd_reloc_dangerous:
	      /* error_message should already be set.  */
	      goto common_error;

	    default:
	      error_message = _("unknown error");
	      /* Fall through.  */

	    common_error:
	      BFD_ASSERT (error_message != NULL);
	      (*info->callbacks->reloc_dangerous)
		(info, error_message, input_bfd, input_section, rel->r_offset);
	      break;
	    }
	}

      if (!save_addend)
	addend = 0;
    }

  return true;
}

/* Set the right machine number.  */

static bool
elf32_aarch64_object_p (bfd *abfd)
{
#if ARCH_SIZE == 32
  bfd_default_set_arch_mach (abfd, bfd_arch_aarch64, bfd_mach_aarch64_ilp32);
#else
  bfd_default_set_arch_mach (abfd, bfd_arch_aarch64, bfd_mach_aarch64);
#endif
  return true;
}

/* Function to keep AArch64 specific flags in the ELF header.  */

static bool
elf32_aarch64_set_private_flags (bfd *abfd, flagword flags)
{
  if (elf_flags_init (abfd) && elf_elfheader (abfd)->e_flags != flags)
    {
    }
  else
    {
      elf_elfheader (abfd)->e_flags = flags;
      elf_flags_init (abfd) = true;
    }

  return true;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bool
elf32_aarch64_merge_private_bfd_data (bfd *ibfd, struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;
  flagword out_flags;
  flagword in_flags;
  bool flags_compatible = true;
  asection *sec;

  /* Check if we have the same endianess.  */
  if (!_bfd_generic_verify_endian_match (ibfd, info))
    return false;

  if (!is_aarch64_elf (ibfd) || !is_aarch64_elf (obfd))
    return true;

  /* The input BFD must have had its flags initialised.  */
  /* The following seems bogus to me -- The flags are initialized in
     the assembler but I don't think an elf_flags_init field is
     written into the object.  */
  /* BFD_ASSERT (elf_flags_init (ibfd)); */

  in_flags = elf_elfheader (ibfd)->e_flags;
  out_flags = elf_elfheader (obfd)->e_flags;

  if (!elf_flags_init (obfd))
    {
      /* If the input is the default architecture and had the default
	 flags then do not bother setting the flags for the output
	 architecture, instead allow future merges to do this.  If no
	 future merges ever set these flags then they will retain their
	 uninitialised values, which surprise surprise, correspond
	 to the default values.  */
      if (bfd_get_arch_info (ibfd)->the_default
	  && elf_elfheader (ibfd)->e_flags == 0)
	return true;

      elf_flags_init (obfd) = true;
      elf_elfheader (obfd)->e_flags = in_flags;

      if (bfd_get_arch (obfd) == bfd_get_arch (ibfd)
	  && bfd_get_arch_info (obfd)->the_default)
	return bfd_set_arch_mach (obfd, bfd_get_arch (ibfd),
				  bfd_get_mach (ibfd));

      return true;
    }

  /* Identical flags must be compatible.  */
  if (in_flags == out_flags)
    return true;

  /* Check to see if the input BFD actually contains any sections.  If
     not, its flags may not have been initialised either, but it
     cannot actually cause any incompatiblity.  Do not short-circuit
     dynamic objects; their section list may be emptied by
     elf_link_add_object_symbols.

     Also check to see if there are no code sections in the input.
     In this case there is no need to check for code specific flags.
     XXX - do we need to worry about floating-point format compatability
     in data sections ?  */
  if (!(ibfd->flags & DYNAMIC))
    {
      bool null_input_bfd = true;
      bool only_data_sections = true;

      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
	{
	  if ((bfd_section_flags (sec)
	       & (SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS))
	      == (SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS))
	    only_data_sections = false;

	  null_input_bfd = false;
	  break;
	}

      if (null_input_bfd || only_data_sections)
	return true;
    }

  return flags_compatible;
}

/* Display the flags field.  */

static bool
elf32_aarch64_print_private_bfd_data (bfd *abfd, void *ptr)
{
  FILE *file = (FILE *) ptr;
  unsigned long flags;

  BFD_ASSERT (abfd != NULL && ptr != NULL);

  /* Print normal ELF private data.  */
  _bfd_elf_print_private_bfd_data (abfd, ptr);

  flags = elf_elfheader (abfd)->e_flags;
  /* Ignore init flag - it may not be set, despite the flags field
     containing valid data.  */

  /* xgettext:c-format */
  fprintf (file, _("private flags = 0x%lx:"), elf_elfheader (abfd)->e_flags);

  if (flags)
    fprintf (file, _(" <Unrecognised flag bits set>"));

  fputc ('\n', file);

  return true;
}

/* Return true if we need copy relocation against EH.  */

static bool
need_copy_relocation_p (struct elf_aarch64_link_hash_entry *eh)
{
  struct elf_dyn_relocs *p;
  asection *s;

  for (p = eh->root.dyn_relocs; p != NULL; p = p->next)
    {
      /* If there is any pc-relative reference, we need to keep copy relocation
	 to avoid propagating the relocation into runtime that current glibc
	 does not support.  */
      if (p->pc_count)
	return true;

      s = p->sec->output_section;
      /* Need copy relocation if it's against read-only section.  */
      if (s != NULL && (s->flags & SEC_READONLY) != 0)
	return true;
    }

  return false;
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.	*/

static bool
elf32_aarch64_adjust_dynamic_symbol (struct bfd_link_info *info,
				     struct elf_link_hash_entry *h)
{
  struct elf_aarch64_link_hash_table *htab;
  asection *s, *srel;

  /* If this is a function, put it in the procedure linkage table.  We
     will fill in the contents of the procedure linkage table later,
     when we know the address of the .got section.  */
  if (h->type == STT_FUNC || h->type == STT_GNU_IFUNC || h->needs_plt)
    {
      if (h->plt.refcount <= 0
	  || (h->type != STT_GNU_IFUNC
	      && (SYMBOL_CALLS_LOCAL (info, h)
		  || (ELF_ST_VISIBILITY (h->other) != STV_DEFAULT
		      && h->root.type == bfd_link_hash_undefweak))))
	{
	  /* This case can occur if we saw a CALL26 reloc in
	     an input file, but the symbol wasn't referred to
	     by a dynamic object or all references were
	     garbage collected. In which case we can end up
	     resolving.  */
	  h->plt.offset = (bfd_vma) - 1;
	  h->needs_plt = 0;
	}

      return true;
    }
  else
    /* Otherwise, reset to -1.  */
    h->plt.offset = (bfd_vma) - 1;


  /* If this is a weak symbol, and there is a real definition, the
     processor independent code will have arranged for us to see the
     real definition first, and we can just use the same value.  */
  if (h->is_weakalias)
    {
      struct elf_link_hash_entry *def = weakdef (h);
      BFD_ASSERT (def->root.type == bfd_link_hash_defined);
      h->root.u.def.section = def->root.u.def.section;
      h->root.u.def.value = def->root.u.def.value;
      if (ELIMINATE_COPY_RELOCS || info->nocopyreloc)
	h->non_got_ref = def->non_got_ref;
      return true;
    }

  /* If we are creating a shared library, we must presume that the
     only references to the symbol are via the global offset table.
     For such cases we need not do anything here; the relocations will
     be handled correctly by relocate_section.  */
  if (bfd_link_pic (info))
    return true;

  /* If there are no references to this symbol that do not use the
     GOT, we don't need to generate a copy reloc.  */
  if (!h->non_got_ref)
    return true;

  /* If -z nocopyreloc was given, we won't generate them either.  */
  if (info->nocopyreloc)
    {
      h->non_got_ref = 0;
      return true;
    }

  if (ELIMINATE_COPY_RELOCS)
    {
      struct elf_aarch64_link_hash_entry *eh;
      /* If we don't find any dynamic relocs in read-only sections, then
	 we'll be keeping the dynamic relocs and avoiding the copy reloc.  */
      eh = (struct elf_aarch64_link_hash_entry *) h;
      if (!need_copy_relocation_p (eh))
	{
	  h->non_got_ref = 0;
	  return true;
	}
    }

  /* We must allocate the symbol in our .dynbss section, which will
     become part of the .bss section of the executable.  There will be
     an entry for this symbol in the .dynsym section.  The dynamic
     object will contain position independent code, so all references
     from the dynamic object to this symbol will go through the global
     offset table.  The dynamic linker will use the .dynsym entry to
     determine the address it must put in the global offset table, so
     both the dynamic object and the regular object will refer to the
     same memory location for the variable.  */

  htab = elf_aarch64_hash_table (info);

  /* We must generate a R_AARCH64_COPY reloc to tell the dynamic linker
     to copy the initial value out of the dynamic object and into the
     runtime process image.  */
  if ((h->root.u.def.section->flags & SEC_READONLY) != 0)
    {
      s = htab->root.sdynrelro;
      srel = htab->root.sreldynrelro;
    }
  else
    {
      s = htab->root.sdynbss;
      srel = htab->root.srelbss;
    }
  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0)
    {
      srel->size += RELOC_SIZE (htab);
      h->needs_copy = 1;
    }

  return _bfd_elf_adjust_dynamic_copy (info, h, s);

}

static bool
elf32_aarch64_allocate_local_symbols (bfd *abfd, unsigned number)
{
  struct elf_aarch64_local_symbol *locals;
  locals = elf_aarch64_locals (abfd);
  if (locals == NULL)
    {
      locals = (struct elf_aarch64_local_symbol *)
	bfd_zalloc (abfd, number * sizeof (struct elf_aarch64_local_symbol));
      if (locals == NULL)
	return false;
      elf_aarch64_locals (abfd) = locals;
    }
  return true;
}

/* Create the .got section to hold the global offset table.  */

static bool
aarch64_elf_create_got_section (bfd *abfd, struct bfd_link_info *info)
{
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  flagword flags;
  asection *s;
  struct elf_link_hash_entry *h;
  struct elf_link_hash_table *htab = elf_hash_table (info);

  /* This function may be called more than once.  */
  if (htab->sgot != NULL)
    return true;

  flags = bed->dynamic_sec_flags;

  s = bfd_make_section_anyway_with_flags (abfd,
					  (bed->rela_plts_and_copies_p
					   ? ".rela.got" : ".rel.got"),
					  (bed->dynamic_sec_flags
					   | SEC_READONLY));
  if (s == NULL
      || !bfd_set_section_alignment (s, bed->s->log_file_align))
    return false;
  htab->srelgot = s;

  s = bfd_make_section_anyway_with_flags (abfd, ".got", flags);
  if (s == NULL
      || !bfd_set_section_alignment (s, bed->s->log_file_align))
    return false;
  htab->sgot = s;
  htab->sgot->size += GOT_ENTRY_SIZE;

  if (bed->want_got_sym)
    {
      /* Define the symbol _GLOBAL_OFFSET_TABLE_ at the start of the .got
	 (or .got.plt) section.  We don't do this in the linker script
	 because we don't want to define the symbol if we are not creating
	 a global offset table.  */
      h = _bfd_elf_define_linkage_sym (abfd, info, s,
				       "_GLOBAL_OFFSET_TABLE_");
      elf_hash_table (info)->hgot = h;
      if (h == NULL)
	return false;
    }

  if (bed->want_got_plt)
    {
      s = bfd_make_section_anyway_with_flags (abfd, ".got.plt", flags);
      if (s == NULL
	  || !bfd_set_section_alignment (s, bed->s->log_file_align))
	return false;
      htab->sgotplt = s;
    }

  /* The first bit of the global offset table is the header.  */
  s->size += bed->got_header_size;

  return true;
}

/* Look through the relocs for a section during the first phase.  */

static bool
elf32_aarch64_check_relocs (bfd *abfd, struct bfd_link_info *info,
			    asection *sec, const Elf_Internal_Rela *relocs)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  asection *sreloc;

  struct elf_aarch64_link_hash_table *htab;

  if (bfd_link_relocatable (info))
    return true;

  BFD_ASSERT (is_aarch64_elf (abfd));

  htab = elf_aarch64_hash_table (info);
  sreloc = NULL;

  symtab_hdr = &elf_symtab_hdr (abfd);
  sym_hashes = elf_sym_hashes (abfd);

  rel_end = relocs + sec->reloc_count;
  for (rel = relocs; rel < rel_end; rel++)
    {
      struct elf_link_hash_entry *h;
      unsigned int r_symndx;
      unsigned int r_type;
      bfd_reloc_code_real_type bfd_r_type;
      Elf_Internal_Sym *isym;

      r_symndx = ELF32_R_SYM (rel->r_info);
      r_type = ELF32_R_TYPE (rel->r_info);

      if (r_symndx >= NUM_SHDR_ENTRIES (symtab_hdr))
	{
	  /* xgettext:c-format */
	  _bfd_error_handler (_("%pB: bad symbol index: %d"), abfd, r_symndx);
	  return false;
	}

      if (r_symndx < symtab_hdr->sh_info)
	{
	  /* A local symbol.  */
	  isym = bfd_sym_from_r_symndx (&htab->root.sym_cache,
					abfd, r_symndx);
	  if (isym == NULL)
	    return false;

	  /* Check relocation against local STT_GNU_IFUNC symbol.  */
	  if (ELF_ST_TYPE (isym->st_info) == STT_GNU_IFUNC)
	    {
	      h = elf32_aarch64_get_local_sym_hash (htab, abfd, rel,
						    true);
	      if (h == NULL)
		return false;

	      /* Fake a STT_GNU_IFUNC symbol.  */
	      h->type = STT_GNU_IFUNC;
	      h->def_regular = 1;
	      h->ref_regular = 1;
	      h->forced_local = 1;
	      h->root.type = bfd_link_hash_defined;
	    }
	  else
	    h = NULL;
	}
      else
	{
	  h = sym_hashes[r_symndx - symtab_hdr->sh_info];
	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;
	}

      /* Could be done earlier, if h were already available.  */
      bfd_r_type = aarch64_tls_transition (abfd, info, r_type, h, r_symndx);

      if (h != NULL)
	{
	  /* If a relocation refers to _GLOBAL_OFFSET_TABLE_, create the .got.
	     This shows up in particular in an R_AARCH64_PREL64 in large model
	     when calculating the pc-relative address to .got section which is
	     used to initialize the gp register.  */
	  if (h->root.root.string
	      && strcmp (h->root.root.string, "_GLOBAL_OFFSET_TABLE_") == 0)
	    {
	      if (htab->root.dynobj == NULL)
		htab->root.dynobj = abfd;

	      if (! aarch64_elf_create_got_section (htab->root.dynobj, info))
		return false;

	      BFD_ASSERT (h == htab->root.hgot);
	    }

	  /* Create the ifunc sections for static executables.  If we
	     never see an indirect function symbol nor we are building
	     a static executable, those sections will be empty and
	     won't appear in output.  */
	  switch (bfd_r_type)
	    {
	    default:
	      break;

	    case BFD_RELOC_AARCH64_ADD_LO12:
	    case BFD_RELOC_AARCH64_ADR_GOT_PAGE:
	    case BFD_RELOC_AARCH64_ADR_HI21_PCREL:
	    case BFD_RELOC_AARCH64_CALL26:
	    case BFD_RELOC_AARCH64_GOT_LD_PREL19:
	    case BFD_RELOC_AARCH64_JUMP26:
	    case BFD_RELOC_AARCH64_LD32_GOTPAGE_LO14:
	    case BFD_RELOC_AARCH64_LD32_GOT_LO12_NC:
	    case BFD_RELOC_AARCH64_LD64_GOTOFF_LO15:
	    case BFD_RELOC_AARCH64_LD64_GOTPAGE_LO15:
	    case BFD_RELOC_AARCH64_LD64_GOT_LO12_NC:
	    case BFD_RELOC_AARCH64_MOVW_GOTOFF_G0_NC:
	    case BFD_RELOC_AARCH64_MOVW_GOTOFF_G1:
	    case BFD_RELOC_AARCH64_32:
	      if (htab->root.dynobj == NULL)
		htab->root.dynobj = abfd;
	      if (!_bfd_elf_create_ifunc_sections (htab->root.dynobj, info))
		return false;
	      break;
	    }

	  /* It is referenced by a non-shared object.  */
	  h->ref_regular = 1;
	}

      switch (bfd_r_type)
	{
	case BFD_RELOC_AARCH64_16:
#if ARCH_SIZE == 64
	case BFD_RELOC_AARCH64_32:
#endif
	  if (bfd_link_pic (info) && (sec->flags & SEC_ALLOC) != 0)
	    {
	      if (h != NULL
		  /* This is an absolute symbol.  It represents a value instead
		     of an address.  */
		  && (bfd_is_abs_symbol (&h->root)
		      /* This is an undefined symbol.  */
		      || h->root.type == bfd_link_hash_undefined))
		break;

	      /* For local symbols, defined global symbols in a non-ABS section,
		 it is assumed that the value is an address.  */
	      int howto_index = bfd_r_type - BFD_RELOC_AARCH64_RELOC_START;
	      _bfd_error_handler
		/* xgettext:c-format */
		(_("%pB: relocation %s against `%s' can not be used when making "
		   "a shared object"),
		 abfd, elf32_aarch64_howto_table[howto_index].name,
		 (h) ? h->root.root.string : "a local symbol");
	      bfd_set_error (bfd_error_bad_value);
	      return false;
	    }
	  else
	    break;

	case BFD_RELOC_AARCH64_MOVW_G0_NC:
	case BFD_RELOC_AARCH64_MOVW_G1_NC:
	case BFD_RELOC_AARCH64_MOVW_G2_NC:
	case BFD_RELOC_AARCH64_MOVW_G3:
	  if (bfd_link_pic (info))
	    {
	      int howto_index = bfd_r_type - BFD_RELOC_AARCH64_RELOC_START;
	      _bfd_error_handler
		/* xgettext:c-format */
		(_("%pB: relocation %s against `%s' can not be used when making "
		   "a shared object; recompile with -fPIC"),
		 abfd, elf32_aarch64_howto_table[howto_index].name,
		 (h) ? h->root.root.string : "a local symbol");
	      bfd_set_error (bfd_error_bad_value);
	      return false;
	    }
	  /* Fall through.  */

	case BFD_RELOC_AARCH64_16_PCREL:
	case BFD_RELOC_AARCH64_32_PCREL:
	case BFD_RELOC_AARCH64_64_PCREL:
	case BFD_RELOC_AARCH64_ADD_LO12:
	case BFD_RELOC_AARCH64_ADR_HI21_NC_PCREL:
	case BFD_RELOC_AARCH64_ADR_HI21_PCREL:
	case BFD_RELOC_AARCH64_ADR_LO21_PCREL:
	case BFD_RELOC_AARCH64_LDST128_LO12:
	case BFD_RELOC_AARCH64_LDST16_LO12:
	case BFD_RELOC_AARCH64_LDST32_LO12:
	case BFD_RELOC_AARCH64_LDST64_LO12:
	case BFD_RELOC_AARCH64_LDST8_LO12:
	case BFD_RELOC_AARCH64_LD_LO19_PCREL:
	  if (h == NULL || bfd_link_pic (info))
	    break;
	  /* Fall through.  */

	case BFD_RELOC_AARCH64_32:

	  /* We don't need to handle relocs into sections not going into
	     the "real" output.  */
	  if ((sec->flags & SEC_ALLOC) == 0)
	    break;

	  if (h != NULL)
	    {
	      if (!bfd_link_pic (info))
		h->non_got_ref = 1;

	      h->plt.refcount += 1;
	      h->pointer_equality_needed = 1;
	    }

	  /* No need to do anything if we're not creating a shared
	     object.  */
	  if (!(bfd_link_pic (info)
		/* If on the other hand, we are creating an executable, we
		   may need to keep relocations for symbols satisfied by a
		   dynamic library if we manage to avoid copy relocs for the
		   symbol.

		   NOTE: Currently, there is no support of copy relocs
		   elimination on pc-relative relocation types, because there is
		   no dynamic relocation support for them in glibc.  We still
		   record the dynamic symbol reference for them.  This is
		   because one symbol may be referenced by both absolute
		   relocation (for example, BFD_RELOC_AARCH64_32) and
		   pc-relative relocation.  We need full symbol reference
		   information to make correct decision later in
		   elf32_aarch64_adjust_dynamic_symbol.  */
		|| (ELIMINATE_COPY_RELOCS
		    && !bfd_link_pic (info)
		    && h != NULL
		    && (h->root.type == bfd_link_hash_defweak
			|| !h->def_regular))))
	    break;

	  {
	    struct elf_dyn_relocs *p;
	    struct elf_dyn_relocs **head;
	    int howto_index = bfd_r_type - BFD_RELOC_AARCH64_RELOC_START;

	    /* We must copy these reloc types into the output file.
	       Create a reloc section in dynobj and make room for
	       this reloc.  */
	    if (sreloc == NULL)
	      {
		if (htab->root.dynobj == NULL)
		  htab->root.dynobj = abfd;

		sreloc = _bfd_elf_make_dynamic_reloc_section
		  (sec, htab->root.dynobj, LOG_FILE_ALIGN, abfd, /*rela? */ true);

		if (sreloc == NULL)
		  return false;
	      }

	    /* If this is a global symbol, we count the number of
	       relocations we need for this symbol.  */
	    if (h != NULL)
	      {
		head = &h->dyn_relocs;
	      }
	    else
	      {
		/* Track dynamic relocs needed for local syms too.
		   We really need local syms available to do this
		   easily.  Oh well.  */

		asection *s;
		void **vpp;

		isym = bfd_sym_from_r_symndx (&htab->root.sym_cache,
					      abfd, r_symndx);
		if (isym == NULL)
		  return false;

		s = bfd_section_from_elf_index (abfd, isym->st_shndx);
		if (s == NULL)
		  s = sec;

		/* Beware of type punned pointers vs strict aliasing
		   rules.  */
		vpp = &(elf_section_data (s)->local_dynrel);
		head = (struct elf_dyn_relocs **) vpp;
	      }

	    p = *head;
	    if (p == NULL || p->sec != sec)
	      {
		size_t amt = sizeof *p;
		p = ((struct elf_dyn_relocs *)
		     bfd_zalloc (htab->root.dynobj, amt));
		if (p == NULL)
		  return false;
		p->next = *head;
		*head = p;
		p->sec = sec;
	      }

	    p->count += 1;

	    if (elf32_aarch64_howto_table[howto_index].pc_relative)
	      p->pc_count += 1;
	  }
	  break;

	  /* RR: We probably want to keep a consistency check that
	     there are no dangling GOT_PAGE relocs.  */
	case BFD_RELOC_AARCH64_ADR_GOT_PAGE:
	case BFD_RELOC_AARCH64_GOT_LD_PREL19:
	case BFD_RELOC_AARCH64_LD32_GOTPAGE_LO14:
	case BFD_RELOC_AARCH64_LD32_GOT_LO12_NC:
	case BFD_RELOC_AARCH64_LD64_GOTOFF_LO15:
	case BFD_RELOC_AARCH64_LD64_GOTPAGE_LO15:
	case BFD_RELOC_AARCH64_LD64_GOT_LO12_NC:
	case BFD_RELOC_AARCH64_MOVW_GOTOFF_G0_NC:
	case BFD_RELOC_AARCH64_MOVW_GOTOFF_G1:
	case BFD_RELOC_AARCH64_TLSDESC_ADD_LO12:
	case BFD_RELOC_AARCH64_TLSDESC_ADR_PAGE21:
	case BFD_RELOC_AARCH64_TLSDESC_ADR_PREL21:
	case BFD_RELOC_AARCH64_TLSDESC_LD32_LO12_NC:
	case BFD_RELOC_AARCH64_TLSDESC_LD64_LO12:
	case BFD_RELOC_AARCH64_TLSDESC_LD_PREL19:
	case BFD_RELOC_AARCH64_TLSDESC_OFF_G0_NC:
	case BFD_RELOC_AARCH64_TLSDESC_OFF_G1:
	case BFD_RELOC_AARCH64_TLSGD_ADD_LO12_NC:
	case BFD_RELOC_AARCH64_TLSGD_ADR_PAGE21:
	case BFD_RELOC_AARCH64_TLSGD_ADR_PREL21:
	case BFD_RELOC_AARCH64_TLSGD_MOVW_G0_NC:
	case BFD_RELOC_AARCH64_TLSGD_MOVW_G1:
	case BFD_RELOC_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21:
	case BFD_RELOC_AARCH64_TLSIE_LD32_GOTTPREL_LO12_NC:
	case BFD_RELOC_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC:
	case BFD_RELOC_AARCH64_TLSIE_LD_GOTTPREL_PREL19:
	case BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC:
	case BFD_RELOC_AARCH64_TLSIE_MOVW_GOTTPREL_G1:
	case BFD_RELOC_AARCH64_TLSLD_ADD_LO12_NC:
	case BFD_RELOC_AARCH64_TLSLD_ADR_PAGE21:
	case BFD_RELOC_AARCH64_TLSLD_ADR_PREL21:
	  {
	    unsigned got_type;
	    unsigned old_got_type;

	    got_type = aarch64_reloc_got_type (bfd_r_type);

	    if (h)
	      {
		h->got.refcount += 1;
		old_got_type = elf_aarch64_hash_entry (h)->got_type;
	      }
	    else
	      {
		struct elf_aarch64_local_symbol *locals;

		if (!elf32_aarch64_allocate_local_symbols
		    (abfd, symtab_hdr->sh_info))
		  return false;

		locals = elf_aarch64_locals (abfd);
		BFD_ASSERT (r_symndx < symtab_hdr->sh_info);
		locals[r_symndx].got_refcount += 1;
		old_got_type = locals[r_symndx].got_type;
	      }

	    /* If a variable is accessed with both general dynamic TLS
	       methods, two slots may be created.  */
	    if (GOT_TLS_GD_ANY_P (old_got_type) && GOT_TLS_GD_ANY_P (got_type))
	      got_type |= old_got_type;

	    /* We will already have issued an error message if there
	       is a TLS/non-TLS mismatch, based on the symbol type.
	       So just combine any TLS types needed.  */
	    if (old_got_type != GOT_UNKNOWN && old_got_type != GOT_NORMAL
		&& got_type != GOT_NORMAL)
	      got_type |= old_got_type;

	    /* If the symbol is accessed by both IE and GD methods, we
	       are able to relax.  Turn off the GD flag, without
	       messing up with any other kind of TLS types that may be
	       involved.  */
	    if ((got_type & GOT_TLS_IE) && GOT_TLS_GD_ANY_P (got_type))
	      got_type &= ~ (GOT_TLSDESC_GD | GOT_TLS_GD);

	    if (old_got_type != got_type)
	      {
		if (h != NULL)
		  elf_aarch64_hash_entry (h)->got_type = got_type;
		else
		  {
		    struct elf_aarch64_local_symbol *locals;
		    locals = elf_aarch64_locals (abfd);
		    BFD_ASSERT (r_symndx < symtab_hdr->sh_info);
		    locals[r_symndx].got_type = got_type;
		  }
	      }

	    if (htab->root.dynobj == NULL)
	      htab->root.dynobj = abfd;
	    if (! aarch64_elf_create_got_section (htab->root.dynobj, info))
	      return false;
	    break;
	  }

	case BFD_RELOC_AARCH64_CALL26:
	case BFD_RELOC_AARCH64_JUMP26:
	  /* If this is a local symbol then we resolve it
	     directly without creating a PLT entry.  */
	  if (h == NULL)
	    continue;

	  h->needs_plt = 1;
	  if (h->plt.refcount <= 0)
	    h->plt.refcount = 1;
	  else
	    h->plt.refcount += 1;
	  break;

	default:
	  break;
	}
    }

  return true;
}

/* Treat mapping symbols as special target symbols.  */

static bool
elf32_aarch64_is_target_special_symbol (bfd *abfd ATTRIBUTE_UNUSED,
					asymbol *sym)
{
  return bfd_is_aarch64_special_symbol_name (sym->name,
					     BFD_AARCH64_SPECIAL_SYM_TYPE_ANY);
}

/* If the ELF symbol SYM might be a function in SEC, return the
   function size and set *CODE_OFF to the function's entry point,
   otherwise return zero.  */

static bfd_size_type
elf32_aarch64_maybe_function_sym (const asymbol *sym, asection *sec,
				  bfd_vma *code_off)
{
  bfd_size_type size;
  elf_symbol_type * elf_sym = (elf_symbol_type *) sym;

  if ((sym->flags & (BSF_SECTION_SYM | BSF_FILE | BSF_OBJECT
		     | BSF_THREAD_LOCAL | BSF_RELC | BSF_SRELC)) != 0
      || sym->section != sec)
    return 0;

  size = (sym->flags & BSF_SYNTHETIC) ? 0 : elf_sym->internal_elf_sym.st_size;

  if (!(sym->flags & BSF_SYNTHETIC))
    switch (ELF_ST_TYPE (elf_sym->internal_elf_sym.st_info))
      {
	case STT_NOTYPE:
	  /* Ignore symbols created by the annobin plugin for gcc and clang.
	     These symbols are hidden, local, notype and have a size of 0.  */
	  if (size == 0
	      && sym->flags & BSF_LOCAL
	      && ELF_ST_VISIBILITY (elf_sym->internal_elf_sym.st_other) == STV_HIDDEN)
	    return 0;
	  /* Fall through.  */
	case STT_FUNC:
	  /* FIXME: Allow STT_GNU_IFUNC as well ?  */
	  break;
	default:
	  return 0;
      }

  if ((sym->flags & BSF_LOCAL)
      && bfd_is_aarch64_special_symbol_name (sym->name,
					     BFD_AARCH64_SPECIAL_SYM_TYPE_ANY))
    return 0;

  *code_off = sym->value;

  /* Do not return 0 for the function's size.  */
  return size ? size : 1;
}

static bool
elf32_aarch64_find_inliner_info (bfd *abfd,
				 const char **filename_ptr,
				 const char **functionname_ptr,
				 unsigned int *line_ptr)
{
  bool found;
  found = _bfd_dwarf2_find_inliner_info
    (abfd, filename_ptr,
     functionname_ptr, line_ptr, &elf_tdata (abfd)->dwarf2_find_line_info);
  return found;
}


static bool
elf32_aarch64_init_file_header (bfd *abfd, struct bfd_link_info *link_info)
{
  Elf_Internal_Ehdr *i_ehdrp;	/* ELF file header, internal form.  */

  if (!_bfd_elf_init_file_header (abfd, link_info))
    return false;

  i_ehdrp = elf_elfheader (abfd);
  i_ehdrp->e_ident[EI_ABIVERSION] = AARCH64_ELF_ABI_VERSION;
  return true;
}

static enum elf_reloc_type_class
elf32_aarch64_reloc_type_class (const struct bfd_link_info *info ATTRIBUTE_UNUSED,
				const asection *rel_sec ATTRIBUTE_UNUSED,
				const Elf_Internal_Rela *rela)
{
  struct elf_aarch64_link_hash_table *htab = elf_aarch64_hash_table (info);

  if (htab->root.dynsym != NULL
      && htab->root.dynsym->contents != NULL)
    {
      /* Check relocation against STT_GNU_IFUNC symbol if there are
	 dynamic symbols.  */
      bfd *abfd = info->output_bfd;
      const struct elf_backend_data *bed = get_elf_backend_data (abfd);
      unsigned long r_symndx = ELF32_R_SYM (rela->r_info);
      if (r_symndx != STN_UNDEF)
	{
	  Elf_Internal_Sym sym;
	  if (!bed->s->swap_symbol_in (abfd,
				       (htab->root.dynsym->contents
					+ r_symndx * bed->s->sizeof_sym),
				       0, &sym))
	    {
	      /* xgettext:c-format */
	      _bfd_error_handler (_("%pB symbol number %lu references"
				    " nonexistent SHT_SYMTAB_SHNDX section"),
				    abfd, r_symndx);
	      /* Ideally an error class should be returned here.  */
	    }
	  else if (ELF_ST_TYPE (sym.st_info) == STT_GNU_IFUNC)
	    return reloc_class_ifunc;
	}
    }

  switch ((int) ELF32_R_TYPE (rela->r_info))
    {
    case AARCH64_R (IRELATIVE):
      return reloc_class_ifunc;
    case AARCH64_R (RELATIVE):
      return reloc_class_relative;
    case AARCH64_R (JUMP_SLOT):
      return reloc_class_plt;
    case AARCH64_R (COPY):
      return reloc_class_copy;
    default:
      return reloc_class_normal;
    }
}

/* Handle an AArch64 specific section when reading an object file.  This is
   called when bfd_section_from_shdr finds a section with an unknown
   type.  */

static bool
elf32_aarch64_section_from_shdr (bfd *abfd,
				 Elf_Internal_Shdr *hdr,
				 const char *name, int shindex)
{
  /* There ought to be a place to keep ELF backend specific flags, but
     at the moment there isn't one.  We just keep track of the
     sections by their name, instead.  Fortunately, the ABI gives
     names for all the AArch64 specific sections, so we will probably get
     away with this.  */
  switch (hdr->sh_type)
    {
    case SHT_AARCH64_ATTRIBUTES:
      break;

    default:
      return false;
    }

  if (!_bfd_elf_make_section_from_shdr (abfd, hdr, name, shindex))
    return false;

  return true;
}

/* Process any AArch64-specific program segment types.  */

static bool
elf32_aarch64_section_from_phdr (bfd *abfd ATTRIBUTE_UNUSED,
				 Elf_Internal_Phdr *hdr,
				 int hdr_index ATTRIBUTE_UNUSED,
				 const char *name ATTRIBUTE_UNUSED)
{
  /* Right now we only handle the PT_AARCH64_MEMTAG_MTE segment type.  */
  if (hdr == NULL || hdr->p_type != PT_AARCH64_MEMTAG_MTE)
    return false;

  if (hdr->p_filesz > 0)
    {
      /* Sections created from memory tag p_type's are always named
	 "memtag".  This makes it easier for tools (for example, GDB)
	 to find them.  */
      asection *newsect = bfd_make_section_anyway (abfd, "memtag");

      if (newsect == NULL)
	return false;

      unsigned int opb = bfd_octets_per_byte (abfd, NULL);

      /* p_vaddr holds the original start address of the tagged memory
	 range.  */
      newsect->vma = hdr->p_vaddr / opb;

      /* p_filesz holds the storage size of the packed tags.  */
      newsect->size = hdr->p_filesz;
      newsect->filepos = hdr->p_offset;

      /* p_memsz holds the size of the memory range that contains tags.  The
	 section's rawsize field is reused for this purpose.  */
      newsect->rawsize = hdr->p_memsz;

      /* Make sure the section's flags has SEC_HAS_CONTENTS set, otherwise
	 BFD will return all zeroes when attempting to get contents from this
	 section.  */
      newsect->flags |= SEC_HAS_CONTENTS;
    }

  return true;
}

/* Implements the bfd_elf_modify_headers hook for aarch64.  */

static bool
elf32_aarch64_modify_headers (bfd *abfd,
			      struct bfd_link_info *info)
{
  struct elf_segment_map *m;
  Elf_Internal_Phdr *p;

  for (m = elf_seg_map (abfd); m != NULL; m = m->next)
    {
      /* We are only interested in the memory tag segment that will be dumped
	 to a core file.  If we have no memory tags or this isn't a core file we
	 are dealing with, just skip this segment.  */
      if (m->p_type != PT_AARCH64_MEMTAG_MTE
	  || bfd_get_format (abfd) != bfd_core)
	continue;

      /* For memory tag segments in core files, the size of the file contents
	 is smaller than the size of the memory range.  Adjust the memory size
	 accordingly.  The real memory size is held in the section's rawsize
	 field.  */
      if (m->count > 0)
	{
	  p = elf_tdata (abfd)->phdr;
	  p += m->idx;
	  p->p_memsz = m->sections[0]->rawsize;
	  p->p_flags = 0;
	  p->p_paddr = 0;
	  p->p_align = 0;
	}
    }

  /* Give the generic code a chance to handle the headers.  */
  return _bfd_elf_modify_headers (abfd, info);
}


typedef struct
{
  void *finfo;
  struct bfd_link_info *info;
  asection *sec;
  int sec_shndx;
  int (*func) (void *, const char *, Elf_Internal_Sym *,
	       asection *, struct elf_link_hash_entry *);
} output_arch_syminfo;

enum map_symbol_type
{
  AARCH64_MAP_INSN,
  AARCH64_MAP_DATA
};


/* Output a single mapping symbol.  */

static bool
elf32_aarch64_output_map_sym (output_arch_syminfo *osi,
			      enum map_symbol_type type, bfd_vma offset)
{
  static const char *names[2] = { "$x", "$d" };
  Elf_Internal_Sym sym;

  sym.st_value = (osi->sec->output_section->vma
		  + osi->sec->output_offset + offset);
  sym.st_size = 0;
  sym.st_other = 0;
  sym.st_info = ELF_ST_INFO (STB_LOCAL, STT_NOTYPE);
  sym.st_shndx = osi->sec_shndx;
  return osi->func (osi->finfo, names[type], &sym, osi->sec, NULL) == 1;
}

/* Output a single local symbol for a generated stub.  */

static bool
elf32_aarch64_output_stub_sym (output_arch_syminfo *osi, const char *name,
			       bfd_vma offset, bfd_vma size)
{
  Elf_Internal_Sym sym;

  sym.st_value = (osi->sec->output_section->vma
		  + osi->sec->output_offset + offset);
  sym.st_size = size;
  sym.st_other = 0;
  sym.st_info = ELF_ST_INFO (STB_LOCAL, STT_FUNC);
  sym.st_shndx = osi->sec_shndx;
  return osi->func (osi->finfo, name, &sym, osi->sec, NULL) == 1;
}

static bool
aarch64_map_one_stub (struct bfd_hash_entry *gen_entry, void *in_arg)
{
  struct elf_aarch64_stub_hash_entry *stub_entry;
  asection *stub_sec;
  bfd_vma addr;
  char *stub_name;
  output_arch_syminfo *osi;

  /* Massage our args to the form they really have.  */
  stub_entry = (struct elf_aarch64_stub_hash_entry *) gen_entry;
  osi = (output_arch_syminfo *) in_arg;

  stub_sec = stub_entry->stub_sec;

  /* Ensure this stub is attached to the current section being
     processed.  */
  if (stub_sec != osi->sec)
    return true;

  addr = (bfd_vma) stub_entry->stub_offset;

  stub_name = stub_entry->output_name;

  switch (stub_entry->stub_type)
    {
    case aarch64_stub_adrp_branch:
      if (!elf32_aarch64_output_stub_sym (osi, stub_name, addr,
					  sizeof (aarch64_adrp_branch_stub)))
	return false;
      if (!elf32_aarch64_output_map_sym (osi, AARCH64_MAP_INSN, addr))
	return false;
      break;
    case aarch64_stub_long_branch:
      if (!elf32_aarch64_output_stub_sym
	  (osi, stub_name, addr, sizeof (aarch64_long_branch_stub)))
	return false;
      if (!elf32_aarch64_output_map_sym (osi, AARCH64_MAP_INSN, addr))
	return false;
      if (!elf32_aarch64_output_map_sym (osi, AARCH64_MAP_DATA, addr + 16))
	return false;
      break;
    case aarch64_stub_bti_direct_branch:
      if (!elf32_aarch64_output_stub_sym (osi, stub_name, addr,
	  sizeof (aarch64_bti_direct_branch_stub)))
	return false;
      if (!elf32_aarch64_output_map_sym (osi, AARCH64_MAP_INSN, addr))
	return false;
      break;
    case aarch64_stub_erratum_835769_veneer:
      if (!elf32_aarch64_output_stub_sym (osi, stub_name, addr,
					  sizeof (aarch64_erratum_835769_stub)))
	return false;
      if (!elf32_aarch64_output_map_sym (osi, AARCH64_MAP_INSN, addr))
	return false;
      break;
    case aarch64_stub_erratum_843419_veneer:
      if (!elf32_aarch64_output_stub_sym (osi, stub_name, addr,
					  sizeof (aarch64_erratum_843419_stub)))
	return false;
      if (!elf32_aarch64_output_map_sym (osi, AARCH64_MAP_INSN, addr))
	return false;
      break;
    case aarch64_stub_none:
      break;

    default:
      abort ();
    }

  return true;
}

/* Output mapping symbols for linker generated sections.  */

static bool
elf32_aarch64_output_arch_local_syms (bfd *output_bfd,
				      struct bfd_link_info *info,
				      void *finfo,
				      int (*func) (void *, const char *,
						   Elf_Internal_Sym *,
						   asection *,
						   struct elf_link_hash_entry
						   *))
{
  output_arch_syminfo osi;
  struct elf_aarch64_link_hash_table *htab;

  if (info->strip == strip_all
      && !info->emitrelocations
      && !bfd_link_relocatable (info))
    return true;

  htab = elf_aarch64_hash_table (info);

  osi.finfo = finfo;
  osi.info = info;
  osi.func = func;

  /* Long calls stubs.  */
  if (htab->stub_bfd && htab->stub_bfd->sections)
    {
      asection *stub_sec;

      for (stub_sec = htab->stub_bfd->sections;
	   stub_sec != NULL; stub_sec = stub_sec->next)
	{
	  /* Ignore non-stub sections.  */
	  if (!strstr (stub_sec->name, STUB_SUFFIX))
	    continue;

	  osi.sec = stub_sec;

	  osi.sec_shndx = _bfd_elf_section_from_bfd_section
	    (output_bfd, osi.sec->output_section);

	  /* The first instruction in a stub is always a branch.  */
	  if (!elf32_aarch64_output_map_sym (&osi, AARCH64_MAP_INSN, 0))
	    return false;

	  bfd_hash_traverse (&htab->stub_hash_table, aarch64_map_one_stub,
			     &osi);
	}
    }

  /* Finally, output mapping symbols for the PLT.  */
  if (!htab->root.splt || htab->root.splt->size == 0)
    return true;

  osi.sec_shndx = _bfd_elf_section_from_bfd_section
    (output_bfd, htab->root.splt->output_section);
  osi.sec = htab->root.splt;

  elf32_aarch64_output_map_sym (&osi, AARCH64_MAP_INSN, 0);

  return true;

}

/* Allocate target specific section data.  */

static bool
elf32_aarch64_new_section_hook (bfd *abfd, asection *sec)
{
  _aarch64_elf_section_data *sdata;

  sdata = bfd_zalloc (abfd, sizeof (*sdata));
  if (sdata == NULL)
    return false;
  sec->used_by_bfd = sdata;

  return _bfd_elf_new_section_hook (abfd, sec);
}


/* Create dynamic sections. This is different from the ARM backend in that
   the got, plt, gotplt and their relocation sections are all created in the
   standard part of the bfd elf backend.  */

static bool
elf32_aarch64_create_dynamic_sections (bfd *dynobj,
				       struct bfd_link_info *info)
{
  /* We need to create .got section.  */
  if (!aarch64_elf_create_got_section (dynobj, info))
    return false;

  return _bfd_elf_create_dynamic_sections (dynobj, info);
}


/* Allocate space in .plt, .got and associated reloc sections for
   dynamic relocs.  */

static bool
elf32_aarch64_allocate_dynrelocs (struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info;
  struct elf_aarch64_link_hash_table *htab;
  struct elf_aarch64_link_hash_entry *eh;
  struct elf_dyn_relocs *p;

  /* An example of a bfd_link_hash_indirect symbol is versioned
     symbol. For example: __gxx_personality_v0(bfd_link_hash_indirect)
     -> __gxx_personality_v0(bfd_link_hash_defined)

     There is no need to process bfd_link_hash_indirect symbols here
     because we will also be presented with the concrete instance of
     the symbol and elf32_aarch64_copy_indirect_symbol () will have been
     called to copy all relevant data from the generic to the concrete
     symbol instance.  */
  if (h->root.type == bfd_link_hash_indirect)
    return true;

  if (h->root.type == bfd_link_hash_warning)
    h = (struct elf_link_hash_entry *) h->root.u.i.link;

  info = (struct bfd_link_info *) inf;
  htab = elf_aarch64_hash_table (info);

  /* Since STT_GNU_IFUNC symbol must go through PLT, we handle it
     here if it is defined and referenced in a non-shared object.  */
  if (h->type == STT_GNU_IFUNC
      && h->def_regular)
    return true;
  else if (htab->root.dynamic_sections_created && h->plt.refcount > 0)
    {
      /* Make sure this symbol is output as a dynamic symbol.
	 Undefined weak syms won't yet be marked as dynamic.  */
      if (h->dynindx == -1 && !h->forced_local
	  && h->root.type == bfd_link_hash_undefweak)
	{
	  if (!bfd_elf_link_record_dynamic_symbol (info, h))
	    return false;
	}

      if (bfd_link_pic (info) || WILL_CALL_FINISH_DYNAMIC_SYMBOL (1, 0, h))
	{
	  asection *s = htab->root.splt;

	  /* If this is the first .plt entry, make room for the special
	     first entry.  */
	  if (s->size == 0)
	    s->size += htab->plt_header_size;

	  h->plt.offset = s->size;

	  /* If this symbol is not defined in a regular file, and we are
	     not generating a shared library, then set the symbol to this
	     location in the .plt.  This is required to make function
	     pointers compare as equal between the normal executable and
	     the shared library.  */
	  if (!bfd_link_pic (info) && !h->def_regular)
	    {
	      h->root.u.def.section = s;
	      h->root.u.def.value = h->plt.offset;
	    }

	  /* Make room for this entry. For now we only create the
	     small model PLT entries. We later need to find a way
	     of relaxing into these from the large model PLT entries.  */
	  s->size += htab->plt_entry_size;

	  /* We also need to make an entry in the .got.plt section, which
	     will be placed in the .got section by the linker script.  */
	  htab->root.sgotplt->size += GOT_ENTRY_SIZE;

	  /* We also need to make an entry in the .rela.plt section.  */
	  htab->root.srelplt->size += RELOC_SIZE (htab);

	  /* We need to ensure that all GOT entries that serve the PLT
	     are consecutive with the special GOT slots [0] [1] and
	     [2]. Any addtional relocations, such as
	     R_AARCH64_TLSDESC, must be placed after the PLT related
	     entries.  We abuse the reloc_count such that during
	     sizing we adjust reloc_count to indicate the number of
	     PLT related reserved entries.  In subsequent phases when
	     filling in the contents of the reloc entries, PLT related
	     entries are placed by computing their PLT index (0
	     .. reloc_count). While other none PLT relocs are placed
	     at the slot indicated by reloc_count and reloc_count is
	     updated.  */

	  htab->root.srelplt->reloc_count++;

	  /* Mark the DSO in case R_<CLS>_JUMP_SLOT relocs against
	     variant PCS symbols are present.  */
	  if (h->other & STO_AARCH64_VARIANT_PCS)
	    htab->variant_pcs = 1;

	}
      else
	{
	  h->plt.offset = (bfd_vma) - 1;
	  h->needs_plt = 0;
	}
    }
  else
    {
      h->plt.offset = (bfd_vma) - 1;
      h->needs_plt = 0;
    }

  eh = (struct elf_aarch64_link_hash_entry *) h;
  eh->tlsdesc_got_jump_table_offset = (bfd_vma) - 1;

  if (h->got.refcount > 0)
    {
      bool dyn;
      unsigned got_type = elf_aarch64_hash_entry (h)->got_type;

      h->got.offset = (bfd_vma) - 1;

      dyn = htab->root.dynamic_sections_created;

      /* Make sure this symbol is output as a dynamic symbol.
	 Undefined weak syms won't yet be marked as dynamic.  */
      if (dyn && h->dynindx == -1 && !h->forced_local
	  && h->root.type == bfd_link_hash_undefweak)
	{
	  if (!bfd_elf_link_record_dynamic_symbol (info, h))
	    return false;
	}

      if (got_type == GOT_UNKNOWN)
	{
	}
      else if (got_type == GOT_NORMAL)
	{
	  h->got.offset = htab->root.sgot->size;
	  htab->root.sgot->size += GOT_ENTRY_SIZE;
	  if ((ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
	       || h->root.type != bfd_link_hash_undefweak)
	      && (bfd_link_pic (info)
		  || WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, 0, h))
	      /* Undefined weak symbol in static PIE resolves to 0 without
		 any dynamic relocations.  */
	      && !UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
	    {
	      htab->root.srelgot->size += RELOC_SIZE (htab);
	    }
	}
      else
	{
	  int indx;
	  if (got_type & GOT_TLSDESC_GD)
	    {
	      eh->tlsdesc_got_jump_table_offset =
		(htab->root.sgotplt->size
		 - aarch64_compute_jump_table_size (htab));
	      htab->root.sgotplt->size += GOT_ENTRY_SIZE * 2;
	      h->got.offset = (bfd_vma) - 2;
	    }

	  if (got_type & GOT_TLS_GD)
	    {
	      h->got.offset = htab->root.sgot->size;
	      htab->root.sgot->size += GOT_ENTRY_SIZE * 2;
	    }

	  if (got_type & GOT_TLS_IE)
	    {
	      h->got.offset = htab->root.sgot->size;
	      htab->root.sgot->size += GOT_ENTRY_SIZE;
	    }

	  indx = h && h->dynindx != -1 ? h->dynindx : 0;
	  if ((ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
	       || h->root.type != bfd_link_hash_undefweak)
	      && (!bfd_link_executable (info)
		  || indx != 0
		  || WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, 0, h)))
	    {
	      if (got_type & GOT_TLSDESC_GD)
		{
		  htab->root.srelplt->size += RELOC_SIZE (htab);
		  /* Note reloc_count not incremented here!  We have
		     already adjusted reloc_count for this relocation
		     type.  */

		  /* TLSDESC PLT is now needed, but not yet determined.  */
		  htab->root.tlsdesc_plt = (bfd_vma) - 1;
		}

	      if (got_type & GOT_TLS_GD)
		htab->root.srelgot->size += RELOC_SIZE (htab) * 2;

	      if (got_type & GOT_TLS_IE)
		htab->root.srelgot->size += RELOC_SIZE (htab);
	    }
	}
    }
  else
    {
      h->got.offset = (bfd_vma) - 1;
    }

  if (h->dyn_relocs == NULL)
    return true;

  for (p = h->dyn_relocs; p != NULL; p = p->next)
    if (eh->def_protected)
      {
	/* Disallow copy relocations against protected symbol.  */
	asection *s = p->sec->output_section;
	if (s != NULL && (s->flags & SEC_READONLY) != 0)
	  {
	    info->callbacks->fatal
		/* xgettext:c-format */
		(_ ("%P: %pB: copy relocation against non-copyable "
		    "protected symbol `%s'\n"),
		 p->sec->owner, h->root.root.string);
	    return false;
	  }
      }

  /* In the shared -Bsymbolic case, discard space allocated for
     dynamic pc-relative relocs against symbols which turn out to be
     defined in regular objects.  For the normal shared case, discard
     space for pc-relative relocs that have become local due to symbol
     visibility changes.  */

  if (bfd_link_pic (info))
    {
      /* Relocs that use pc_count are those that appear on a call
	 insn, or certain REL relocs that can generated via assembly.
	 We want calls to protected symbols to resolve directly to the
	 function rather than going via the plt.  If people want
	 function pointer comparisons to work as expected then they
	 should avoid writing weird assembly.  */
      if (SYMBOL_CALLS_LOCAL (info, h))
	{
	  struct elf_dyn_relocs **pp;

	  for (pp = &h->dyn_relocs; (p = *pp) != NULL;)
	    {
	      p->count -= p->pc_count;
	      p->pc_count = 0;
	      if (p->count == 0)
		*pp = p->next;
	      else
		pp = &p->next;
	    }
	}

      /* Also discard relocs on undefined weak syms with non-default
	 visibility.  */
      if (h->dyn_relocs != NULL && h->root.type == bfd_link_hash_undefweak)
	{
	  if (ELF_ST_VISIBILITY (h->other) != STV_DEFAULT
	      || UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
	    h->dyn_relocs = NULL;

	  /* Make sure undefined weak symbols are output as a dynamic
	     symbol in PIEs.  */
	  else if (h->dynindx == -1
		   && !h->forced_local
		   && h->root.type == bfd_link_hash_undefweak
		   && !bfd_elf_link_record_dynamic_symbol (info, h))
	    return false;
	}

    }
  else if (ELIMINATE_COPY_RELOCS)
    {
      /* For the non-shared case, discard space for relocs against
	 symbols which turn out to need copy relocs or are not
	 dynamic.  */

      if (!h->non_got_ref
	  && ((h->def_dynamic
	       && !h->def_regular)
	      || (htab->root.dynamic_sections_created
		  && (h->root.type == bfd_link_hash_undefweak
		      || h->root.type == bfd_link_hash_undefined))))
	{
	  /* Make sure this symbol is output as a dynamic symbol.
	     Undefined weak syms won't yet be marked as dynamic.  */
	  if (h->dynindx == -1
	      && !h->forced_local
	      && h->root.type == bfd_link_hash_undefweak
	      && !bfd_elf_link_record_dynamic_symbol (info, h))
	    return false;

	  /* If that succeeded, we know we'll be keeping all the
	     relocs.  */
	  if (h->dynindx != -1)
	    goto keep;
	}

      h->dyn_relocs = NULL;

    keep:;
    }

  /* Finally, allocate space.  */
  for (p = h->dyn_relocs; p != NULL; p = p->next)
    {
      asection *sreloc;

      sreloc = elf_section_data (p->sec)->sreloc;

      BFD_ASSERT (sreloc != NULL);

      sreloc->size += p->count * RELOC_SIZE (htab);
    }

  return true;
}

/* Allocate space in .plt, .got and associated reloc sections for
   ifunc dynamic relocs.  */

static bool
elf32_aarch64_allocate_ifunc_dynrelocs (struct elf_link_hash_entry *h,
					void *inf)
{
  struct bfd_link_info *info;
  struct elf_aarch64_link_hash_table *htab;

  /* An example of a bfd_link_hash_indirect symbol is versioned
     symbol. For example: __gxx_personality_v0(bfd_link_hash_indirect)
     -> __gxx_personality_v0(bfd_link_hash_defined)

     There is no need to process bfd_link_hash_indirect symbols here
     because we will also be presented with the concrete instance of
     the symbol and elf32_aarch64_copy_indirect_symbol () will have been
     called to copy all relevant data from the generic to the concrete
     symbol instance.  */
  if (h->root.type == bfd_link_hash_indirect)
    return true;

  if (h->root.type == bfd_link_hash_warning)
    h = (struct elf_link_hash_entry *) h->root.u.i.link;

  info = (struct bfd_link_info *) inf;
  htab = elf_aarch64_hash_table (info);

  /* Since STT_GNU_IFUNC symbol must go through PLT, we handle it
     here if it is defined and referenced in a non-shared object.  */
  if (h->type == STT_GNU_IFUNC
      && h->def_regular)
    return _bfd_elf_allocate_ifunc_dyn_relocs (info, h,
					       &h->dyn_relocs,
					       htab->plt_entry_size,
					       htab->plt_header_size,
					       GOT_ENTRY_SIZE,
					       false);
  return true;
}

/* Allocate space in .plt, .got and associated reloc sections for
   local ifunc dynamic relocs.  */

static int
elf32_aarch64_allocate_local_ifunc_dynrelocs (void **slot, void *inf)
{
  struct elf_link_hash_entry *h
    = (struct elf_link_hash_entry *) *slot;

  if (h->type != STT_GNU_IFUNC
      || !h->def_regular
      || !h->ref_regular
      || !h->forced_local
      || h->root.type != bfd_link_hash_defined)
    abort ();

  return elf32_aarch64_allocate_ifunc_dynrelocs (h, inf);
}

/* Record a relative relocation that will be emitted packed (DT_RELR).
   Called after relocation sections are sized, so undo the size accounting
   for this relocation.  */

static bool
record_relr (struct elf_aarch64_link_hash_table *htab, asection *sec,
	     bfd_vma off, asection *sreloc)
{
  /* Undo the relocation section size accounting.  */
  BFD_ASSERT (sreloc->size >= RELOC_SIZE (htab));
  sreloc->size -= RELOC_SIZE (htab);
  /* The packing format uses the last bit of the address so that
     must be aligned.  We don't pack relocations that may not be
     aligned even though the final output address could end up
     aligned, to avoid complex sizing logic for a rare case.  */
  BFD_ASSERT (off % 2 == 0 && sec->alignment_power > 0);
  if (htab->relr_count >= htab->relr_alloc)
    {
      if (htab->relr_alloc == 0)
	htab->relr_alloc = 4096;
      else
	htab->relr_alloc *= 2;
      htab->relr = bfd_realloc (htab->relr,
				htab->relr_alloc * sizeof (*htab->relr));
      if (htab->relr == NULL)
	return false;
    }
  htab->relr[htab->relr_count].sec = sec;
  htab->relr[htab->relr_count].off = off;
  htab->relr_count++;
  return true;
}

/* Follow elf32_aarch64_allocate_dynrelocs, but only record relative
   relocations against the GOT and undo their previous size accounting.  */

static bool
record_relr_dyn_got_relocs (struct elf_link_hash_entry *h, void *inf)
{

  if (h->root.type == bfd_link_hash_indirect)
    return true;
  if (h->root.type == bfd_link_hash_warning)
    h = (struct elf_link_hash_entry *) h->root.u.i.link;
  if (h->type == STT_GNU_IFUNC && h->def_regular)
    return true;
  if (h->got.refcount <= 0)
    return true;
  if (elf_aarch64_hash_entry (h)->got_type != GOT_NORMAL)
    return true;

  struct bfd_link_info *info = (struct bfd_link_info *) inf;
  struct elf_aarch64_link_hash_table *htab = elf_aarch64_hash_table (info);

  if ((ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
       || h->root.type != bfd_link_hash_undefweak)
      && bfd_link_pic (info)
      /* Undefined weak symbol in static PIE resolves to 0 without
	 any dynamic relocations.  */
      && !UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
    {
      bool relative_reloc = SYMBOL_REFERENCES_LOCAL (info, h)
			    && !bfd_is_abs_symbol (&h->root);
      if (relative_reloc)
	if (!record_relr (htab, htab->root.sgot, h->got.offset,
			  htab->root.srelgot))
	  return false;
    }
  return true;
}

/* Record packed relative relocs against the GOT for local symbols.
   Undo the size accounting of elf32_aarch64_late_size_sections.  */

static bool
record_relr_local_got_relocs (bfd *input_bfd, struct bfd_link_info *info)
{
  struct elf_aarch64_local_symbol *locals;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_aarch64_link_hash_table *htab;

  if (!bfd_link_pic (info))
    return true;

  locals = elf_aarch64_locals (input_bfd);
  if (locals == NULL)
    return true;

  symtab_hdr = &elf_symtab_hdr (input_bfd);
  htab = elf_aarch64_hash_table (info);
  for (unsigned int i = 0; i < symtab_hdr->sh_info; i++)
    {
      bfd_vma off = locals[i].got_offset;
      if (locals[i].got_refcount <= 0)
	continue;
      if ((locals[i].got_type & GOT_NORMAL) == 0)
	continue;

      /* FIXME: If the local symbol is in SHN_ABS then emitting
	 a relative relocation is not correct, but it seems to
	 be wrong in elf32_aarch64_final_link_relocate too.  */
      if (!record_relr (htab, htab->root.sgot, off, htab->root.srelgot))
	return false;
    }
  return true;
}

/* Follows the logic of elf32_aarch64_relocate_section to decide which
   relocations will become relative and possible to pack.  Ignore
   relocations against the GOT, those are handled separately per-symbol.
   Undo the size accounting of the packed relocations and record them
   so the relr section can be sized later.  */

static bool
record_relr_non_got_relocs (bfd *input_bfd, struct bfd_link_info *info,
			    asection *sec)
{
  const Elf_Internal_Rela *relocs;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  asection *sreloc;
  struct elf_aarch64_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;

  if (sec->reloc_count == 0)
    return true;
  if ((sec->flags & (SEC_RELOC | SEC_ALLOC | SEC_DEBUGGING))
      != (SEC_RELOC | SEC_ALLOC))
    return true;
  if (sec->alignment_power == 0)
    return true;
  if (discarded_section (sec))
    return true;
  sreloc = elf_section_data (sec)->sreloc;
  if (sreloc == NULL)
    return true;
  htab = elf_aarch64_hash_table (info);
  symtab_hdr = &elf_symtab_hdr (input_bfd);
  sym_hashes = elf_sym_hashes (input_bfd);
  relocs = _bfd_elf_link_info_read_relocs (input_bfd, info, sec, NULL, NULL,
					   info->keep_memory);
  BFD_ASSERT (relocs != NULL);
  rel_end = relocs + sec->reloc_count;
  for (rel = relocs; rel < rel_end; rel++)
    {
      unsigned int r_symndx = ELF32_R_SYM (rel->r_info);
      unsigned int r_type = ELF32_R_TYPE (rel->r_info);

      bfd_reloc_code_real_type bfd_r_type
	= elf32_aarch64_bfd_reloc_from_type (input_bfd, r_type);
      /* Handle relocs that can become R_AARCH64_RELATIVE,
	 but not ones against the GOT as those are handled
	 separately per-symbol.  */
      if (bfd_r_type != BFD_RELOC_AARCH64_32)
	continue;
      /* Can only pack relocation against an aligned address.  */
      if (rel->r_offset % 2 != 0)
	continue;

      struct elf_link_hash_entry *h = NULL;
      asection *def_sec = NULL;
      bool resolved_to_zero = false;
      if (r_symndx < symtab_hdr->sh_info)
	{
	  /* A local symbol.  */
	  Elf_Internal_Sym *isym;
	  isym = bfd_sym_from_r_symndx (&htab->root.sym_cache,
					input_bfd, r_symndx);
	  BFD_ASSERT (isym != NULL);
	  if (ELF_ST_TYPE (isym->st_info) == STT_GNU_IFUNC)
	    continue;
	  def_sec = bfd_section_from_elf_index (input_bfd, isym->st_shndx);
	}
      else
	{
	  h = sym_hashes[r_symndx - symtab_hdr->sh_info];
	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;

	  /* Filter out symbols that cannot have a relative reloc.  */
	  if (h->dyn_relocs == NULL)
	    continue;
	  if (bfd_is_abs_symbol (&h->root))
	    continue;
	  if (h->type == STT_GNU_IFUNC)
	    continue;

	  if (h->root.type == bfd_link_hash_defined
	      || h->root.type == bfd_link_hash_defweak)
	    def_sec = h->root.u.def.section;
	  resolved_to_zero = UNDEFWEAK_NO_DYNAMIC_RELOC (info, h);
	}
      if (def_sec != NULL && discarded_section (def_sec))
	continue;
      /* Same logic as in elf32_aarch64_final_link_relocate.
	 Except conditionals trimmed that cannot result a reltive reloc.  */
      if (bfd_link_pic (info)
	  && (h == NULL
	      || (ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
		  && !resolved_to_zero)
	      || h->root.type != bfd_link_hash_undefweak))
	{
	  if (h != NULL
	      && h->dynindx != -1
	      && (!(bfd_link_pie (info) || SYMBOLIC_BIND (info, h))
		  || !h->def_regular))
	    continue;
	  if (!record_relr (htab, sec, rel->r_offset, sreloc))
	    return false;
	}
    }
  return true;
}

static int
cmp_relr_addr (const void *p, const void *q)
{
  const bfd_vma *a = p;
  const bfd_vma *b = q;
  return *a < *b ? -1 : *a > *b ? 1 : 0;
}

/* Produce a malloc'd sorted array of reloc addresses in htab->relr_sorted.
   Returns false on allocation failure.  */

static bool
sort_relr (struct bfd_link_info *info,
	   struct elf_aarch64_link_hash_table *htab)
{
  if (htab->relr_count == 0)
    return true;

  bfd_vma *addr = htab->relr_sorted;
  if (addr == NULL)
    {
      addr = bfd_malloc (htab->relr_count * sizeof (*addr));
      if (addr == NULL)
	return false;
      htab->relr_sorted = addr;
    }

  for (bfd_size_type i = 0; i < htab->relr_count; i++)
    {
      bfd_vma off = _bfd_elf_section_offset (info->output_bfd, info,
					     htab->relr[i].sec,
					     htab->relr[i].off);
      addr[i] = htab->relr[i].sec->output_section->vma
		+ htab->relr[i].sec->output_offset
		+ off;
    }
  qsort (addr, htab->relr_count, sizeof (*addr), cmp_relr_addr);
  return true;
}

/* Size of a relr entry and a relocated location.  */
#define RELR_SZ (ARCH_SIZE / 8)
/* Number of consecutive locations a relr bitmap entry references.  */
#define RELR_N (ARCH_SIZE - 1)

/* Size .relr.dyn whenever the layout changes, the number of packed
   relocs are unchanged but the packed representation can.  */

bool
elf32_aarch64_size_relative_relocs (struct bfd_link_info *info,
				   bool *need_layout)
{
  struct elf_aarch64_link_hash_table *htab = elf_aarch64_hash_table (info);
  asection *srelrdyn = htab->root.srelrdyn;
  *need_layout = false;

  if (!sort_relr (info, htab))
    return false;
  bfd_vma *addr = htab->relr_sorted;

  BFD_ASSERT (srelrdyn != NULL);
  bfd_size_type oldsize = srelrdyn->size;
  srelrdyn->size = 0;
  for (bfd_size_type i = 0; i < htab->relr_count; )
    {
      bfd_vma base = addr[i];
      i++;
      srelrdyn->size += RELR_SZ;
      base += RELR_SZ;
      for (;;)
	{
	  bfd_size_type start_i = i;
	  while (i < htab->relr_count
		 && addr[i] - base < RELR_N * RELR_SZ
		 && (addr[i] - base) % RELR_SZ == 0)
	    i++;
	  if (i == start_i)
	    break;
	  srelrdyn->size += RELR_SZ;
	  base += RELR_N * RELR_SZ;
	}
    }
  if (srelrdyn->size != oldsize)
    {
      *need_layout = true;
      /* Stop after a few iterations in case the layout does not converge,
	 we can do this when the size would shrink.  */
      if (htab->relr_layout_iter++ > 5 && srelrdyn->size < oldsize)
	{
	  srelrdyn->size = oldsize;
	  *need_layout = false;
	}
    }
  return true;
}

/* Emit the .relr.dyn section after it is sized and the layout is fixed.  */

bool
elf32_aarch64_finish_relative_relocs (struct bfd_link_info *info)
{
  struct elf_aarch64_link_hash_table *htab = elf_aarch64_hash_table (info);
  asection *srelrdyn = htab->root.srelrdyn;
  bfd *dynobj = htab->root.dynobj;

  if (srelrdyn == NULL || srelrdyn->size == 0)
    return true;
  srelrdyn->contents = bfd_alloc (dynobj, srelrdyn->size);
  if (srelrdyn->contents == NULL)
    return false;
  srelrdyn->alloced = 1;
  bfd_vma *addr = htab->relr_sorted;
  bfd_byte *loc = srelrdyn->contents;
  for (bfd_size_type i = 0; i < htab->relr_count; )
    {
      bfd_vma base = addr[i];
      i++;
      bfd_put_32 (dynobj, base, loc);
      loc += RELR_SZ;
      base += RELR_SZ;
      for (;;)
	{
	  bfd_vma bits = 0;
	  while (i < htab->relr_count)
	    {
	      bfd_vma delta = addr[i] - base;
	      if (delta >= RELR_N * RELR_SZ || delta % RELR_SZ != 0)
		break;
	      bits |= (bfd_vma) 1 << (delta / RELR_SZ);
	      i++;
	    }
	  if (bits == 0)
	    break;
	  bfd_put_32 (dynobj, (bits << 1) | 1, loc);
	  loc += RELR_SZ;
	  base += RELR_N * RELR_SZ;
	}
    }
  free (addr);
  htab->relr_sorted = NULL;
  /* Pad any excess with 1's, a do-nothing encoding.  */
  while (loc < srelrdyn->contents + srelrdyn->size)
    {
      bfd_put_32 (dynobj, 1, loc);
      loc += RELR_SZ;
    }
  return true;
}

/* This is the most important function of all . Innocuosly named
   though !  */

static bool
elf32_aarch64_late_size_sections (bfd *output_bfd ATTRIBUTE_UNUSED,
				  struct bfd_link_info *info)
{
  struct elf_aarch64_link_hash_table *htab;
  bfd *dynobj;
  asection *s;
  bool relocs;
  bfd *ibfd;

  htab = elf_aarch64_hash_table ((info));
  dynobj = htab->root.dynobj;

  if (dynobj == NULL)
    return true;

  if (htab->root.dynamic_sections_created)
    {
      if (bfd_link_executable (info) && !info->nointerp)
	{
	  s = htab->root.interp;
	  if (s == NULL)
	    abort ();
	  s->size = sizeof ELF_DYNAMIC_INTERPRETER;
	  s->contents = (unsigned char *) ELF_DYNAMIC_INTERPRETER;
	  s->alloced = 1;
	}
    }

  /* Set up .got offsets for local syms, and space for local dynamic
     relocs.  */
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      struct elf_aarch64_local_symbol *locals = NULL;
      Elf_Internal_Shdr *symtab_hdr;
      asection *srel;
      unsigned int i;

      if (!is_aarch64_elf (ibfd))
	continue;

      for (s = ibfd->sections; s != NULL; s = s->next)
	{
	  struct elf_dyn_relocs *p;

	  for (p = (struct elf_dyn_relocs *)
	       (elf_section_data (s)->local_dynrel); p != NULL; p = p->next)
	    {
	      if (discarded_section (p->sec))
		{
		  /* Input section has been discarded, either because
		     it is a copy of a linkonce section or due to
		     linker script /DISCARD/, so we'll be discarding
		     the relocs too.  */
		}
	      else if (p->count != 0)
		{
		  srel = elf_section_data (p->sec)->sreloc;
		  srel->size += p->count * RELOC_SIZE (htab);
		  if ((p->sec->output_section->flags & SEC_READONLY) != 0)
		    info->flags |= DF_TEXTREL;
		}
	    }
	}

      locals = elf_aarch64_locals (ibfd);
      if (!locals)
	continue;

      symtab_hdr = &elf_symtab_hdr (ibfd);
      srel = htab->root.srelgot;
      for (i = 0; i < symtab_hdr->sh_info; i++)
	{
	  locals[i].got_offset = (bfd_vma) - 1;
	  locals[i].tlsdesc_got_jump_table_offset = (bfd_vma) - 1;
	  if (locals[i].got_refcount > 0)
	    {
	      unsigned got_type = locals[i].got_type;
	      if (got_type & GOT_TLSDESC_GD)
		{
		  locals[i].tlsdesc_got_jump_table_offset =
		    (htab->root.sgotplt->size
		     - aarch64_compute_jump_table_size (htab));
		  htab->root.sgotplt->size += GOT_ENTRY_SIZE * 2;
		  locals[i].got_offset = (bfd_vma) - 2;
		}

	      if (got_type & GOT_TLS_GD)
		{
		  locals[i].got_offset = htab->root.sgot->size;
		  htab->root.sgot->size += GOT_ENTRY_SIZE * 2;
		}

	      if (got_type & GOT_TLS_IE
		  || got_type & GOT_NORMAL)
		{
		  locals[i].got_offset = htab->root.sgot->size;
		  htab->root.sgot->size += GOT_ENTRY_SIZE;
		}

	      if (got_type == GOT_UNKNOWN)
		{
		}

	      if (bfd_link_pic (info))
		{
		  if (got_type & GOT_TLSDESC_GD)
		    {
		      htab->root.srelplt->size += RELOC_SIZE (htab);
		      /* Note RELOC_COUNT not incremented here! */
		      htab->root.tlsdesc_plt = (bfd_vma) - 1;
		    }

		  if (got_type & GOT_TLS_GD)
		    htab->root.srelgot->size += RELOC_SIZE (htab) * 2;

		  if (got_type & GOT_TLS_IE
		      || got_type & GOT_NORMAL)
		    htab->root.srelgot->size += RELOC_SIZE (htab);
		}
	    }
	  else
	    {
	      locals[i].got_refcount = (bfd_vma) - 1;
	    }
	}
    }


  /* Allocate global sym .plt and .got entries, and space for global
     sym dynamic relocs.  */
  elf_link_hash_traverse (&htab->root, elf32_aarch64_allocate_dynrelocs,
			  info);

  /* Allocate global ifunc sym .plt and .got entries, and space for global
     ifunc sym dynamic relocs.  */
  elf_link_hash_traverse (&htab->root, elf32_aarch64_allocate_ifunc_dynrelocs,
			  info);

  /* Allocate .plt and .got entries, and space for local ifunc symbols.  */
  htab_traverse (htab->loc_hash_table,
		 elf32_aarch64_allocate_local_ifunc_dynrelocs,
		 info);

  /* For every jump slot reserved in the sgotplt, reloc_count is
     incremented.  However, when we reserve space for TLS descriptors,
     it's not incremented, so in order to compute the space reserved
     for them, it suffices to multiply the reloc count by the jump
     slot size.  */

  if (htab->root.srelplt)
    htab->sgotplt_jump_table_size = aarch64_compute_jump_table_size (htab);

  if (htab->root.tlsdesc_plt)
    {
      if (htab->root.splt->size == 0)
	htab->root.splt->size += htab->plt_header_size;

      /* If we're not using lazy TLS relocations, don't generate the
	 GOT and PLT entry required.  */
      if ((info->flags & DF_BIND_NOW))
	htab->root.tlsdesc_plt = 0;
      else
	{
	  htab->root.tlsdesc_plt = htab->root.splt->size;
	  htab->root.splt->size += htab->tlsdesc_plt_entry_size;

	  htab->root.tlsdesc_got = htab->root.sgot->size;
	  htab->root.sgot->size += GOT_ENTRY_SIZE;
	}
    }

  /* Record the relative relocations that will be packed and undo the
     size allocation for them in .rela.*. The size of .relr.dyn will be
     computed later iteratively since it depends on the final layout.  */
  if (info->enable_dt_relr && !bfd_link_relocatable (info))
    {
      elf_link_hash_traverse (&htab->root, record_relr_dyn_got_relocs, info);

      for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
	{
	  if (!is_aarch64_elf (ibfd))
	    continue;

	  for (s = ibfd->sections; s != NULL; s = s->next)
	    if (!record_relr_non_got_relocs (ibfd, info, s))
	      return false;

	  if (!record_relr_local_got_relocs (ibfd, info))
	    return false;
	}
    }

  /* Init mapping symbols information to use later to distingush between
     code and data while scanning for errata.  */
  if (htab->fix_erratum_835769 || htab->fix_erratum_843419)
    for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
      {
	if (!is_aarch64_elf (ibfd))
	  continue;
	bfd_elf32_aarch64_init_maps (ibfd);
      }

  /* We now have determined the sizes of the various dynamic sections.
     Allocate memory for them.  */
  relocs = false;
  for (s = dynobj->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
	continue;

      if (s == htab->root.splt
	  || s == htab->root.sgot
	  || s == htab->root.sgotplt
	  || s == htab->root.iplt
	  || s == htab->root.igotplt
	  || s == htab->root.sdynbss
	  || s == htab->root.sdynrelro)
	{
	  /* Strip this section if we don't need it; see the
	     comment below.  */
	}
      else if (startswith (bfd_section_name (s), ".rela"))
	{
	  if (s->size != 0 && s != htab->root.srelplt)
	    relocs = true;

	  /* We use the reloc_count field as a counter if we need
	     to copy relocs into the output file.  */
	  if (s != htab->root.srelplt)
	    s->reloc_count = 0;
	}
      else if (s == htab->root.srelrdyn)
	{
	  /* Remove .relr.dyn based on relr_count, not size, since
	     it is not sized yet.  */
	  if (htab->relr_count == 0)
	    s->flags |= SEC_EXCLUDE;
	  else
	    /* Force dynamic tags for relocs even if there are no
	       .rela* relocs, required for setting DT_TEXTREL.  */
	    relocs = true;
	  /* Allocate contents later.  */
	  continue;
	}
      else
	{
	  /* It's not one of our sections, so don't allocate space.  */
	  continue;
	}

      if (s->size == 0)
	{
	  /* If we don't need this section, strip it from the
	     output file.  This is mostly to handle .rela.bss and
	     .rela.plt.  We must create both sections in
	     create_dynamic_sections, because they must be created
	     before the linker maps input sections to output
	     sections.  The linker does that before
	     adjust_dynamic_symbol is called, and it is that
	     function which decides whether anything needs to go
	     into these sections.  */
	  s->flags |= SEC_EXCLUDE;
	  continue;
	}

      if ((s->flags & SEC_HAS_CONTENTS) == 0)
	continue;

      /* Allocate memory for the section contents.  We use bfd_zalloc
	 here in case unused entries are not reclaimed before the
	 section's contents are written out.  This should not happen,
	 but this way if it does, we get a R_AARCH64_NONE reloc instead
	 of garbage.  */
      s->contents = (bfd_byte *) bfd_zalloc (dynobj, s->size);
      if (s->contents == NULL)
	return false;
      s->alloced = 1;
    }

  if (htab->root.dynamic_sections_created)
    {
      /* Add some entries to the .dynamic section.  We fill in the
	 values later, in elf32_aarch64_finish_dynamic_sections, but we
	 must add the entries now so that we get the correct size for
	 the .dynamic section.  The DT_DEBUG entry is filled in by the
	 dynamic linker and used by the debugger.  */
#define add_dynamic_entry(TAG, VAL)			\
      _bfd_elf_add_dynamic_entry (info, TAG, VAL)

      if (!_bfd_elf_add_dynamic_tags (output_bfd, info, relocs))
	return false;

      if (htab->root.splt->size != 0)
	{
	  if (htab->variant_pcs
	      && !add_dynamic_entry (DT_AARCH64_VARIANT_PCS, 0))
	    return false;

	  aarch64_plt_type plt_type
	    = elf_aarch64_tdata (output_bfd)->sw_protections.plt_type;
	  if ((plt_type == PLT_BTI_PAC)
	      && (!add_dynamic_entry (DT_AARCH64_BTI_PLT, 0)
		  || !add_dynamic_entry (DT_AARCH64_PAC_PLT, 0)))
	    return false;

	  else if ((plt_type == PLT_BTI)
		   && !add_dynamic_entry (DT_AARCH64_BTI_PLT, 0))
	    return false;

	  else if ((plt_type == PLT_PAC)
		   && !add_dynamic_entry (DT_AARCH64_PAC_PLT, 0))
	    return false;
	}

      if (is_aarch64_elf (output_bfd)
	  && htab->memtag_opts.memtag_mode != AARCH64_MEMTAG_MODE_NONE
	  && !add_dynamic_entry (DT_AARCH64_MEMTAG_MODE,
				 htab->memtag_opts.memtag_mode == AARCH64_MEMTAG_MODE_ASYNC))
	return false;

      if (is_aarch64_elf (output_bfd)
	  && htab->memtag_opts.memtag_stack == 1
	  && !add_dynamic_entry (DT_AARCH64_MEMTAG_STACK,
				 htab->memtag_opts.memtag_stack == 1))
	return false;
    }

#undef add_dynamic_entry

  return true;
}

static inline void
elf_aarch64_update_plt_entry (bfd *output_bfd,
			      bfd_reloc_code_real_type r_type,
			      bfd_byte *plt_entry, bfd_vma value)
{
  reloc_howto_type *howto = elf32_aarch64_howto_from_bfd_reloc (r_type);

  /* FIXME: We should check the return value from this function call.  */
  (void) _bfd_aarch64_elf_put_addend (output_bfd, plt_entry, r_type, howto, value);
}

static void
elf32_aarch64_create_small_pltn_entry (struct elf_link_hash_entry *h,
				       struct elf_aarch64_link_hash_table
				       *htab, bfd *output_bfd,
				       struct bfd_link_info *info)
{
  bfd_byte *plt_entry;
  bfd_vma plt_index;
  bfd_vma got_offset;
  bfd_vma gotplt_entry_address;
  bfd_vma plt_entry_address;
  Elf_Internal_Rela rela;
  bfd_byte *loc;
  asection *plt, *gotplt, *relplt;

  /* When building a static executable, use .iplt, .igot.plt and
     .rela.iplt sections for STT_GNU_IFUNC symbols.  */
  if (htab->root.splt != NULL)
    {
      plt = htab->root.splt;
      gotplt = htab->root.sgotplt;
      relplt = htab->root.srelplt;
    }
  else
    {
      plt = htab->root.iplt;
      gotplt = htab->root.igotplt;
      relplt = htab->root.irelplt;
    }

  /* Get the index in the procedure linkage table which
     corresponds to this symbol.  This is the index of this symbol
     in all the symbols for which we are making plt entries.  The
     first entry in the procedure linkage table is reserved.

     Get the offset into the .got table of the entry that
     corresponds to this function.	Each .got entry is GOT_ENTRY_SIZE
     bytes. The first three are reserved for the dynamic linker.

     For static executables, we don't reserve anything.  */

  if (plt == htab->root.splt)
    {
      plt_index = (h->plt.offset - htab->plt_header_size) / htab->plt_entry_size;
      got_offset = (plt_index + 3) * GOT_ENTRY_SIZE;
    }
  else
    {
      plt_index = h->plt.offset / htab->plt_entry_size;
      got_offset = plt_index * GOT_ENTRY_SIZE;
    }

  plt_entry = plt->contents + h->plt.offset;
  plt_entry_address = plt->output_section->vma
    + plt->output_offset + h->plt.offset;
  gotplt_entry_address = gotplt->output_section->vma +
    gotplt->output_offset + got_offset;

  /* Copy in the boiler-plate for the PLTn entry.  */
  memcpy (plt_entry, htab->plt_entry, htab->plt_entry_size);

  /* Allow for any delta (such as a BTI instruction) before the common
     sequence.  */
  plt_entry += htab->plt_entry_delta;

  /* Fill in the top 21 bits for this: ADRP x16, PLT_GOT + n * 8.
     ADRP:   ((PG(S+A)-PG(P)) >> 12) & 0x1fffff */
  elf_aarch64_update_plt_entry (output_bfd, BFD_RELOC_AARCH64_ADR_HI21_PCREL,
				plt_entry,
				PG (gotplt_entry_address) -
				PG (plt_entry_address));

  /* Fill in the lo12 bits for the load from the pltgot.  */
  elf_aarch64_update_plt_entry (output_bfd, BFD_RELOC_AARCH64_LDST32_LO12,
				plt_entry + 4,
				PG_OFFSET (gotplt_entry_address));

  /* Fill in the lo12 bits for the add from the pltgot entry.  */
  elf_aarch64_update_plt_entry (output_bfd, BFD_RELOC_AARCH64_ADD_LO12,
				plt_entry + 8,
				PG_OFFSET (gotplt_entry_address));

  /* All the GOTPLT Entries are essentially initialized to PLT0.  */
  bfd_put_32 (output_bfd,
	      plt->output_section->vma + plt->output_offset,
	      gotplt->contents + got_offset);

  rela.r_offset = gotplt_entry_address;

  if (h->dynindx == -1
      || ((bfd_link_executable (info)
	   || ELF_ST_VISIBILITY (h->other) != STV_DEFAULT)
	  && h->def_regular
	  && h->type == STT_GNU_IFUNC))
    {
      /* If an STT_GNU_IFUNC symbol is locally defined, generate
	 R_AARCH64_IRELATIVE instead of R_AARCH64_JUMP_SLOT.  */
      rela.r_info = ELF32_R_INFO (0, AARCH64_R (IRELATIVE));
      rela.r_addend = (h->root.u.def.value
		       + h->root.u.def.section->output_section->vma
		       + h->root.u.def.section->output_offset);
    }
  else
    {
      /* Fill in the entry in the .rela.plt section.  */
      rela.r_info = ELF32_R_INFO (h->dynindx, AARCH64_R (JUMP_SLOT));
      rela.r_addend = 0;
    }

  /* Compute the relocation entry to used based on PLT index and do
     not adjust reloc_count. The reloc_count has already been adjusted
     to account for this entry.  */
  loc = relplt->contents + plt_index * RELOC_SIZE (htab);
  bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
}

/* Size sections even though they're not dynamic.  We use it to setup
   _TLS_MODULE_BASE_, if needed.  */

static bool
elf32_aarch64_early_size_sections (bfd *output_bfd,
				   struct bfd_link_info *info)
{
  asection *tls_sec;

  if (bfd_link_relocatable (info))
    return true;

  tls_sec = elf_hash_table (info)->tls_sec;

  if (tls_sec)
    {
      struct elf_link_hash_entry *tlsbase;

      tlsbase = elf_link_hash_lookup (elf_hash_table (info),
				      "_TLS_MODULE_BASE_", true, true, false);

      if (tlsbase)
	{
	  struct bfd_link_hash_entry *h = NULL;
	  const struct elf_backend_data *bed =
	    get_elf_backend_data (output_bfd);

	  if (!(_bfd_generic_link_add_one_symbol
		(info, output_bfd, "_TLS_MODULE_BASE_", BSF_LOCAL,
		 tls_sec, 0, NULL, false, bed->collect, &h)))
	    return false;

	  tlsbase->type = STT_TLS;
	  tlsbase = (struct elf_link_hash_entry *) h;
	  tlsbase->def_regular = 1;
	  tlsbase->other = STV_HIDDEN;
	  (*bed->elf_backend_hide_symbol) (info, tlsbase, true);
	}
    }

  return true;
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bool
elf32_aarch64_finish_dynamic_symbol (bfd *output_bfd,
				     struct bfd_link_info *info,
				     struct elf_link_hash_entry *h,
				     Elf_Internal_Sym *sym)
{
  struct elf_aarch64_link_hash_table *htab;
  htab = elf_aarch64_hash_table (info);

  if (h->plt.offset != (bfd_vma) - 1)
    {
      asection *plt, *gotplt, *relplt;

      /* This symbol has an entry in the procedure linkage table.  Set
	 it up.  */

      /* When building a static executable, use .iplt, .igot.plt and
	 .rela.iplt sections for STT_GNU_IFUNC symbols.  */
      if (htab->root.splt != NULL)
	{
	  plt = htab->root.splt;
	  gotplt = htab->root.sgotplt;
	  relplt = htab->root.srelplt;
	}
      else
	{
	  plt = htab->root.iplt;
	  gotplt = htab->root.igotplt;
	  relplt = htab->root.irelplt;
	}

      /* This symbol has an entry in the procedure linkage table.  Set
	 it up.	 */
      if ((h->dynindx == -1
	   && !((h->forced_local || bfd_link_executable (info))
		&& h->def_regular
		&& h->type == STT_GNU_IFUNC))
	  || plt == NULL
	  || gotplt == NULL
	  || relplt == NULL)
	abort ();

      elf32_aarch64_create_small_pltn_entry (h, htab, output_bfd, info);
      if (!h->def_regular)
	{
	  /* Mark the symbol as undefined, rather than as defined in
	     the .plt section.  */
	  sym->st_shndx = SHN_UNDEF;
	  /* If the symbol is weak we need to clear the value.
	     Otherwise, the PLT entry would provide a definition for
	     the symbol even if the symbol wasn't defined anywhere,
	     and so the symbol would never be NULL.  Leave the value if
	     there were any relocations where pointer equality matters
	     (this is a clue for the dynamic linker, to make function
	     pointer comparisons work between an application and shared
	     library).  */
	  if (!h->ref_regular_nonweak || !h->pointer_equality_needed)
	    sym->st_value = 0;
	}
    }

  if (h->got.offset != (bfd_vma) - 1
      && elf_aarch64_hash_entry (h)->got_type == GOT_NORMAL
      /* Undefined weak symbol in static PIE resolves to 0 without
	 any dynamic relocations.  */
      && !UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
    {
      Elf_Internal_Rela rela;
      bfd_byte *loc;

      /* This symbol has an entry in the global offset table.  Set it
	 up.  */
      if (htab->root.sgot == NULL || htab->root.srelgot == NULL)
	abort ();

      rela.r_offset = (htab->root.sgot->output_section->vma
		       + htab->root.sgot->output_offset
		       + (h->got.offset & ~(bfd_vma) 1));

      if (h->def_regular
	  && h->type == STT_GNU_IFUNC)
	{
	  if (bfd_link_pic (info))
	    {
	      /* Generate R_AARCH64_GLOB_DAT.  */
	      goto do_glob_dat;
	    }
	  else
	    {
	      asection *plt;

	      if (!h->pointer_equality_needed)
		abort ();

	      /* For non-shared object, we can't use .got.plt, which
		 contains the real function address if we need pointer
		 equality.  We load the GOT entry with the PLT entry.  */
	      plt = htab->root.splt ? htab->root.splt : htab->root.iplt;
	      bfd_put_32 (output_bfd, (plt->output_section->vma
				       + plt->output_offset
				       + h->plt.offset),
			  htab->root.sgot->contents
			  + (h->got.offset & ~(bfd_vma) 1));
	      return true;
	    }
	}
      else if (bfd_link_pic (info) && SYMBOL_REFERENCES_LOCAL (info, h))
	{
	  if (!(h->def_regular || ELF_COMMON_DEF_P (h)))
	    return false;
	  BFD_ASSERT ((h->got.offset & 1) != 0);
	  /* Don't emit relative relocs if they are packed.  */
	  if (info->enable_dt_relr)
	    goto skip_got_reloc;
	  rela.r_info = ELF32_R_INFO (0, AARCH64_R (RELATIVE));
	  rela.r_addend = (h->root.u.def.value
			   + h->root.u.def.section->output_section->vma
			   + h->root.u.def.section->output_offset);
	}
      else
	{
	do_glob_dat:
	  BFD_ASSERT ((h->got.offset & 1) == 0);
	  bfd_put_32 (output_bfd, (bfd_vma) 0,
		      htab->root.sgot->contents + h->got.offset);
	  rela.r_info = ELF32_R_INFO (h->dynindx, AARCH64_R (GLOB_DAT));
	  rela.r_addend = 0;
	}

      loc = htab->root.srelgot->contents;
      loc += htab->root.srelgot->reloc_count++ * RELOC_SIZE (htab);
      bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
    }
skip_got_reloc:

  if (h->needs_copy)
    {
      Elf_Internal_Rela rela;
      asection *s;
      bfd_byte *loc;

      /* This symbol needs a copy reloc.  Set it up.  */
      if (h->dynindx == -1
	  || (h->root.type != bfd_link_hash_defined
	      && h->root.type != bfd_link_hash_defweak)
	  || htab->root.srelbss == NULL)
	abort ();

      rela.r_offset = (h->root.u.def.value
		       + h->root.u.def.section->output_section->vma
		       + h->root.u.def.section->output_offset);
      rela.r_info = ELF32_R_INFO (h->dynindx, AARCH64_R (COPY));
      rela.r_addend = 0;
      if (h->root.u.def.section == htab->root.sdynrelro)
	s = htab->root.sreldynrelro;
      else
	s = htab->root.srelbss;
      loc = s->contents + s->reloc_count++ * RELOC_SIZE (htab);
      bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
    }

  /* Mark _DYNAMIC and _GLOBAL_OFFSET_TABLE_ as absolute.  SYM may
     be NULL for local symbols.  */
  if (sym != NULL
      && (h == elf_hash_table (info)->hdynamic
	  || h == elf_hash_table (info)->hgot))
    sym->st_shndx = SHN_ABS;

  return true;
}

/* Finish up local dynamic symbol handling.  We set the contents of
   various dynamic sections here.  */

static int
elf32_aarch64_finish_local_dynamic_symbol (void **slot, void *inf)
{
  struct elf_link_hash_entry *h
    = (struct elf_link_hash_entry *) *slot;
  struct bfd_link_info *info
    = (struct bfd_link_info *) inf;

  return elf32_aarch64_finish_dynamic_symbol (info->output_bfd,
					      info, h, NULL);
}

static void
elf32_aarch64_init_small_plt0_entry (bfd *output_bfd ATTRIBUTE_UNUSED,
				     struct elf_aarch64_link_hash_table
				     *htab)
{
  /* Fill in PLT0. Fixme:RR Note this doesn't distinguish between
     small and large plts and at the minute just generates
     the small PLT.  */

  /* PLT0 of the small PLT looks like this in ELF64 -
     stp x16, x30, [sp, #-16]!		// Save the reloc and lr on stack.
     adrp x16, PLT_GOT + 16		// Get the page base of the GOTPLT
     ldr  x17, [x16, #:lo12:PLT_GOT+16] // Load the address of the
					// symbol resolver
     add  x16, x16, #:lo12:PLT_GOT+16   // Load the lo12 bits of the
					// GOTPLT entry for this.
     br   x17
     PLT0 will be slightly different in ELF32 due to different got entry
     size.  */
  bfd_vma plt_got_2nd_ent;	/* Address of GOT[2].  */
  bfd_vma plt_base;


  memcpy (htab->root.splt->contents, htab->plt0_entry,
	  htab->plt_header_size);

  /* PR 26312: Explicitly set the sh_entsize to 0 so that
     consumers do not think that the section contains fixed
     sized objects.  */
  elf_section_data (htab->root.splt->output_section)->this_hdr.sh_entsize = 0;

  plt_got_2nd_ent = (htab->root.sgotplt->output_section->vma
		  + htab->root.sgotplt->output_offset
		  + GOT_ENTRY_SIZE * 2);

  plt_base = htab->root.splt->output_section->vma +
    htab->root.splt->output_offset;

  /* First instruction in BTI enabled PLT stub is a BTI
     instruction so skip it.  */
  bfd_byte *plt0_entry = htab->root.splt->contents;
  if (elf_aarch64_tdata (output_bfd)->sw_protections.plt_type & PLT_BTI)
    plt0_entry = plt0_entry + 4;

  /* Fill in the top 21 bits for this: ADRP x16, PLT_GOT + n * 8.
     ADRP:   ((PG(S+A)-PG(P)) >> 12) & 0x1fffff */
  elf_aarch64_update_plt_entry (output_bfd, BFD_RELOC_AARCH64_ADR_HI21_PCREL,
				plt0_entry + 4,
				PG (plt_got_2nd_ent) - PG (plt_base + 4));

  elf_aarch64_update_plt_entry (output_bfd, BFD_RELOC_AARCH64_LDST32_LO12,
				plt0_entry + 8,
				PG_OFFSET (plt_got_2nd_ent));

  elf_aarch64_update_plt_entry (output_bfd, BFD_RELOC_AARCH64_ADD_LO12,
				plt0_entry + 12,
				PG_OFFSET (plt_got_2nd_ent));
}

static bool
elf32_aarch64_finish_dynamic_sections (bfd *output_bfd,
				       struct bfd_link_info *info)
{
  struct elf_aarch64_link_hash_table *htab;
  bfd *dynobj;
  asection *sdyn;

  htab = elf_aarch64_hash_table (info);
  dynobj = htab->root.dynobj;
  sdyn = bfd_get_linker_section (dynobj, ".dynamic");

  if (htab->root.dynamic_sections_created)
    {
      Elf32_External_Dyn *dyncon, *dynconend;

      if (sdyn == NULL || htab->root.sgot == NULL)
	abort ();

      dyncon = (Elf32_External_Dyn *) sdyn->contents;
      dynconend = (Elf32_External_Dyn *) (sdyn->contents + sdyn->size);
      for (; dyncon < dynconend; dyncon++)
	{
	  Elf_Internal_Dyn dyn;
	  asection *s;

	  bfd_elf32_swap_dyn_in (dynobj, dyncon, &dyn);

	  switch (dyn.d_tag)
	    {
	    default:
	      continue;

	    case DT_PLTGOT:
	      s = htab->root.sgotplt;
	      dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
	      break;

	    case DT_JMPREL:
	      s = htab->root.srelplt;
	      dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
	      break;

	    case DT_PLTRELSZ:
	      s = htab->root.srelplt;
	      dyn.d_un.d_val = s->size;
	      break;

	    case DT_TLSDESC_PLT:
	      s = htab->root.splt;
	      dyn.d_un.d_ptr = s->output_section->vma + s->output_offset
		+ htab->root.tlsdesc_plt;
	      break;

	    case DT_TLSDESC_GOT:
	      s = htab->root.sgot;
	      BFD_ASSERT (htab->root.tlsdesc_got != (bfd_vma)-1);
	      dyn.d_un.d_ptr = s->output_section->vma + s->output_offset
		+ htab->root.tlsdesc_got;
	      break;
	    }

	  bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
	}

    }

  /* Fill in the special first entry in the procedure linkage table.  */
  if (htab->root.splt && htab->root.splt->size > 0)
    {
      elf32_aarch64_init_small_plt0_entry (output_bfd, htab);

      if (htab->root.tlsdesc_plt && !(info->flags & DF_BIND_NOW))
	{
	  BFD_ASSERT (htab->root.tlsdesc_got != (bfd_vma)-1);
	  bfd_put_32 (output_bfd, (bfd_vma) 0,
		      htab->root.sgot->contents + htab->root.tlsdesc_got);

	  const bfd_byte *entry = elf32_aarch64_tlsdesc_small_plt_entry;
	  htab->tlsdesc_plt_entry_size = PLT_TLSDESC_ENTRY_SIZE;

	  aarch64_plt_type type
	    = elf_aarch64_tdata (output_bfd)->sw_protections.plt_type;
	  if (type == PLT_BTI || type == PLT_BTI_PAC)
	    {
	      entry = elf32_aarch64_tlsdesc_small_plt_bti_entry;
	    }

	  memcpy (htab->root.splt->contents + htab->root.tlsdesc_plt,
		  entry, htab->tlsdesc_plt_entry_size);

	  {
	    bfd_vma adrp1_addr =
	      htab->root.splt->output_section->vma
	      + htab->root.splt->output_offset
	      + htab->root.tlsdesc_plt + 4;

	    bfd_vma adrp2_addr = adrp1_addr + 4;

	    bfd_vma got_addr =
	      htab->root.sgot->output_section->vma
	      + htab->root.sgot->output_offset;

	    bfd_vma pltgot_addr =
	      htab->root.sgotplt->output_section->vma
	      + htab->root.sgotplt->output_offset;

	    bfd_vma dt_tlsdesc_got = got_addr + htab->root.tlsdesc_got;

	    bfd_byte *plt_entry =
	      htab->root.splt->contents + htab->root.tlsdesc_plt;

	   /* First instruction in BTI enabled PLT stub is a BTI
	      instruction so skip it.  */
	    if (type & PLT_BTI)
	      {
		plt_entry = plt_entry + 4;
		adrp1_addr = adrp1_addr + 4;
		adrp2_addr = adrp2_addr + 4;
	      }

	    /* adrp x2, DT_TLSDESC_GOT */
	    elf_aarch64_update_plt_entry (output_bfd,
					  BFD_RELOC_AARCH64_ADR_HI21_PCREL,
					  plt_entry + 4,
					  (PG (dt_tlsdesc_got)
					   - PG (adrp1_addr)));

	    /* adrp x3, 0 */
	    elf_aarch64_update_plt_entry (output_bfd,
					  BFD_RELOC_AARCH64_ADR_HI21_PCREL,
					  plt_entry + 8,
					  (PG (pltgot_addr)
					   - PG (adrp2_addr)));

	    /* ldr x2, [x2, #0] */
	    elf_aarch64_update_plt_entry (output_bfd,
					  BFD_RELOC_AARCH64_LDST32_LO12,
					  plt_entry + 12,
					  PG_OFFSET (dt_tlsdesc_got));

	    /* add x3, x3, 0 */
	    elf_aarch64_update_plt_entry (output_bfd,
					  BFD_RELOC_AARCH64_ADD_LO12,
					  plt_entry + 16,
					  PG_OFFSET (pltgot_addr));
	  }
	}
    }

  if (htab->root.sgotplt)
    {
      if (bfd_is_abs_section (htab->root.sgotplt->output_section))
	{
	  _bfd_error_handler
	    (_("discarded output section: `%pA'"), htab->root.sgotplt);
	  return false;
	}

      /* Fill in the first three entries in the global offset table.  */
      if (htab->root.sgotplt->size > 0)
	{
	  bfd_put_32 (output_bfd, (bfd_vma) 0, htab->root.sgotplt->contents);

	  /* Write GOT[1] and GOT[2], needed for the dynamic linker.  */
	  bfd_put_32 (output_bfd,
		      (bfd_vma) 0,
		      htab->root.sgotplt->contents + GOT_ENTRY_SIZE);
	  bfd_put_32 (output_bfd,
		      (bfd_vma) 0,
		      htab->root.sgotplt->contents + GOT_ENTRY_SIZE * 2);
	}

      if (htab->root.sgot)
	{
	  if (htab->root.sgot->size > 0)
	    {
	      bfd_vma addr =
		sdyn ? sdyn->output_section->vma + sdyn->output_offset : 0;
	      bfd_put_32 (output_bfd, addr, htab->root.sgot->contents);
	    }
	}

      elf_section_data (htab->root.sgotplt->output_section)->
	this_hdr.sh_entsize = GOT_ENTRY_SIZE;
    }

  if (htab->root.sgot && htab->root.sgot->size > 0)
    elf_section_data (htab->root.sgot->output_section)->this_hdr.sh_entsize
      = GOT_ENTRY_SIZE;

  /* Fill PLT and GOT entries for local STT_GNU_IFUNC symbols.  */
  htab_traverse (htab->loc_hash_table,
		 elf32_aarch64_finish_local_dynamic_symbol,
		 info);

  return true;
}

/* Check if BTI enabled PLTs are needed.  Returns the type needed.  */
static aarch64_plt_type
get_plt_type (bfd *abfd)
{
  aarch64_plt_type ret = PLT_NORMAL;
  bfd_byte *contents, *extdyn, *extdynend;
  asection *sec = bfd_get_section_by_name (abfd, ".dynamic");
  if (!sec
      || (sec->flags & SEC_HAS_CONTENTS) == 0
      || sec->size < sizeof (Elf32_External_Dyn)
      || !bfd_malloc_and_get_section (abfd, sec, &contents))
    return ret;
  extdyn = contents;
  extdynend = contents + sec->size - sizeof (Elf32_External_Dyn);
  for (; extdyn <= extdynend; extdyn += sizeof (Elf32_External_Dyn))
    {
      Elf_Internal_Dyn dyn;
      bfd_elf32_swap_dyn_in (abfd, extdyn, &dyn);

      /* Let's check the processor specific dynamic array tags.  */
      bfd_vma tag = dyn.d_tag;
      if (tag < DT_LOPROC || tag > DT_HIPROC)
	continue;

      switch (tag)
	{
	case DT_AARCH64_BTI_PLT:
	  ret |= PLT_BTI;
	  break;

	case DT_AARCH64_PAC_PLT:
	  ret |= PLT_PAC;
	  break;

	default: break;
	}
    }
  free (contents);
  return ret;
}

static long
elf32_aarch64_get_synthetic_symtab (bfd *abfd,
				    long symcount,
				    asymbol **syms,
				    long dynsymcount,
				    asymbol **dynsyms,
				    asymbol **ret)
{
  elf_aarch64_tdata (abfd)->sw_protections.plt_type = get_plt_type (abfd);
  return _bfd_elf_get_synthetic_symtab (abfd, symcount, syms,
					dynsymcount, dynsyms, ret);
}

/* Return address for Ith PLT stub in section PLT, for relocation REL
   or (bfd_vma) -1 if it should not be included.  */

static bfd_vma
elf32_aarch64_plt_sym_val (bfd_vma i, const asection *plt,
			   const arelent *rel ATTRIBUTE_UNUSED)
{
  size_t plt0_size = PLT_ENTRY_SIZE;
  size_t pltn_size = PLT_SMALL_ENTRY_SIZE;

  aarch64_plt_type plt_type
    = elf_aarch64_tdata (plt->owner)->sw_protections.plt_type;
  if (plt_type == PLT_BTI_PAC)
    {
      if (elf_elfheader (plt->owner)->e_type == ET_EXEC)
	pltn_size = PLT_BTI_PAC_SMALL_ENTRY_SIZE;
      else
	pltn_size = PLT_PAC_SMALL_ENTRY_SIZE;
    }
  else if (plt_type == PLT_BTI)
    {
      if (elf_elfheader (plt->owner)->e_type == ET_EXEC)
	pltn_size = PLT_BTI_SMALL_ENTRY_SIZE;
    }
  else if (plt_type == PLT_PAC)
    {
      pltn_size = PLT_PAC_SMALL_ENTRY_SIZE;
    }

  return plt->vma + plt0_size + i * pltn_size;
}

/* Returns TRUE if NAME is an AArch64 mapping symbol.
   The ARM ELF standard defines $x (for A64 code) and $d (for data).
   It also allows a period initiated suffix to be added to the symbol, ie:
   "$[adtx]\.[:sym_char]+".  */

static bool
is_aarch64_mapping_symbol (const char * name)
{
  return name != NULL /* Paranoia.  */
    && name[0] == '$' /* Note: if objcopy --prefix-symbols has been used then
			 the mapping symbols could have acquired a prefix.
			 We do not support this here, since such symbols no
			 longer conform to the ARM ELF ABI.  */
    && (name[1] == 'd' || name[1] == 'x')
    && (name[2] == 0 || name[2] == '.');
  /* FIXME: Strictly speaking the symbol is only a valid mapping symbol if
     any characters that follow the period are legal characters for the body
     of a symbol's name.  For now we just assume that this is the case.  */
}

/* Make sure that mapping symbols in object files are not removed via the
   "strip --strip-unneeded" tool.  These symbols might needed in order to
   correctly generate linked files.  Once an object file has been linked,
   it should be safe to remove them.  */

static void
elf32_aarch64_backend_symbol_processing (bfd *abfd, asymbol *sym)
{
  if (((abfd->flags & (EXEC_P | DYNAMIC)) == 0)
      && sym->section != bfd_abs_section_ptr
      && is_aarch64_mapping_symbol (sym->name))
    sym->flags |= BSF_KEEP;
}

/* Implement elf_backend_setup_gnu_properties for AArch64.  It serves as a
   wrapper function for _bfd_aarch64_elf_link_setup_gnu_properties to account
   for the effect of GNU properties of the output_bfd.  */
static bfd *
elf32_aarch64_link_setup_gnu_properties (struct bfd_link_info *info)
{
  bfd *pbfd = _bfd_aarch64_elf_link_setup_gnu_properties (info);

  /* When BTI is forced on the command line, information flows from plt_type to
     outprop, so plt_type has already been set and outprop don't have any effect
     on plt_type.
     Whereas if BTI is inferred from the input bfds, information flows from
     outprop to plt_type.  If the property GNU_PROPERTY_AARCH64_FEATURE_1_BTI
     has been set on all the input bfds, then BTI is set on the output bfd and
     plt_type is updated accordingly.  */
  struct elf_aarch64_obj_tdata * tdata = elf_aarch64_tdata (info->output_bfd);
  uint32_t outprop = tdata->gnu_property_aarch64_feature_1_and;
  if (outprop & GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
    tdata->sw_protections.plt_type |= PLT_BTI;
  setup_plt_values (info, tdata->sw_protections.plt_type);
  return pbfd;
}

/* Implement elf_backend_merge_gnu_properties for AArch64.  It serves as a
   wrapper function for _bfd_aarch64_elf_merge_gnu_properties to account
   for the effect of GNU properties of the output_bfd.  */
static bool
elf32_aarch64_merge_gnu_properties (struct bfd_link_info *info,
				       bfd *abfd, bfd *bbfd,
				       elf_property *aprop,
				       elf_property *bprop)
{
  uint32_t outprop
    = elf_aarch64_tdata (info->output_bfd)->gnu_property_aarch64_feature_1_and;

  /* Properties are merged per type, hence only check for warnings when merging
     GNU_PROPERTY_AARCH64_FEATURE_1_AND.  */
  if ((aprop && aprop->pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND)
   || (bprop && bprop->pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND))
    {
      const aarch64_protection_opts *sw_protections
	= &elf_aarch64_tdata (info->output_bfd)->sw_protections;
      aarch64_feature_marking_report bti_report = sw_protections->bti_report;
      aarch64_feature_marking_report gcs_report = sw_protections->gcs_report;

      /* If output has been marked with BTI using command line argument, give
	 out warning if necessary.  */
      if ((outprop & GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
	  && (bti_report != MARKING_NONE))
	{
	  if (!aprop || !(aprop->u.number & GNU_PROPERTY_AARCH64_FEATURE_1_BTI))
	    _bfd_aarch64_elf_check_bti_report (info, abfd);
	  if (!bprop || !(bprop->u.number & GNU_PROPERTY_AARCH64_FEATURE_1_BTI))
	    _bfd_aarch64_elf_check_bti_report (info, bbfd);
	}

      /* If the output has been marked with GCS using '-z gcs' and the input is
	 missing GCS feature tag, throw a warning/error in accordance with
	 -z gcs-report=warning/error.  */
      if ((outprop & GNU_PROPERTY_AARCH64_FEATURE_1_GCS)
	  && gcs_report != MARKING_NONE)
	{
	  if (!aprop || !(aprop->u.number & GNU_PROPERTY_AARCH64_FEATURE_1_GCS))
	    _bfd_aarch64_elf_check_gcs_report (info, abfd);
	  if (!bprop || !(bprop->u.number & GNU_PROPERTY_AARCH64_FEATURE_1_GCS))
	    _bfd_aarch64_elf_check_gcs_report (info, bbfd);
	}
    }

  return  _bfd_aarch64_elf_merge_gnu_properties (info, abfd, aprop,
						 bprop, outprop);
}

/* We use this so we can override certain functions
   (though currently we don't).  */

const struct elf_size_info elf32_aarch64_size_info =
{
  sizeof (Elf32_External_Ehdr),
  sizeof (Elf32_External_Phdr),
  sizeof (Elf32_External_Shdr),
  sizeof (Elf32_External_Rel),
  sizeof (Elf32_External_Rela),
  sizeof (Elf32_External_Sym),
  sizeof (Elf32_External_Dyn),
  sizeof (Elf_External_Note),
  4,				/* Hash table entry size.  */
  1,				/* Internal relocs per external relocs.  */
  ARCH_SIZE,			/* Arch size.  */
  LOG_FILE_ALIGN,		/* Log_file_align.  */
  ELFCLASS32, EV_CURRENT,
  bfd_elf32_write_out_phdrs,
  bfd_elf32_write_shdrs_and_ehdr,
  bfd_elf32_checksum_contents,
  bfd_elf32_write_relocs,
  bfd_elf32_swap_symbol_in,
  bfd_elf32_swap_symbol_out,
  bfd_elf32_slurp_reloc_table,
  bfd_elf32_slurp_symbol_table,
  bfd_elf32_swap_dyn_in,
  bfd_elf32_swap_dyn_out,
  bfd_elf32_swap_reloc_in,
  bfd_elf32_swap_reloc_out,
  bfd_elf32_swap_reloca_in,
  bfd_elf32_swap_reloca_out
};

#define ELF_ARCH			bfd_arch_aarch64
#define ELF_TARGET_ID			AARCH64_ELF_DATA
#define ELF_MACHINE_CODE		EM_AARCH64
#define ELF_MAXPAGESIZE			0x10000
#define ELF_COMMONPAGESIZE		0x1000

#define bfd_elf32_bfd_is_target_special_symbol	\
  elf32_aarch64_is_target_special_symbol

#define bfd_elf32_bfd_link_hash_table_create	\
  elf32_aarch64_link_hash_table_create

#define bfd_elf32_bfd_merge_private_bfd_data	\
  elf32_aarch64_merge_private_bfd_data

#define bfd_elf32_bfd_print_private_bfd_data	\
  elf32_aarch64_print_private_bfd_data

#define bfd_elf32_bfd_reloc_type_lookup		\
  elf32_aarch64_reloc_type_lookup

#define bfd_elf32_bfd_reloc_name_lookup		\
  elf32_aarch64_reloc_name_lookup

#define bfd_elf32_bfd_set_private_flags		\
  elf32_aarch64_set_private_flags

#define bfd_elf32_find_inliner_info		\
  elf32_aarch64_find_inliner_info

#define bfd_elf32_get_synthetic_symtab		\
  elf32_aarch64_get_synthetic_symtab

#define bfd_elf32_mkobject			\
  elf32_aarch64_mkobject

#define bfd_elf32_new_section_hook		\
  elf32_aarch64_new_section_hook

#define elf_backend_adjust_dynamic_symbol	\
  elf32_aarch64_adjust_dynamic_symbol

#define elf_backend_early_size_sections		\
  elf32_aarch64_early_size_sections

#define elf_backend_check_relocs		\
  elf32_aarch64_check_relocs

#define elf_backend_copy_indirect_symbol	\
  elf32_aarch64_copy_indirect_symbol

#define elf_backend_merge_symbol_attribute	\
  elf32_aarch64_merge_symbol_attribute

/* Create .dynbss, and .rela.bss sections in DYNOBJ, and set up shortcuts
   to them in our hash.  */
#define elf_backend_create_dynamic_sections	\
  elf32_aarch64_create_dynamic_sections

#define elf_backend_init_index_section		\
  _bfd_elf_init_2_index_sections

#define elf_backend_finish_dynamic_sections	\
  elf32_aarch64_finish_dynamic_sections

#define elf_backend_finish_dynamic_symbol	\
  elf32_aarch64_finish_dynamic_symbol

#define elf_backend_object_p			\
  elf32_aarch64_object_p

#define elf_backend_output_arch_local_syms	\
  elf32_aarch64_output_arch_local_syms

#define elf_backend_maybe_function_sym		\
  elf32_aarch64_maybe_function_sym

#define elf_backend_plt_sym_val			\
  elf32_aarch64_plt_sym_val

#define elf_backend_init_file_header		\
  elf32_aarch64_init_file_header

#define elf_backend_relocate_section		\
  elf32_aarch64_relocate_section

#define elf_backend_reloc_type_class		\
  elf32_aarch64_reloc_type_class

#define elf_backend_section_from_shdr		\
  elf32_aarch64_section_from_shdr

#define elf_backend_section_from_phdr		\
  elf32_aarch64_section_from_phdr

#define elf_backend_modify_headers		\
  elf32_aarch64_modify_headers

#define elf_backend_late_size_sections		\
  elf32_aarch64_late_size_sections

#define elf_backend_size_info			\
  elf32_aarch64_size_info

#define elf_backend_write_section		\
  elf32_aarch64_write_section

#define elf_backend_symbol_processing		\
  elf32_aarch64_backend_symbol_processing

#define elf_backend_setup_gnu_properties	\
  elf32_aarch64_link_setup_gnu_properties

#define elf_backend_merge_gnu_properties	\
  elf32_aarch64_merge_gnu_properties

#define elf_backend_size_relative_relocs	\
  elf32_aarch64_size_relative_relocs

#define elf_backend_finish_relative_relocs	\
  elf32_aarch64_finish_relative_relocs

#define elf_backend_can_refcount       1
#define elf_backend_can_gc_sections    1
#define elf_backend_plt_readonly       1
#define elf_backend_want_got_plt       1
#define elf_backend_want_plt_sym       0
#define elf_backend_want_dynrelro      1
#define elf_backend_may_use_rel_p      0
#define elf_backend_may_use_rela_p     1
#define elf_backend_default_use_rela_p 1
#define elf_backend_rela_normal	       1
#define elf_backend_dtrel_excludes_plt 1
#define elf_backend_got_header_size (GOT_ENTRY_SIZE * 3)
#define elf_backend_default_execstack  0
#define elf_backend_extern_protected_data 0
#define elf_backend_hash_symbol elf_aarch64_hash_symbol

#undef	elf_backend_obj_attrs_section
#define elf_backend_obj_attrs_section		SEC_AARCH64_ATTRIBUTES

#include "elf32-target.h"
