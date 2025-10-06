#line 1 "../../binutils-gdb/bfd/elfnn-riscv.c"
/* RISC-V-specific support for 32-bit ELF.
   Copyright (C) 2011-2025 Free Software Foundation, Inc.

   Contributed by Andrew Waterman (andrew@sifive.com).
   Based on TILE-Gx and MIPS targets.

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

/* This file handles RISC-V ELF targets.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "bfdlink.h"
#include "genlink.h"
#include "elf-bfd.h"
#include "elfxx-riscv.h"
#include "elf/riscv.h"
#include "opcode/riscv.h"
#include "objalloc.h"

#include <limits.h>
#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

/* True if dynamic relocation is needed.  If we are creating a shared library,
   and this is a reloc against a global symbol, or a non PC relative reloc
   against a local symbol, then we need to copy the reloc into the shared
   library.  However, if we are linking with -Bsymbolic, we do not need to
   copy a reloc against a global symbol which is defined in an object we are
   including in the link (i.e., DEF_REGULAR is set).

   At this point we have not seen all the input files, so it is possible that
   DEF_REGULAR is not set now but will be set later (it is never cleared).
   In case of a weak definition, DEF_REGULAR may be cleared later by a strong
   definition in a shared library.  We account for that possibility below by
   storing information in the relocs_copied field of the hash table entry.
   A similar situation occurs when creating shared libraries and symbol
   visibility changes render the symbol local.

   If on the other hand, we are creating an executable, we may need to keep
   relocations for symbols satisfied by a dynamic library if we manage to
   avoid copy relocs for the symbol.

   Generate dynamic pointer relocation against STT_GNU_IFUNC symbol in the
   non-code section (R_RISCV_32/R_RISCV_64).  */
#define RISCV_NEED_DYNAMIC_RELOC(PCREL, INFO, H, SEC) \
  ((bfd_link_pic (INFO) \
    && ((SEC)->flags & SEC_ALLOC) != 0 \
    && (!(PCREL) \
	|| ((H) != NULL \
	    && (!(INFO)->symbolic \
		|| (H)->root.type == bfd_link_hash_defweak \
		|| !(H)->def_regular)))) \
   || (!bfd_link_pic (INFO) \
       && ((SEC)->flags & SEC_ALLOC) != 0 \
       && (H) != NULL \
       && ((H)->root.type == bfd_link_hash_defweak \
	   || !(H)->def_regular)) \
   || (!bfd_link_pic (INFO) \
       && (H) != NULL \
       && (H)->type == STT_GNU_IFUNC \
       && ((SEC)->flags & SEC_CODE) == 0))

/* True if dynamic relocation should be generated.  */
#define RISCV_GENERATE_DYNAMIC_RELOC(PCREL, INFO, H, RESOLVED_TO_ZERO) \
  ((bfd_link_pic (INFO) \
    && ((H) == NULL \
	|| (ELF_ST_VISIBILITY ((H)->other) == STV_DEFAULT && !(RESOLVED_TO_ZERO)) \
	|| (H)->root.type != bfd_link_hash_undefweak) \
    && (!(PCREL) \
	|| !SYMBOL_CALLS_LOCAL ((INFO), (H)))) \
   || (!bfd_link_pic (INFO) \
       && (H) != NULL \
       && (H)->dynindx != -1 \
       && !(H)->non_got_ref \
       && (((H)->def_dynamic && !(H)->def_regular) \
	   || (H)->root.type == bfd_link_hash_undefweak \
	   || (H)->root.type == bfd_link_hash_undefined)))

/* True if this input relocation should be copied to output.  H->dynindx
   may be -1 if this symbol was marked to become local.  */
#define RISCV_COPY_INPUT_RELOC(INFO, H) \
  ((H) != NULL \
   && (H)->dynindx != -1 \
   && (!bfd_link_pic (INFO) \
       || !(bfd_link_pie ((INFO)) || SYMBOLIC_BIND ((INFO), (H))) \
       || !(H)->def_regular))

/* True if this is actually a static link, or it is a -Bsymbolic link
   and the symbol is defined locally, or the symbol was forced to be
   local because of a version file.  */
#define RISCV_RESOLVED_LOCALLY(INFO, H) \
  (!WILL_CALL_FINISH_DYNAMIC_SYMBOL (elf_hash_table (INFO)->dynamic_sections_created, \
				     bfd_link_pic (INFO), (H)) \
   || (bfd_link_pic (INFO) \
       && SYMBOL_REFERENCES_LOCAL ((INFO), (H))))

/* Set NEED_RELOC to true if TLS GD/IE needs dynamic relocations, and INDX will
   be the dynamic index.  PR22263, use the same check in allocate_dynrelocs and
   riscv_elf_relocate_section for TLS GD/IE.  */
#define RISCV_TLS_GD_IE_NEED_DYN_RELOC(INFO, DYN, H, INDX, NEED_RELOC) \
  do \
    { \
      if ((H) != NULL \
	  && (H)->dynindx != -1 \
	  && WILL_CALL_FINISH_DYNAMIC_SYMBOL ((DYN), bfd_link_pic (INFO), (H)) \
	  && (bfd_link_dll (INFO) || !SYMBOL_REFERENCES_LOCAL ((INFO), (H)))) \
	(INDX) = (H)->dynindx; \
      if ((bfd_link_dll (INFO) || (INDX) != 0) \
	  && ((H) == NULL \
	      || ELF_ST_VISIBILITY ((H)->other) == STV_DEFAULT \
	      || (H)->root.type != bfd_link_hash_undefweak)) \
	(NEED_RELOC) = true; \
    } \
  while (0)

#define ARCH_SIZE 32

#define MINUS_ONE ((bfd_vma)0 - 1)

#define RISCV_ELF_LOG_WORD_BYTES (ARCH_SIZE == 32 ? 2 : 3)

#define RISCV_ELF_WORD_BYTES (1 << RISCV_ELF_LOG_WORD_BYTES)

/* The name of the dynamic interpreter.  This is put in the .interp
   section.  */

#define ELF64_DYNAMIC_INTERPRETER "/lib/ld.so.1"
#define ELF32_DYNAMIC_INTERPRETER "/lib32/ld.so.1"

#define ELF_ARCH			bfd_arch_riscv
#define ELF_TARGET_ID			RISCV_ELF_DATA
#define ELF_MACHINE_CODE		EM_RISCV
#define ELF_MAXPAGESIZE			0x1000
#define ELF_COMMONPAGESIZE		0x1000

#define RISCV_ATTRIBUTES_SECTION_NAME ".riscv.attributes"

/* RISC-V ELF linker hash entry.  */

struct riscv_elf_link_hash_entry
{
  struct elf_link_hash_entry elf;

#define GOT_UNKNOWN	0
#define GOT_NORMAL	1
#define GOT_TLS_GD	2
#define GOT_TLS_IE	4
#define GOT_TLS_LE	8
#define GOT_TLSDESC	16
  char tls_type;
};

#define riscv_elf_hash_entry(ent) \
  ((struct riscv_elf_link_hash_entry *) (ent))

struct _bfd_riscv_elf_obj_tdata
{
  struct elf_obj_tdata root;

  /* tls_type for each local got entry.  */
  char *local_got_tls_type;

  /* All GNU_PROPERTY_RISCV_FEATURE_1_AND properties. */
  uint32_t gnu_and_prop;
  /* PLT type.  */
  riscv_plt_type plt_type;
};

#define _bfd_riscv_elf_tdata(abfd) \
  ((struct _bfd_riscv_elf_obj_tdata *) (abfd)->tdata.any)

#define _bfd_riscv_elf_local_got_tls_type(abfd) \
  (_bfd_riscv_elf_tdata (abfd)->local_got_tls_type)

#define _bfd_riscv_elf_tls_type(abfd, h, symndx)		\
  (*((h) != NULL ? &riscv_elf_hash_entry (h)->tls_type		\
     : &_bfd_riscv_elf_local_got_tls_type (abfd) [symndx]))

#define is_riscv_elf(bfd)				\
  (bfd_get_flavour (bfd) == bfd_target_elf_flavour	\
   && elf_tdata (bfd) != NULL				\
   && elf_object_id (bfd) == RISCV_ELF_DATA)

static bool
elf32_riscv_mkobject (bfd *abfd)
{
  return bfd_elf_allocate_object (abfd,
				  sizeof (struct _bfd_riscv_elf_obj_tdata));
}

#include "elf/common.h"
#include "elf/internal.h"

struct riscv_elf_link_hash_table
{
  struct elf_link_hash_table elf;

  /* Various options and other info passed from the linker.  */
  struct riscv_elf_params *params;

  /* Short-cuts to get to dynamic linker sections.  */
  asection *sdyntdata;

  /* The max alignment of output sections.  */
  bfd_vma max_alignment;

  /* The max alignment of output sections in [gp-2K, gp+2K) range.  */
  bfd_vma max_alignment_for_gp;

  /* Used by local STT_GNU_IFUNC symbols.  */
  htab_t loc_hash_table;
  void * loc_hash_memory;

  /* The index of the last unused .rel.iplt slot.  */
  bfd_vma last_iplt_index;

  /* The data segment phase, don't relax the section
     when it is exp_seg_relro_adjust.  */
  int *data_segment_phase;

  /* Relocations for variant CC symbols may be present.  */
  int variant_cc;

  /* The number of bytes in the PLT header and enties.  */
  bfd_size_type plt_header_size;
  bfd_size_type plt_entry_size;

  /* Functions to make PLT header and entries.  */
  bool (*make_plt_header) (bfd *output_bfd, struct riscv_elf_link_hash_table *htab);
  bool (*make_plt_entry) (bfd *output_bfd, asection *got, bfd_vma got_offset,
			  asection *plt, bfd_vma plt_offset);
};

/* Instruction access functions. */
#define riscv_get_insn(bits, ptr)		\
  ((bits) == 16 ? bfd_getl16 (ptr)		\
   : (bits) == 32 ? bfd_getl32 (ptr)		\
   : (bits) == 64 ? bfd_getl64 (ptr)		\
   : (abort (), (bfd_vma) - 1))
#define riscv_put_insn(bits, val, ptr)		\
  ((bits) == 16 ? bfd_putl16 (val, ptr)		\
   : (bits) == 32 ? bfd_putl32 (val, ptr)	\
   : (bits) == 64 ? bfd_putl64 (val, ptr)	\
   : (abort (), (void) 0))

/* Get the RISC-V ELF linker hash table from a link_info structure.  */
#define riscv_elf_hash_table(p) \
  ((is_elf_hash_table ((p)->hash)					\
    && elf_hash_table_id (elf_hash_table (p)) == RISCV_ELF_DATA)	\
   ? (struct riscv_elf_link_hash_table *) (p)->hash : NULL)

/* Forward declaration PLT related functions.  */
static bool
riscv_make_plt_header (bfd *, struct riscv_elf_link_hash_table *);
static bool
riscv_make_plt_entry (bfd *, asection *, bfd_vma, asection *, bfd_vma);

void
riscv_elf32_set_options (struct bfd_link_info *link_info,
			 struct riscv_elf_params *params)
{
  riscv_elf_hash_table (link_info)->params = params;
}

static bool
riscv_info_to_howto_rela (bfd *abfd,
			  arelent *cache_ptr,
			  Elf_Internal_Rela *dst)
{
  cache_ptr->howto = riscv_elf_rtype_to_howto (abfd, ELF32_R_TYPE (dst->r_info));
  return cache_ptr->howto != NULL;
}

static void
riscv_elf_append_rela (bfd *abfd, asection *s, Elf_Internal_Rela *rel)
{
  const struct elf_backend_data *bed;
  bfd_byte *loc;

  bed = get_elf_backend_data (abfd);
  loc = s->contents + (s->reloc_count++ * bed->s->sizeof_rela);
  bed->s->swap_reloca_out (abfd, rel, loc);
}

/* Return true if a relocation is modifying an instruction. */

static bool
riscv_is_insn_reloc (const reloc_howto_type *howto)
{
  /* Heuristic: A multibyte destination with a nontrivial mask
     is an instruction */
  return (howto->bitsize > 8
	  && howto->dst_mask != 0
	  && ~(howto->dst_mask | (howto->bitsize < sizeof(bfd_vma) * CHAR_BIT
	       ? (MINUS_ONE << howto->bitsize) : (bfd_vma)0)) != 0);
}

/* PLT/GOT stuff.  */
#define PLT_HEADER_INSNS 8
#define PLT_ENTRY_INSNS 4
#define PLT_HEADER_SIZE (PLT_HEADER_INSNS * 4)
#define PLT_ENTRY_SIZE (PLT_ENTRY_INSNS * 4)

#define PLT_ZICFILP_UNLABELED_HEADER_INSNS 12
#define PLT_ZICFILP_UNLABELED_ENTRY_INSNS 4
#define PLT_ZICFILP_UNLABELED_HEADER_SIZE (PLT_ZICFILP_UNLABELED_HEADER_INSNS * 4)
#define PLT_ZICFILP_UNLABELED_ENTRY_SIZE (PLT_ZICFILP_UNLABELED_ENTRY_INSNS * 4)

#define GOT_ENTRY_SIZE RISCV_ELF_WORD_BYTES
#define TLS_GD_GOT_ENTRY_SIZE (RISCV_ELF_WORD_BYTES * 2)
#define TLS_IE_GOT_ENTRY_SIZE RISCV_ELF_WORD_BYTES
#define TLSDESC_GOT_ENTRY_SIZE (RISCV_ELF_WORD_BYTES * 2)
/* Reserve two entries of GOTPLT for ld.so, one is used for PLT resolver,
   the other is used for link map.  Other targets also reserve one more
   entry used for runtime profile?  */
#define GOTPLT_HEADER_SIZE (2 * GOT_ENTRY_SIZE)

#define sec_addr(sec) ((sec)->output_section->vma + (sec)->output_offset)

#if ARCH_SIZE == 32
# define MATCH_LREG MATCH_LW
#else
# define MATCH_LREG MATCH_LD
#endif


/* Check whether the compact PLT is used in this object.  Tools need this
   to dump the correct PLT header contents.  */

static long
elf32_riscv_get_synthetic_symtab (bfd *abfd,
				  long symcount,
				  asymbol **syms,
				  long dynsymcount,
				  asymbol **dynsyms,
				  asymbol **ret)
{
  /* Check Zicfilp PLT.  */
  elf_property *prop;
  prop = _bfd_elf_get_property (abfd, GNU_PROPERTY_RISCV_FEATURE_1_AND, 4);
  if (prop)
    {
      if (prop->u.number & GNU_PROPERTY_RISCV_FEATURE_1_CFI_LP_UNLABELED)
	 _bfd_riscv_elf_tdata (abfd)->plt_type |= PLT_ZICFILP_UNLABELED;
    }

  return _bfd_elf_get_synthetic_symtab (abfd, symcount, syms,
					dynsymcount, dynsyms, ret);
}

/* Generate a PLT header.  */

static bool
riscv_make_plt_header (bfd *output_bfd, struct riscv_elf_link_hash_table *htab)
{
  asection *splt = htab->elf.splt;
  bfd_vma addr = sec_addr (splt);

  asection *sgotplt = htab->elf.sgotplt;
  bfd_vma gotplt_addr = sec_addr (sgotplt);

  bfd_vma gotplt_offset_high = RISCV_PCREL_HIGH_PART (gotplt_addr, addr);
  bfd_vma gotplt_offset_low = RISCV_PCREL_LOW_PART (gotplt_addr, addr);

  /* RVE has no t3 register, so this won't work, and is not supported.  */
  if (elf_elfheader (output_bfd)->e_flags & EF_RISCV_RVE)
    {
      _bfd_error_handler (_("%pB: warning: RVE PLT generation not supported"),
			  output_bfd);
      return false;
    }

  /* auipc  t2, %hi(.got.plt)
     sub    t1, t1, t3		     # shifted .got.plt offset + hdr size + 12
     l[w|d] t3, %lo(.got.plt)(t2)    # _dl_runtime_resolve
     addi   t1, t1, -(hdr size + 12) # shifted .got.plt offset
     addi   t0, t2, %lo(.got.plt)    # &.got.plt
     srli   t1, t1, log2(16/PTRSIZE) # .got.plt offset
     l[w|d] t0, PTRSIZE(t0)	     # link map
     jr	    t3  */

  uint32_t entry[PLT_HEADER_INSNS];
  entry[0] = RISCV_UTYPE (AUIPC, X_T2, gotplt_offset_high);
  entry[1] = RISCV_RTYPE (SUB, X_T1, X_T1, X_T3);
  entry[2] = RISCV_ITYPE (LREG, X_T3, X_T2, gotplt_offset_low);
  entry[3] = RISCV_ITYPE (ADDI, X_T1, X_T1, (uint32_t) -(PLT_HEADER_SIZE + 12));
  entry[4] = RISCV_ITYPE (ADDI, X_T0, X_T2, gotplt_offset_low);
  entry[5] = RISCV_ITYPE (SRLI, X_T1, X_T1, 4 - RISCV_ELF_LOG_WORD_BYTES);
  entry[6] = RISCV_ITYPE (LREG, X_T0, X_T0, RISCV_ELF_WORD_BYTES);
  entry[7] = RISCV_ITYPE (JALR, 0, X_T3, 0);

  for (int i = 0; i < PLT_HEADER_INSNS; i++)
    bfd_putl32 (entry[i], splt->contents + 4 * i);

  return true;
}

static bool
riscv_make_plt_zicfilp_unlabeled_header (bfd *output_bfd,
					 struct riscv_elf_link_hash_table *htab)
{
  /*
      lpad   0  # disable label checking
      auipc  t2, %hi(.got.plt)          # Rewrite this to using
      sub    t1, t1, t3                 # shifted .got.plt offset + hdr size + 16
      l[w|d] t3, %lo(1b)(t2)            # _dl_runtime_resolve
      addi   t1, t1, -(hdr size + 12)   # shifted .got.plt offset
      addi   t0, t2, %pcrel_lo(1b)      # &.got.plt
      srli   t1, t1, log2(16/PTRSIZE)   # .got.plt offset
      l[w|d] t0, PTRSIZE(t0)            # link map
      jr     t3
      nop
      nop
      nop  */

  /* RVE has no t3 register, so this won't work, and is not supported.  */
  if (elf_elfheader (output_bfd)->e_flags & EF_RISCV_RVE)
    {
      _bfd_error_handler (_("%pB: warning: RVE PLT generation not supported"),
			  output_bfd);
      return false;
    }

  asection *gotplt = htab->elf.sgotplt;
  bfd_vma gotplt_addr = sec_addr (gotplt);

  asection *splt = htab->elf.splt;
  bfd_vma plt_header_addr = sec_addr (splt);

  bfd_vma auipc_addr = plt_header_addr + 4;
  /* Add INSN_BYTES to skip the lpad instruction.  */
  bfd_vma gotplt_offset_high = RISCV_PCREL_HIGH_PART (gotplt_addr, auipc_addr);
  bfd_vma gotplt_offset_low = RISCV_PCREL_LOW_PART (gotplt_addr, auipc_addr);

  uint32_t header[PLT_ZICFILP_UNLABELED_HEADER_INSNS];
  header[0] = RISCV_UTYPE (LPAD, X_ZERO, 0);
  header[1] = RISCV_UTYPE (AUIPC, X_T2, gotplt_offset_high);
  header[2] = RISCV_RTYPE (SUB, X_T1, X_T1, X_T3);
  header[3] = RISCV_ITYPE (LREG, X_T3, X_T2, gotplt_offset_low);
  header[4] = RISCV_ITYPE (ADDI, X_T1, X_T1,
			   (uint32_t) -(PLT_ZICFILP_UNLABELED_HEADER_SIZE + 16));
  header[5] = RISCV_ITYPE (ADDI, X_T0, X_T2, gotplt_offset_low);
  header[6] = RISCV_ITYPE (SRLI, X_T1, X_T1, 4 - RISCV_ELF_LOG_WORD_BYTES);
  header[7] = RISCV_ITYPE (LREG, X_T0, X_T0, RISCV_ELF_WORD_BYTES);
  header[8] = RISCV_ITYPE (JALR, 0, X_T3, 0);
  header[9] = RISCV_NOP;
  header[10] = RISCV_NOP;
  header[11] = RISCV_NOP;

  for (int i = 0; i < PLT_ZICFILP_UNLABELED_HEADER_INSNS; i++)
    bfd_putl32 (header[i], splt->contents + 4 * i);

  return true;
}

/* Generate a PLT entry.  */

static bool
riscv_make_plt_entry (bfd *output_bfd, asection *gotsec, bfd_vma got_offset,
		      asection *pltsec, bfd_vma plt_offset)
{
  bfd_vma got = sec_addr (gotsec) + got_offset;
  bfd_vma addr = sec_addr (pltsec) + plt_offset;
  /* RVE has no t3 register, so this won't work, and is not supported.  */
  if (elf_elfheader (output_bfd)->e_flags & EF_RISCV_RVE)
    {
      _bfd_error_handler (_("%pB: warning: RVE PLT generation not supported"),
			  output_bfd);
      return false;
    }

  /* auipc  t3, %hi(.got.plt entry)
     l[w|d] t3, %lo(.got.plt entry)(t3)
     jalr   t1, t3
     nop  */

  uint32_t entry[PLT_ENTRY_INSNS];
  entry[0] = RISCV_UTYPE (AUIPC, X_T3, RISCV_PCREL_HIGH_PART (got, addr));
  entry[1] = RISCV_ITYPE (LREG,  X_T3, X_T3, RISCV_PCREL_LOW_PART (got, addr));
  entry[2] = RISCV_ITYPE (JALR, X_T1, X_T3, 0);
  entry[3] = RISCV_NOP;

  bfd_byte *loc = pltsec->contents + plt_offset;
  for (int i = 0; i < PLT_ENTRY_INSNS; i++)
    bfd_putl32 (entry[i], loc + 4 * i);

  return true;
}

static bool
riscv_make_plt_zicfilp_unlabeled_entry (bfd *output_bfd, asection *got,
					bfd_vma got_offset, asection *plt,
					bfd_vma plt_offset)
{
  /*    lpad    0
    1:  auipc   t3, %pcrel_hi(function@.got.plt)
	l[w|d]  t3, %pcrel_lo(1b)(t3)
	jalr    t1, t3 */

  /* RVE has no t3 register, so this won't work, and is not supported.  */
  if (elf_elfheader (output_bfd)->e_flags & EF_RISCV_RVE)
    {
      _bfd_error_handler (_("%pB: warning: RVE PLT generation not supported"),
			  output_bfd);
      return false;
    }

  bfd_vma got_entry_addr = sec_addr(got) + got_offset;
  bfd_vma plt_entry_addr = sec_addr(plt) + plt_offset;
  bfd_vma auipc_addr = plt_entry_addr + 4;
  uint32_t entry[PLT_ZICFILP_UNLABELED_ENTRY_INSNS];
  entry[0] = RISCV_UTYPE (LPAD, X_ZERO, 0);
  entry[1] = RISCV_UTYPE (AUIPC, X_T3, RISCV_PCREL_HIGH_PART (got_entry_addr, auipc_addr));
  entry[2] = RISCV_ITYPE (LREG,  X_T3, X_T3, RISCV_PCREL_LOW_PART (got_entry_addr, auipc_addr));
  entry[3] = RISCV_ITYPE (JALR, X_T1, X_T3, 0);

  bfd_byte *loc = plt->contents + plt_offset;
  for (int i = 0; i < PLT_ZICFILP_UNLABELED_ENTRY_INSNS; i++)
    bfd_putl32 (entry[i], loc + 4 * i);

  return true;
}

/* Create an entry in an RISC-V ELF linker hash table.  */

static struct bfd_hash_entry *
link_hash_newfunc (struct bfd_hash_entry *entry,
		   struct bfd_hash_table *table, const char *string)
{
  /* Allocate the structure if it has not already been allocated by a
     subclass.  */
  if (entry == NULL)
    {
      entry =
	bfd_hash_allocate (table,
			   sizeof (struct riscv_elf_link_hash_entry));
      if (entry == NULL)
	return entry;
    }

  /* Call the allocation method of the superclass.  */
  entry = _bfd_elf_link_hash_newfunc (entry, table, string);
  if (entry != NULL)
    {
      struct riscv_elf_link_hash_entry *eh;

      eh = (struct riscv_elf_link_hash_entry *) entry;
      eh->tls_type = GOT_UNKNOWN;
    }

  return entry;
}

/* Compute a hash of a local hash entry.  We use elf_link_hash_entry
   for local symbol so that we can handle local STT_GNU_IFUNC symbols
   as global symbol.  We reuse indx and dynstr_index for local symbol
   hash since they aren't used by global symbols in this backend.  */

static hashval_t
riscv_elf_local_htab_hash (const void *ptr)
{
  struct elf_link_hash_entry *h = (struct elf_link_hash_entry *) ptr;
  return ELF_LOCAL_SYMBOL_HASH (h->indx, h->dynstr_index);
}

/* Compare local hash entries.  */

static int
riscv_elf_local_htab_eq (const void *ptr1, const void *ptr2)
{
  struct elf_link_hash_entry *h1 = (struct elf_link_hash_entry *) ptr1;
  struct elf_link_hash_entry *h2 = (struct elf_link_hash_entry *) ptr2;

  return h1->indx == h2->indx && h1->dynstr_index == h2->dynstr_index;
}

/* Find and/or create a hash entry for local symbol.  */

static struct elf_link_hash_entry *
riscv_elf_get_local_sym_hash (struct riscv_elf_link_hash_table *htab,
			      bfd *abfd, const Elf_Internal_Rela *rel,
			      bool create)
{
  struct riscv_elf_link_hash_entry eh, *ret;
  asection *sec = abfd->sections;
  hashval_t h = ELF_LOCAL_SYMBOL_HASH (sec->id,
				       ELF32_R_SYM (rel->r_info));
  void **slot;

  eh.elf.indx = sec->id;
  eh.elf.dynstr_index = ELF32_R_SYM (rel->r_info);
  slot = htab_find_slot_with_hash (htab->loc_hash_table, &eh, h,
				   create ? INSERT : NO_INSERT);

  if (!slot)
    return NULL;

  if (*slot)
    {
      ret = (struct riscv_elf_link_hash_entry *) *slot;
      return &ret->elf;
    }

  ret = (struct riscv_elf_link_hash_entry *)
	objalloc_alloc ((struct objalloc *) htab->loc_hash_memory,
			sizeof (struct riscv_elf_link_hash_entry));
  if (ret)
    {
      memset (ret, 0, sizeof (*ret));
      ret->elf.indx = sec->id;
      ret->elf.dynstr_index = ELF32_R_SYM (rel->r_info);
      ret->elf.dynindx = -1;
      *slot = ret;
    }
  return &ret->elf;
}

/* Destroy a RISC-V elf linker hash table.  */

static void
riscv_elf_link_hash_table_free (bfd *obfd)
{
  struct riscv_elf_link_hash_table *ret
    = (struct riscv_elf_link_hash_table *) obfd->link.hash;

  if (ret->loc_hash_table)
    htab_delete (ret->loc_hash_table);
  if (ret->loc_hash_memory)
    objalloc_free ((struct objalloc *) ret->loc_hash_memory);

  _bfd_elf_link_hash_table_free (obfd);
}

/* Set up the PLT generation stubs in the hash table.  */

static void
setup_plt_values (struct bfd *output_bfd,
		  struct riscv_elf_link_hash_table *htab,
		  unsigned plt_type)
{
  switch (plt_type)
    {
    case PLT_NORMAL:
      htab->plt_header_size = PLT_HEADER_SIZE;
      htab->plt_entry_size = PLT_ENTRY_SIZE;
      htab->make_plt_header = riscv_make_plt_header;
      htab->make_plt_entry = riscv_make_plt_entry;
      break;

    case PLT_ZICFILP_UNLABELED:
      htab->plt_header_size = PLT_ZICFILP_UNLABELED_HEADER_SIZE;
      htab->plt_entry_size = PLT_ZICFILP_UNLABELED_ENTRY_SIZE;
      htab->make_plt_header = riscv_make_plt_zicfilp_unlabeled_header;
      htab->make_plt_entry = riscv_make_plt_zicfilp_unlabeled_entry;
      break;

    default:
      _bfd_error_handler (_("%pB: error: unsupported PLT type: %u"),
			  output_bfd,
			  plt_type);
      bfd_set_error (bfd_error_bad_value);
      break;
    }
}

/* Create a RISC-V ELF linker hash table.  */

static struct bfd_link_hash_table *
riscv_elf_link_hash_table_create (bfd *abfd)
{
  struct riscv_elf_link_hash_table *ret;
  size_t amt = sizeof (struct riscv_elf_link_hash_table);

  ret = (struct riscv_elf_link_hash_table *) bfd_zmalloc (amt);
  if (ret == NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init (&ret->elf, abfd, link_hash_newfunc,
				      sizeof (struct riscv_elf_link_hash_entry)))
    {
      free (ret);
      return NULL;
    }

  ret->max_alignment = (bfd_vma) -1;
  ret->max_alignment_for_gp = (bfd_vma) -1;

  setup_plt_values (abfd, ret, PLT_NORMAL);

  /* Create hash table for local ifunc.  */
  ret->loc_hash_table = htab_try_create (1024,
					 riscv_elf_local_htab_hash,
					 riscv_elf_local_htab_eq,
					 NULL);
  ret->loc_hash_memory = objalloc_create ();
  if (!ret->loc_hash_table || !ret->loc_hash_memory)
    {
      riscv_elf_link_hash_table_free (abfd);
      return NULL;
    }
  ret->elf.root.hash_table_free = riscv_elf_link_hash_table_free;

  return &ret->elf.root;
}

/* Create the .got section.  */

static bool
riscv_elf_create_got_section (bfd *abfd, struct bfd_link_info *info)
{
  flagword flags;
  asection *s, *s_got;
  struct elf_link_hash_entry *h;
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
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

  s = s_got = bfd_make_section_anyway_with_flags (abfd, ".got", flags);
  if (s == NULL
      || !bfd_set_section_alignment (s, bed->s->log_file_align))
    return false;
  htab->sgot = s;

  /* The first bit of the global offset table is the header.  */
  s->size += bed->got_header_size;

  if (bed->want_got_plt)
    {
      s = bfd_make_section_anyway_with_flags (abfd, ".got.plt", flags);
      if (s == NULL
	  || !bfd_set_section_alignment (s, bed->s->log_file_align))
	return false;
      htab->sgotplt = s;

      /* Reserve room for the header.  */
      s->size += GOTPLT_HEADER_SIZE;
    }

  if (bed->want_got_sym)
    {
      /* Define the symbol _GLOBAL_OFFSET_TABLE_ at the start of the .got
	 section.  We don't do this in the linker script because we don't want
	 to define the symbol if we are not creating a global offset
	 table.  */
      h = _bfd_elf_define_linkage_sym (abfd, info, s_got,
				       "_GLOBAL_OFFSET_TABLE_");
      elf_hash_table (info)->hgot = h;
      if (h == NULL)
	return false;
    }

  return true;
}

/* Create .plt, .rela.plt, .got, .got.plt, .rela.got, .dynbss, and
   .rela.bss sections in DYNOBJ, and set up shortcuts to them in our
   hash table.  */

static bool
riscv_elf_create_dynamic_sections (bfd *dynobj,
				   struct bfd_link_info *info)
{
  struct riscv_elf_link_hash_table *htab;

  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);

  if (!riscv_elf_create_got_section (dynobj, info))
    return false;

  if (!_bfd_elf_create_dynamic_sections (dynobj, info))
    return false;

  if (!bfd_link_pic (info))
    {
      /* Technically, this section doesn't have contents.  It is used as the
	 target of TLS copy relocs, to copy TLS data from shared libraries into
	 the executable.  However, if we don't mark it as loadable, then it
	 matches the IS_TBSS test in ldlang.c, and there is no run-time address
	 space allocated for it even though it has SEC_ALLOC.  That test is
	 correct for .tbss, but not correct for this section.  There is also
	 a second problem that having a section with no contents can only work
	 if it comes after all sections with contents in the same segment,
	 but the linker script does not guarantee that.  This is just mixed in
	 with other .tdata.* sections.  We can fix both problems by lying and
	 saying that there are contents.  This section is expected to be small
	 so this should not cause a significant extra program startup cost.  */
      htab->sdyntdata =
	bfd_make_section_anyway_with_flags (dynobj, ".tdata.dyn",
					    (SEC_ALLOC | SEC_THREAD_LOCAL
					     | SEC_LOAD | SEC_DATA
					     | SEC_HAS_CONTENTS
					     | SEC_LINKER_CREATED));
    }

  if (!htab->elf.splt || !htab->elf.srelplt || !htab->elf.sdynbss
      || (!bfd_link_pic (info) && (!htab->elf.srelbss || !htab->sdyntdata)))
    abort ();

  return true;
}

/* Copy the extra info we tack onto an elf_link_hash_entry.  */

static void
riscv_elf_copy_indirect_symbol (struct bfd_link_info *info,
				struct elf_link_hash_entry *dir,
				struct elf_link_hash_entry *ind)
{
  struct riscv_elf_link_hash_entry *edir, *eind;

  edir = (struct riscv_elf_link_hash_entry *) dir;
  eind = (struct riscv_elf_link_hash_entry *) ind;

  if (ind->root.type == bfd_link_hash_indirect
      && dir->got.refcount <= 0)
    {
      edir->tls_type = eind->tls_type;
      eind->tls_type = GOT_UNKNOWN;
    }
  _bfd_elf_link_hash_copy_indirect (info, dir, ind);
}

static bool
riscv_elf_record_tls_type (bfd *abfd, struct elf_link_hash_entry *h,
			   unsigned long symndx, char tls_type)
{
  char *new_tls_type = &_bfd_riscv_elf_tls_type (abfd, h, symndx);

  *new_tls_type |= tls_type;
  if ((*new_tls_type & GOT_NORMAL) && (*new_tls_type & ~GOT_NORMAL))
    {
      (*_bfd_error_handler)
	(_("%pB: `%s' accessed both as normal and thread local symbol"),
	 abfd, h ? h->root.root.string : "<local>");
      return false;
    }
  return true;
}

static bool
riscv_elf_record_got_reference (bfd *abfd, struct bfd_link_info *info,
				struct elf_link_hash_entry *h, long symndx)
{
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;

  if (htab->elf.sgot == NULL)
    {
      if (!riscv_elf_create_got_section (htab->elf.dynobj, info))
	return false;
    }

  if (h != NULL)
    {
      h->got.refcount += 1;
      return true;
    }

  /* This is a global offset table entry for a local symbol.  */
  if (elf_local_got_refcounts (abfd) == NULL)
    {
      bfd_size_type size = symtab_hdr->sh_info * (sizeof (bfd_vma) + 1);
      if (!(elf_local_got_refcounts (abfd) = bfd_zalloc (abfd, size)))
	return false;
      _bfd_riscv_elf_local_got_tls_type (abfd)
	= (char *) (elf_local_got_refcounts (abfd) + symtab_hdr->sh_info);
    }
  elf_local_got_refcounts (abfd) [symndx] += 1;

  return true;
}

static bool
bad_static_reloc (bfd *abfd, unsigned r_type, struct elf_link_hash_entry *h)
{
  reloc_howto_type * r = riscv_elf_rtype_to_howto (abfd, r_type);

  /* We propably can improve the information to tell users that they
     should be recompile the code with -fPIC or -fPIE, just like what
     x86 does.  */
  (*_bfd_error_handler)
    (_("%pB: relocation %s against `%s' can not be used when making a shared "
       "object; recompile with -fPIC"),
     abfd, r ? r->name : _("<unknown>"),
     h != NULL ? h->root.root.string : "a local symbol");
  bfd_set_error (bfd_error_bad_value);
  return false;
}

/* Look through the relocs for a section during the first phase, and
   allocate space in the global offset table or procedure linkage
   table.  */

static bool
riscv_elf_check_relocs (bfd *abfd, struct bfd_link_info *info,
			asection *sec, const Elf_Internal_Rela *relocs)
{
  struct riscv_elf_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  asection *sreloc = NULL;

  if (bfd_link_relocatable (info))
    return true;

  htab = riscv_elf_hash_table (info);
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (abfd);

  if (htab->elf.dynobj == NULL)
    htab->elf.dynobj = abfd;

  for (rel = relocs; rel < relocs + sec->reloc_count; rel++)
    {
      unsigned int r_type;
      unsigned int r_symndx;
      struct elf_link_hash_entry *h;
      bool is_abs_symbol = false;

      r_symndx = ELF32_R_SYM (rel->r_info);
      r_type = ELF32_R_TYPE (rel->r_info);

      if (r_symndx >= NUM_SHDR_ENTRIES (symtab_hdr))
	{
	  (*_bfd_error_handler) (_("%pB: bad symbol index: %d"),
				 abfd, r_symndx);
	  return false;
	}

      if (r_symndx < symtab_hdr->sh_info)
	{
	  /* A local symbol.  */
	  Elf_Internal_Sym *isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache,
							  abfd, r_symndx);
	  if (isym == NULL)
	    return false;

	  is_abs_symbol = isym->st_shndx == SHN_ABS ? true : false;

	  /* Check relocation against local STT_GNU_IFUNC symbol.  */
	  if (ELF_ST_TYPE (isym->st_info) == STT_GNU_IFUNC)
	    {
	      h = riscv_elf_get_local_sym_hash (htab, abfd, rel, true);
	      if (h == NULL)
		return false;

	      /* Fake STT_GNU_IFUNC global symbol.  */
	      h->root.root.string = bfd_elf_sym_name (abfd, symtab_hdr,
						      isym, NULL);
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

	  is_abs_symbol = bfd_is_abs_symbol (&h->root) ? true : false;
	}

      if (h != NULL)
	{
	  switch (r_type)
	    {
	    case R_RISCV_32:
	    case R_RISCV_64:
	    case R_RISCV_CALL:
	    case R_RISCV_CALL_PLT:
	    case R_RISCV_HI20:
	    case R_RISCV_GOT_HI20:
	    case R_RISCV_PCREL_HI20:
	      /* Create the ifunc sections, iplt and ipltgot, for static
		 executables.  */
	      if (h->type == STT_GNU_IFUNC
		  && !_bfd_elf_create_ifunc_sections (htab->elf.dynobj, info))
		return false;
	      break;

	    default:
	      break;
	    }

	  /* It is referenced by a non-shared object.  */
	  h->ref_regular = 1;
	}

      switch (r_type)
	{
	case R_RISCV_TLS_GD_HI20:
	  if (!riscv_elf_record_got_reference (abfd, info, h, r_symndx)
	      || !riscv_elf_record_tls_type (abfd, h, r_symndx, GOT_TLS_GD))
	    return false;
	  break;

	case R_RISCV_TLS_GOT_HI20:
	  if (bfd_link_dll (info))
	    info->flags |= DF_STATIC_TLS;
	  if (!riscv_elf_record_got_reference (abfd, info, h, r_symndx)
	      || !riscv_elf_record_tls_type (abfd, h, r_symndx, GOT_TLS_IE))
	    return false;
	  break;

	case R_RISCV_GOT_HI20:
	  if (!riscv_elf_record_got_reference (abfd, info, h, r_symndx)
	      || !riscv_elf_record_tls_type (abfd, h, r_symndx, GOT_NORMAL))
	    return false;
	  break;

	case R_RISCV_TLSDESC_HI20:
	  if (!riscv_elf_record_got_reference (abfd, info, h, r_symndx)
	      || !riscv_elf_record_tls_type (abfd, h, r_symndx, GOT_TLSDESC))
	    return false;
	  break;

	case R_RISCV_CALL:
	case R_RISCV_CALL_PLT:
	  /* These symbol requires a procedure linkage table entry.
	     We actually build the entry in adjust_dynamic_symbol,
	     because these might be a case of linking PIC code without
	     linking in any dynamic objects, in which case we don't
	     need to generate a procedure linkage table after all.  */

	  /* If it is a local symbol, then we resolve it directly
	     without creating a PLT entry.  */
	  if (h == NULL)
	    continue;

	  h->needs_plt = 1;
	  h->plt.refcount += 1;
	  break;

	case R_RISCV_PCREL_HI20:
	  if (h != NULL
	      && h->type == STT_GNU_IFUNC)
	    {
	      h->non_got_ref = 1;
	      h->pointer_equality_needed = 1;

	      /* We don't use the PCREL_HI20 in the data section,
		 so we always need the plt when it refers to
		 ifunc symbol.  */
	      h->plt.refcount += 1;
	    }

	  /* The non-preemptible absolute symbol shouldn't be referneced with
	     pc-relative relocation when generating shared object.  However,
	     PCREL_HI20/LO12 relocs are always bind locally when generating
	     shared object, so all absolute symbol referenced need to be
	     disallowed, except they are defined in linker script.

	     Maybe we should add this check for all pc-relative relocations,
	     please see pr28789 and pr25749 for details.  */
	  if (bfd_link_pic (info)
	      /* (h == NULL || SYMBOL_REFERENCES_LOCAL (info, h))  */
	      && is_abs_symbol)
	    {
	      if (h != NULL && (h)->root.ldscript_def)
		/* Disallow the absolute symbol defined in linker script here
		   will cause the glibc-linux toolchain build failed, so regard
		   them as pc-relative symbols, just like what x86 did.  */
		;
	      else
		{
		  const char *name;
		  if (h->root.root.string)
		    name = h->root.root.string;
		  else
		    {
		      Elf_Internal_Sym *sym;
		      sym = bfd_sym_from_r_symndx (&htab->elf.sym_cache, abfd,
						   r_symndx);
		      name = bfd_elf_sym_name (abfd, symtab_hdr, sym, NULL);
		    }

		  reloc_howto_type *r_t =
			riscv_elf_rtype_to_howto (abfd, r_type);
		  _bfd_error_handler
		    (_("%pB: relocation %s against absolute symbol `%s' can "
		       "not be used when making a shared object"),
		     abfd, r_t ? r_t->name : _("<unknown>"), name);
		  bfd_set_error (bfd_error_bad_value);
		  return false;
		}
	    }
	  /* Fall through.  */

	case R_RISCV_JAL:
	case R_RISCV_BRANCH:
	case R_RISCV_RVC_BRANCH:
	case R_RISCV_RVC_JUMP:
	  /* In shared libraries and pie, these relocs are known
	     to bind locally.  */
	  if (bfd_link_pic (info))
	    break;
	  goto static_reloc;

	case R_RISCV_TPREL_HI20:
	  /* This is not allowed in the pic, but okay in pie.  */
	  if (!bfd_link_executable (info))
	    return bad_static_reloc (abfd, r_type, h);
	  if (h != NULL)
	    riscv_elf_record_tls_type (abfd, h, r_symndx, GOT_TLS_LE);
	  break;

	case R_RISCV_HI20:
	  if (bfd_link_pic (info))
	    return bad_static_reloc (abfd, r_type, h);
	  goto static_reloc;

	case R_RISCV_32:
	  if (ARCH_SIZE > 32
	      && bfd_link_pic (info)
	      && (sec->flags & SEC_ALLOC) != 0)
	    {
	      if (is_abs_symbol)
		break;

	      reloc_howto_type *r_t = riscv_elf_rtype_to_howto (abfd, r_type);
	      _bfd_error_handler
		(_("%pB: relocation %s against non-absolute symbol `%s' can "
		   "not be used in RV32 when making a shared object"),
		 abfd, r_t ? r_t->name : _("<unknown>"),
		 h != NULL ? h->root.root.string : "a local symbol");
	      bfd_set_error (bfd_error_bad_value);
	      return false;
	    }
	  goto static_reloc;

	case R_RISCV_COPY:
	case R_RISCV_JUMP_SLOT:
	case R_RISCV_RELATIVE:
	case R_RISCV_64:
	  /* Fall through.  */

	static_reloc:

	  if (h != NULL
	      && (!bfd_link_pic (info)
		  || h->type == STT_GNU_IFUNC))
	    {
	      /* This reloc might not bind locally.  */
	      h->non_got_ref = 1;
	      h->pointer_equality_needed = 1;

	      if (!h->def_regular
		  || (sec->flags & (SEC_CODE | SEC_READONLY)) != 0)
		{
		  /* We may need a .plt entry if the symbol is a function
		     defined in a shared lib or is a function referenced
		     from the code or read-only section.  */
		  h->plt.refcount += 1;
		}
	    }

	  reloc_howto_type *r = riscv_elf_rtype_to_howto (abfd, r_type);
	  if (RISCV_NEED_DYNAMIC_RELOC (r->pc_relative, info, h, sec))
	    {
	      struct elf_dyn_relocs *p;
	      struct elf_dyn_relocs **head;

	      /* When creating a shared object, we must copy these
		 relocs into the output file.  We create a reloc
		 section in dynobj and make room for the reloc.  */
	      if (sreloc == NULL)
		{
		  sreloc = _bfd_elf_make_dynamic_reloc_section
		    (sec, htab->elf.dynobj, RISCV_ELF_LOG_WORD_BYTES,
		    abfd, /*rela?*/ true);

		  if (sreloc == NULL)
		    return false;
		}

	      /* If this is a global symbol, we count the number of
		 relocations we need for this symbol.  */
	      if (h != NULL)
		head = &h->dyn_relocs;
	      else
		{
		  /* Track dynamic relocs needed for local syms too.
		     We really need local syms available to do this
		     easily.  Oh well.  */

		  asection *s;
		  void *vpp;
		  Elf_Internal_Sym *isym;

		  isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache,
						abfd, r_symndx);
		  if (isym == NULL)
		    return false;

		  s = bfd_section_from_elf_index (abfd, isym->st_shndx);
		  if (s == NULL)
		    s = sec;

		  vpp = &elf_section_data (s)->local_dynrel;
		  head = (struct elf_dyn_relocs **) vpp;
		}

	      p = *head;
	      if (p == NULL || p->sec != sec)
		{
		  size_t amt = sizeof *p;
		  p = ((struct elf_dyn_relocs *)
		       bfd_alloc (htab->elf.dynobj, amt));
		  if (p == NULL)
		    return false;
		  p->next = *head;
		  *head = p;
		  p->sec = sec;
		  p->count = 0;
		  p->pc_count = 0;
		}

	      p->count += 1;
	      p->pc_count += r == NULL ? 0 : r->pc_relative;
	    }

	  break;

	default:
	  break;
	}
    }

  return true;
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.  */

static bool
riscv_elf_adjust_dynamic_symbol (struct bfd_link_info *info,
				 struct elf_link_hash_entry *h)
{
  struct riscv_elf_link_hash_table *htab;
  struct riscv_elf_link_hash_entry * eh;
  bfd *dynobj;
  asection *s, *srel;

  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);

  dynobj = htab->elf.dynobj;

  /* Make sure we know what is going on here.  */
  BFD_ASSERT (dynobj != NULL
	      && (h->needs_plt
		  || h->type == STT_GNU_IFUNC
		  || h->is_weakalias
		  || (h->def_dynamic
		      && h->ref_regular
		      && !h->def_regular)));

  /* If this is a function, put it in the procedure linkage table.  We
     will fill in the contents of the procedure linkage table later
     (although we could actually do it here).  */
  if (h->type == STT_FUNC || h->type == STT_GNU_IFUNC || h->needs_plt)
    {
      if (h->plt.refcount <= 0
	  || (h->type != STT_GNU_IFUNC
	      && (SYMBOL_CALLS_LOCAL (info, h)
		  || (ELF_ST_VISIBILITY (h->other) != STV_DEFAULT
		      && h->root.type == bfd_link_hash_undefweak))))
	{
	  /* This case can occur if we saw a R_RISCV_CALL_PLT reloc in an
	     input file, but the symbol was never referred to by a dynamic
	     object, or if all references were garbage collected.  In such
	     a case, we don't actually need to build a PLT entry.  */
	  h->plt.offset = (bfd_vma) -1;
	  h->needs_plt = 0;
	}

      return true;
    }
  else
    h->plt.offset = (bfd_vma) -1;

  /* If this is a weak symbol, and there is a real definition, the
     processor independent code will have arranged for us to see the
     real definition first, and we can just use the same value.  */
  if (h->is_weakalias)
    {
      struct elf_link_hash_entry *def = weakdef (h);
      BFD_ASSERT (def->root.type == bfd_link_hash_defined);
      h->root.u.def.section = def->root.u.def.section;
      h->root.u.def.value = def->root.u.def.value;
      return true;
    }

  /* This is a reference to a symbol defined by a dynamic object which
     is not a function.  */

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

  /* If we don't find any dynamic relocs in read-only sections, then
     we'll be keeping the dynamic relocs and avoiding the copy reloc.  */
  if (!_bfd_elf_readonly_dynrelocs (h))
    {
      h->non_got_ref = 0;
      return true;
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

  /* We must generate a R_RISCV_COPY reloc to tell the dynamic linker
     to copy the initial value out of the dynamic object and into the
     runtime process image.  We need to remember the offset into the
     .rel.bss section we are going to use.  */
  eh = (struct riscv_elf_link_hash_entry *) h;
  if (eh->tls_type & ~GOT_NORMAL)
    {
      s = htab->sdyntdata;
      srel = htab->elf.srelbss;
    }
  else if ((h->root.u.def.section->flags & SEC_READONLY) != 0)
    {
      s = htab->elf.sdynrelro;
      srel = htab->elf.sreldynrelro;
    }
  else
    {
      s = htab->elf.sdynbss;
      srel = htab->elf.srelbss;
    }
  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0)
    {
      srel->size += sizeof (Elf32_External_Rela);
      h->needs_copy = 1;
    }

  return _bfd_elf_adjust_dynamic_copy (info, h, s);
}

/* Allocate space in .plt, .got and associated reloc sections for
   dynamic relocs.  */

static bool
allocate_dynrelocs (struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info;
  struct riscv_elf_link_hash_table *htab;
  struct elf_dyn_relocs *p;

  if (h->root.type == bfd_link_hash_indirect)
    return true;

  info = (struct bfd_link_info *) inf;
  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);

  /* When we are generating pde, make sure gp symbol is output as a
     dynamic symbol.  Then ld.so can set the gp register earlier, before
     resolving the ifunc.  */
  if (!bfd_link_pic (info)
      && htab->elf.dynamic_sections_created
      && strcmp (h->root.root.string, RISCV_GP_SYMBOL) == 0
      && !bfd_elf_link_record_dynamic_symbol (info, h))
    return false;

  /* Since STT_GNU_IFUNC symbols must go through PLT, we handle them
     in the allocate_ifunc_dynrelocs and allocate_local_ifunc_dynrelocs,
     if they are defined and referenced in a non-shared object.  */
  if (h->type == STT_GNU_IFUNC
      && h->def_regular)
    return true;
  else if (htab->elf.dynamic_sections_created
	   && h->plt.refcount > 0)
    {
      /* Make sure this symbol is output as a dynamic symbol.
	 Undefined weak syms won't yet be marked as dynamic.  */
      if (h->dynindx == -1
	  && !h->forced_local
	  && h->root.type == bfd_link_hash_undefweak
	  && !bfd_elf_link_record_dynamic_symbol (info, h))
	return false;

      if (WILL_CALL_FINISH_DYNAMIC_SYMBOL (1, bfd_link_pic (info), h))
	{
	  asection *s = htab->elf.splt;

	  if (s->size == 0)
	    s->size = htab->plt_header_size;

	  h->plt.offset = s->size;

	  /* Make room for this entry.  */
	  s->size += htab->plt_entry_size;

	  /* We also need to make an entry in the .got.plt section.  */
	  htab->elf.sgotplt->size += GOT_ENTRY_SIZE;

	  /* We also need to make an entry in the .rela.plt section.  */
	  htab->elf.srelplt->size += sizeof (Elf32_External_Rela);

	  /* If this symbol is not defined in a regular file, and we are
	     not generating a shared library, then set the symbol to this
	     location in the .plt.  This is required to make function
	     pointers compare as equal between the normal executable and
	     the shared library.  */
	  if (! bfd_link_pic (info)
	      && !h->def_regular)
	    {
	      h->root.u.def.section = s;
	      h->root.u.def.value = h->plt.offset;
	    }

	  /* If the symbol has STO_RISCV_VARIANT_CC flag, then raise the
	     variant_cc flag of riscv_elf_link_hash_table.  */
	  if (h->other & STO_RISCV_VARIANT_CC)
	    htab->variant_cc = 1;
	}
      else
	{
	  h->plt.offset = (bfd_vma) -1;
	  h->needs_plt = 0;
	}
    }
  else
    {
      h->plt.offset = (bfd_vma) -1;
      h->needs_plt = 0;
    }

  if (h->got.refcount > 0)
    {
      asection *s;
      bool dyn = htab->elf.dynamic_sections_created;
      int tls_type = riscv_elf_hash_entry (h)->tls_type;

      /* Make sure this symbol is output as a dynamic symbol.
	 Undefined weak syms won't yet be marked as dynamic.  */
      if (dyn
	  && h->dynindx == -1
	  && !h->forced_local
	  && h->root.type == bfd_link_hash_undefweak
	  && !bfd_elf_link_record_dynamic_symbol (info, h))
	return false;

      s = htab->elf.sgot;
      h->got.offset = s->size;
      if (tls_type & (GOT_TLS_GD | GOT_TLS_IE | GOT_TLSDESC))
	{
	  int indx = 0;
	  bool need_reloc = false;
	  RISCV_TLS_GD_IE_NEED_DYN_RELOC(info, dyn, h, indx, need_reloc);

	  /* TLS_GD needs two dynamic relocs and two GOT slots.  */
	  if (tls_type & GOT_TLS_GD)
	    {
	      s->size += TLS_GD_GOT_ENTRY_SIZE;
	      if (need_reloc)
		htab->elf.srelgot->size += 2 * sizeof (Elf32_External_Rela);
	    }

	  /* TLS_IE needs one dynamic reloc and one GOT slot.  */
	  if (tls_type & GOT_TLS_IE)
	    {
	      s->size += TLS_IE_GOT_ENTRY_SIZE;
	      if (need_reloc)
		htab->elf.srelgot->size += sizeof (Elf32_External_Rela);
	    }

	  /* TLSDESC needs one dynamic reloc and two GOT slots.  */
	  if (tls_type & GOT_TLSDESC)
	    {
	      s->size += TLSDESC_GOT_ENTRY_SIZE;
	      /* TLSDESC always use dynamic relocs.  */
	      htab->elf.srelgot->size += sizeof (Elf32_External_Rela);
	    }
	}
      else
	{
	  s->size += GOT_ENTRY_SIZE;
	  if ((ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
	       || h->root.type != bfd_link_hash_undefweak)
	      && (bfd_link_pic (info)
		  || WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, 0, h))
	      && ! UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
	    htab->elf.srelgot->size += sizeof (Elf32_External_Rela);
	}
    }
  else
    h->got.offset = (bfd_vma) -1;

  if (h->dyn_relocs == NULL)
    return true;

  /* In the shared -Bsymbolic case, discard space allocated for
     dynamic pc-relative relocs against symbols which turn out to be
     defined in regular objects.  For the normal shared case, discard
     space for pc-relative relocs that have become local due to symbol
     visibility changes.  */

  if (bfd_link_pic (info))
    {
      if (SYMBOL_CALLS_LOCAL (info, h))
	{
	  struct elf_dyn_relocs **pp;

	  for (pp = &h->dyn_relocs; (p = *pp) != NULL; )
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
      if (h->dyn_relocs != NULL
	  && h->root.type == bfd_link_hash_undefweak)
	{
	  if (ELF_ST_VISIBILITY (h->other) != STV_DEFAULT
	      || UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
	    h->dyn_relocs = NULL;

	  /* Make sure undefined weak symbols are output as a dynamic
	     symbol in PIEs.  */
	  else if (h->dynindx == -1
		   && !h->forced_local
		   && !bfd_elf_link_record_dynamic_symbol (info, h))
	    return false;
	}
    }
  else
    {
      /* For the non-shared case, discard space for relocs against
	 symbols which turn out to need copy relocs or are not
	 dynamic.  */

      if (!h->non_got_ref
	  && ((h->def_dynamic
	       && !h->def_regular)
	      || (htab->elf.dynamic_sections_created
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

    keep: ;
    }

  /* Finally, allocate space.  */
  for (p = h->dyn_relocs; p != NULL; p = p->next)
    {
      if (discarded_section (p->sec))
	continue;
      asection *sreloc = elf_section_data (p->sec)->sreloc;
      sreloc->size += p->count * sizeof (Elf32_External_Rela);
    }

  return true;
}

/* Allocate space in .plt, .got and associated reloc sections for
   ifunc dynamic relocs.  */

static bool
allocate_ifunc_dynrelocs (struct elf_link_hash_entry *h,
			  void *inf)
{
  struct bfd_link_info *info;
  struct riscv_elf_link_hash_table *htab;

  if (h->root.type == bfd_link_hash_indirect)
    return true;

  if (h->root.type == bfd_link_hash_warning)
    h = (struct elf_link_hash_entry *) h->root.u.i.link;

  info = (struct bfd_link_info *) inf;
  htab = riscv_elf_hash_table (info);

  /* Since STT_GNU_IFUNC symbol must go through PLT, we handle it
     here if it is defined and referenced in a non-shared object.  */
  if (h->type == STT_GNU_IFUNC
      && h->def_regular)
    return _bfd_elf_allocate_ifunc_dyn_relocs (info, h,
					       &h->dyn_relocs,
					       htab->plt_entry_size,
					       htab->plt_header_size,
					       GOT_ENTRY_SIZE,
					       true);
  return true;
}

/* Allocate space in .plt, .got and associated reloc sections for
   local ifunc dynamic relocs.  */

static int
allocate_local_ifunc_dynrelocs (void **slot, void *inf)
{
  struct elf_link_hash_entry *h
    = (struct elf_link_hash_entry *) *slot;

  if (h->type != STT_GNU_IFUNC
      || !h->def_regular
      || !h->ref_regular
      || !h->forced_local
      || h->root.type != bfd_link_hash_defined)
    abort ();

  return allocate_ifunc_dynrelocs (h, inf);
}

static bool
riscv_elf_late_size_sections (bfd *output_bfd, struct bfd_link_info *info)
{
  struct riscv_elf_link_hash_table *htab;
  bfd *dynobj;
  asection *s;
  bfd *ibfd;

  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);
  dynobj = htab->elf.dynobj;
  if (dynobj == NULL)
    return true;

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      /* Set the contents of the .interp section to the interpreter.  */
      if (bfd_link_executable (info) && !info->nointerp)
	{
	  s = elf_hash_table (info)->interp;
	  BFD_ASSERT (s != NULL);
	  s->size = strlen (ELF32_DYNAMIC_INTERPRETER) + 1;
	  s->contents = (unsigned char *) ELF32_DYNAMIC_INTERPRETER;
	  s->alloced = 1;
	}
    }

  /* Set up .got offsets for local syms, and space for local dynamic
     relocs.  */
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      bfd_signed_vma *local_got;
      bfd_signed_vma *end_local_got;
      char *local_tls_type;
      bfd_size_type locsymcount;
      Elf_Internal_Shdr *symtab_hdr;
      asection *srel;

      if (! is_riscv_elf (ibfd))
	continue;

      for (s = ibfd->sections; s != NULL; s = s->next)
	{
	  struct elf_dyn_relocs *p;

	  for (p = elf_section_data (s)->local_dynrel; p != NULL; p = p->next)
	    {
	      if (!bfd_is_abs_section (p->sec)
		  && bfd_is_abs_section (p->sec->output_section))
		{
		  /* Input section has been discarded, either because
		     it is a copy of a linkonce section or due to
		     linker script /DISCARD/, so we'll be discarding
		     the relocs too.  */
		}
	      else if (p->count != 0)
		{
		  srel = elf_section_data (p->sec)->sreloc;
		  srel->size += p->count * sizeof (Elf32_External_Rela);
		  if ((p->sec->output_section->flags & SEC_READONLY) != 0)
		    info->flags |= DF_TEXTREL;
		}
	    }
	}

      local_got = elf_local_got_refcounts (ibfd);
      if (!local_got)
	continue;

      symtab_hdr = &elf_symtab_hdr (ibfd);
      locsymcount = symtab_hdr->sh_info;
      end_local_got = local_got + locsymcount;
      local_tls_type = _bfd_riscv_elf_local_got_tls_type (ibfd);
      s = htab->elf.sgot;
      srel = htab->elf.srelgot;
      for (; local_got < end_local_got; ++local_got, ++local_tls_type)
	{
	  if (*local_got > 0)
	    {
	      *local_got = s->size;
	      if (*local_tls_type & (GOT_TLS_GD | GOT_TLS_IE | GOT_TLSDESC))
		{
		  if (*local_tls_type & GOT_TLS_GD)
		    {
		      s->size += TLS_GD_GOT_ENTRY_SIZE;
		      if (bfd_link_dll (info))
			srel->size += sizeof (Elf32_External_Rela);
		    }
		  if (*local_tls_type & GOT_TLS_IE)
		    {
		      s->size += TLS_IE_GOT_ENTRY_SIZE;
		      if (bfd_link_dll (info))
			srel->size += sizeof (Elf32_External_Rela);
		    }
		  if (*local_tls_type & GOT_TLSDESC)
		    {
		      s->size += TLSDESC_GOT_ENTRY_SIZE;
		      srel->size += sizeof (Elf32_External_Rela);
		    }
		}
	      else
		{
		  s->size += GOT_ENTRY_SIZE;
		  if (bfd_link_pic (info))
		    srel->size += sizeof (Elf32_External_Rela);
		}
	    }
	  else
	    *local_got = (bfd_vma) -1;
	}
    }

  /* Allocate .plt and .got entries and space dynamic relocs for
     global symbols.  */
  elf_link_hash_traverse (&htab->elf, allocate_dynrelocs, info);

  /* Allocate .plt and .got entries and space dynamic relocs for
     global ifunc symbols.  */
  elf_link_hash_traverse (&htab->elf, allocate_ifunc_dynrelocs, info);

  /* Allocate .plt and .got entries and space dynamic relocs for
     local ifunc symbols.  */
  htab_traverse (htab->loc_hash_table, allocate_local_ifunc_dynrelocs, info);

  /* Used to resolve the dynamic relocs overwite problems when
     generating static executable.  */
  if (htab->elf.irelplt)
    htab->last_iplt_index = htab->elf.irelplt->reloc_count - 1;

  if (htab->elf.sgotplt)
    {
      struct elf_link_hash_entry *got;
      got = elf_link_hash_lookup (elf_hash_table (info),
				  "_GLOBAL_OFFSET_TABLE_",
				  false, false, false);

      /* Don't allocate .got.plt section if there are no GOT nor PLT
	 entries and there is no refeence to _GLOBAL_OFFSET_TABLE_.  */
      if ((got == NULL
	   || !got->ref_regular_nonweak)
	  && (htab->elf.sgotplt->size == GOTPLT_HEADER_SIZE)
	  && (htab->elf.splt == NULL
	      || htab->elf.splt->size == 0)
	  && (htab->elf.sgot == NULL
	      || (htab->elf.sgot->size
		  == get_elf_backend_data (output_bfd)->got_header_size)))
	htab->elf.sgotplt->size = 0;
    }

  /* The check_relocs and adjust_dynamic_symbol entry points have
     determined the sizes of the various dynamic sections.  Allocate
     memory for them.  */
  for (s = dynobj->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
	continue;

      if (s == htab->elf.splt
	  || s == htab->elf.sgot
	  || s == htab->elf.sgotplt
	  || s == htab->elf.iplt
	  || s == htab->elf.igotplt
	  || s == htab->elf.sdynbss
	  || s == htab->elf.sdynrelro
	  || s == htab->sdyntdata)
	{
	  /* Strip this section if we don't need it; see the
	     comment below.  */
	}
      else if (startswith (s->name, ".rela"))
	{
	  if (s->size != 0)
	    {
	      /* We use the reloc_count field as a counter if we need
		 to copy relocs into the output file.  */
	      s->reloc_count = 0;
	    }
	}
      else
	{
	  /* It's not one of our sections.  */
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

      /* Allocate memory for the section contents.  Zero the memory
	 for the benefit of .rela.plt, which has 4 unused entries
	 at the beginning, and we don't want garbage.  */
      s->contents = (bfd_byte *) bfd_zalloc (dynobj, s->size);
      if (s->contents == NULL)
	return false;
      s->alloced = 1;
    }

  /* Add dynamic entries.  */
  if (elf_hash_table (info)->dynamic_sections_created)
    {
      if (!_bfd_elf_add_dynamic_tags (output_bfd, info, true))
	return false;

      if (htab->variant_cc
	  && !_bfd_elf_add_dynamic_entry (info, DT_RISCV_VARIANT_CC, 0))
       return false;
    }

  return true;
}

#define TP_OFFSET 0
#define DTP_OFFSET 0x800

/* Return the relocation value for a TLS dtp-relative reloc.  */

static bfd_vma
dtpoff (struct bfd_link_info *info, bfd_vma address)
{
  /* If tls_sec is NULL, we should have signalled an error already.  */
  if (elf_hash_table (info)->tls_sec == NULL)
    return 0;
  return address - elf_hash_table (info)->tls_sec->vma - DTP_OFFSET;
}

/* Return the relocation value for a static TLS tp-relative relocation.  */

static bfd_vma
tpoff (struct bfd_link_info *info, bfd_vma address)
{
  /* If tls_sec is NULL, we should have signalled an error already.  */
  if (elf_hash_table (info)->tls_sec == NULL)
    return 0;
  return address - elf_hash_table (info)->tls_sec->vma - TP_OFFSET;
}

/* Return the relocation value for a static TLSDESC relocation.  */

static bfd_vma
tlsdescoff (struct bfd_link_info *info, bfd_vma address)
{
  /* If tls_sec is NULL, we should have signalled an error already.  */
  if (elf_hash_table (info)->tls_sec == NULL)
    return 0;
  return address - elf_hash_table (info)->tls_sec->vma;
}

/* Return the global pointer's value, or 0 if it is not in use.  */

static bfd_vma
riscv_global_pointer_value (struct bfd_link_info *info)
{
  struct bfd_link_hash_entry *h;

  h = bfd_link_hash_lookup (info->hash, RISCV_GP_SYMBOL, false, false, true);
  if (h == NULL || h->type != bfd_link_hash_defined)
    return 0;

  return h->u.def.value + sec_addr (h->u.def.section);
}

/* Emplace a static relocation.  */

static bfd_reloc_status_type
perform_relocation (const reloc_howto_type *howto,
		    const Elf_Internal_Rela *rel,
		    bfd_vma value,
		    asection *input_section,
		    bfd *input_bfd,
		    bfd_byte *contents)
{
  if (howto->pc_relative)
    value -= sec_addr (input_section) + rel->r_offset;

  /* PR31179, ignore the non-zero addend of R_RISCV_SUB_ULEB128.  */
  if (ELF32_R_TYPE (rel->r_info) != R_RISCV_SUB_ULEB128)
    value += rel->r_addend;

  switch (ELF32_R_TYPE (rel->r_info))
    {
    case R_RISCV_HI20:
    case R_RISCV_TPREL_HI20:
    case R_RISCV_PCREL_HI20:
    case R_RISCV_GOT_HI20:
    case R_RISCV_TLS_GOT_HI20:
    case R_RISCV_TLS_GD_HI20:
    case R_RISCV_TLSDESC_HI20:
      if (ARCH_SIZE > 32 && !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (value)))
	return bfd_reloc_overflow;
      value = ENCODE_UTYPE_IMM (RISCV_CONST_HIGH_PART (value));
      break;

    case R_RISCV_LO12_I:
    case R_RISCV_GPREL_I:
    case R_RISCV_TPREL_LO12_I:
    case R_RISCV_TPREL_I:
    case R_RISCV_PCREL_LO12_I:
    case R_RISCV_TLSDESC_LOAD_LO12:
    case R_RISCV_TLSDESC_ADD_LO12:
      value = ENCODE_ITYPE_IMM (value);
      break;

    case R_RISCV_LO12_S:
    case R_RISCV_GPREL_S:
    case R_RISCV_TPREL_LO12_S:
    case R_RISCV_TPREL_S:
    case R_RISCV_PCREL_LO12_S:
      value = ENCODE_STYPE_IMM (value);
      break;

    case R_RISCV_CALL:
    case R_RISCV_CALL_PLT:
      if (ARCH_SIZE > 32 && !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (value)))
	return bfd_reloc_overflow;
      value = ENCODE_UTYPE_IMM (RISCV_CONST_HIGH_PART (value))
	      | (ENCODE_ITYPE_IMM (value) << 32);
      break;

    case R_RISCV_JAL:
      if (!VALID_JTYPE_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_JTYPE_IMM (value);
      break;

    case R_RISCV_BRANCH:
      if (!VALID_BTYPE_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_BTYPE_IMM (value);
      break;

    case R_RISCV_RVC_BRANCH:
      if (!VALID_CBTYPE_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_CBTYPE_IMM (value);
      break;

    case R_RISCV_RVC_JUMP:
      if (!VALID_CJTYPE_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_CJTYPE_IMM (value);
      break;

    case R_RISCV_RVC_LUI:
      if (RISCV_CONST_HIGH_PART (value) == 0)
	{
	  /* Linker relaxation can convert an address equal to or greater than
	     0x800 to slightly below 0x800.  C.LUI does not accept zero as a
	     valid immediate.  We can fix this by converting it to a C.LI.  */
	  bfd_vma insn = riscv_get_insn (howto->bitsize,
					 contents + rel->r_offset);
	  insn = (insn & ~MATCH_C_LUI) | MATCH_C_LI;
	  riscv_put_insn (howto->bitsize, insn, contents + rel->r_offset);
	  value = ENCODE_CITYPE_IMM (0);
	}
      else if (!VALID_CITYPE_LUI_IMM (RISCV_CONST_HIGH_PART (value)))
	return bfd_reloc_overflow;
      else
	value = ENCODE_CITYPE_LUI_IMM (RISCV_CONST_HIGH_PART (value));
      break;

    /* R_RISCV_SET_ULEB128 won't go into here.  */
    case R_RISCV_SUB_ULEB128:
      {
	unsigned int len = 0;
	_bfd_read_unsigned_leb128 (input_bfd, contents + rel->r_offset, &len);

	/* Clean the contents value to zero (0x80), but keep the original
	   length.  */
	bfd_byte *p = contents + rel->r_offset;
	bfd_byte *endp = p + len - 1;
	memset (p, 0x80, len - 1);
	*(endp) = 0;

	/* Make sure the length of the new uleb128 value within the
	   original (available) length.  */
	unsigned int new_len = 0;
	unsigned int val_t = value;
	do
	  {
	    new_len++;
	    val_t >>= 7;
	  }
	while (val_t);
	if (new_len > len)
	  {
	    _bfd_error_handler
	      (_("final size of uleb128 value at offset 0x%lx in %pA from "
		 "%pB exceeds available space"),
	       (long) rel->r_offset, input_section, input_bfd);
	    return bfd_reloc_dangerous;
	  }
	else
	  {
	    p = _bfd_write_unsigned_leb128 (p, endp, value);
	    BFD_ASSERT (p);

	    /* If the length of the value is reduced and shorter than the
	       original uleb128 length, then _bfd_write_unsigned_leb128 may
	       clear the 0x80 to 0x0 for the last byte that was written.
	       So reset it to keep the the original uleb128 length.  */
	    if (--p < endp)
	      *p |= 0x80;
	  }
	return bfd_reloc_ok;
      }

    case R_RISCV_32:
    case R_RISCV_64:
    case R_RISCV_ADD8:
    case R_RISCV_ADD16:
    case R_RISCV_ADD32:
    case R_RISCV_ADD64:
    case R_RISCV_SUB6:
    case R_RISCV_SUB8:
    case R_RISCV_SUB16:
    case R_RISCV_SUB32:
    case R_RISCV_SUB64:
    case R_RISCV_SET6:
    case R_RISCV_SET8:
    case R_RISCV_SET16:
    case R_RISCV_SET32:
    case R_RISCV_32_PCREL:
    case R_RISCV_TLS_DTPREL32:
    case R_RISCV_TLS_DTPREL64:
      break;

    case R_RISCV_DELETE:
      return bfd_reloc_ok;

    default:
      return bfd_reloc_notsupported;
    }

  bfd_vma word;
  if (riscv_is_insn_reloc (howto))
    word = riscv_get_insn (howto->bitsize, contents + rel->r_offset);
  else
    word = bfd_get (howto->bitsize, input_bfd, contents + rel->r_offset);
  word = (word & ~howto->dst_mask) | (value & howto->dst_mask);
  if (riscv_is_insn_reloc (howto))
    riscv_put_insn (howto->bitsize, word, contents + rel->r_offset);
  else
    bfd_put (howto->bitsize, input_bfd, word, contents + rel->r_offset);

  return bfd_reloc_ok;
}

/* Remember all PC-relative high-part relocs we've encountered to help us
   later resolve the corresponding low-part relocs.  */

typedef struct
{
  /* PC value.  */
  bfd_vma address;
  /* Relocation value with addend.  */
  bfd_vma value;
  /* Original reloc type.  */
  int type;
  /* True if changed to R_RISCV_HI20.  */
  bool absolute;
} riscv_pcrel_hi_reloc;

typedef struct riscv_pcrel_lo_reloc
{
  /* PC value of auipc.  */
  bfd_vma address;
  /* Internal relocation.  */
  Elf_Internal_Rela *reloc;
  /* Record the following information helps to resolve the %pcrel
     which cross different input section.  For now we build a hash
     for pcrel at the start of riscv_elf_relocate_section, and then
     free the hash at the end.  But riscv_elf_relocate_section only
     handles an input section at a time, so that means we can only
     resolve the %pcrel_hi and %pcrel_lo which are in the same input
     section.  Otherwise, we will report dangerous relocation errors
     for those %pcrel which are not in the same input section.  */
  asection *input_section;
  struct bfd_link_info *info;
  reloc_howto_type *howto;
  bfd_byte *contents;
  /* The next riscv_pcrel_lo_reloc.  */
  struct riscv_pcrel_lo_reloc *next;
} riscv_pcrel_lo_reloc;

typedef struct
{
  /* Hash table for riscv_pcrel_hi_reloc.  */
  htab_t hi_relocs;
  /* Linked list for riscv_pcrel_lo_reloc.  */
  riscv_pcrel_lo_reloc *lo_relocs;
} riscv_pcrel_relocs;

static hashval_t
riscv_pcrel_reloc_hash (const void *entry)
{
  const riscv_pcrel_hi_reloc *e = entry;
  return (hashval_t)(e->address >> 2);
}

static int
riscv_pcrel_reloc_eq (const void *entry1, const void *entry2)
{
  const riscv_pcrel_hi_reloc *e1 = entry1, *e2 = entry2;
  return e1->address == e2->address;
}

static bool
riscv_init_pcrel_relocs (riscv_pcrel_relocs *p)
{
  p->lo_relocs = NULL;
  p->hi_relocs = htab_create (1024, riscv_pcrel_reloc_hash,
			      riscv_pcrel_reloc_eq, free);
  return p->hi_relocs != NULL;
}

static void
riscv_free_pcrel_relocs (riscv_pcrel_relocs *p)
{
  riscv_pcrel_lo_reloc *cur = p->lo_relocs;

  while (cur != NULL)
    {
      riscv_pcrel_lo_reloc *next = cur->next;
      free (cur);
      cur = next;
    }

  htab_delete (p->hi_relocs);
}

static bool
riscv_zero_pcrel_hi_reloc (Elf_Internal_Rela *rel,
			   struct bfd_link_info *info,
			   bfd_vma pc,
			   bfd_vma *addr,
			   bfd_byte *contents,
			   const reloc_howto_type *howto)
{
  /* We may need to reference low addreses in PC-relative modes even when the
     PC is far away from these addresses.  For example, undefweak references
     need to produce the address 0 when linked.  As 0 is far from the arbitrary
     addresses that we can link PC-relative programs at, the linker can't
     actually relocate references to those symbols.  In order to allow these
     programs to work we simply convert the PC-relative auipc sequences to
     0-relative lui sequences.  */
  if (bfd_link_pic (info))
    return false;

  /* If it's possible to reference the symbol using auipc we do so, as that's
     more in the spirit of the PC-relative relocations we're processing.  */
  bfd_vma offset = *addr - pc;
  if (ARCH_SIZE == 32 || VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (offset)))
    return false;

  /* If it's impossible to reference this with a LUI-based offset then don't
     bother to convert it at all so users still see the PC-relative relocation
     in the truncation message.  */
  if (ARCH_SIZE > 32 && !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (*addr)))
    return false;

  /* PR27180, encode target absolute address into r_addend rather than
     r_sym.  Clear the ADDR to avoid duplicate relocate in the
     perform_relocation.  */
  rel->r_info = ELF32_R_INFO (0, R_RISCV_HI20);
  rel->r_addend += *addr;
  *addr = 0;

  bfd_vma insn = riscv_get_insn (howto->bitsize, contents + rel->r_offset);
  insn = (insn & ~MASK_AUIPC) | MATCH_LUI;
  riscv_put_insn (howto->bitsize, insn, contents + rel->r_offset);
  return true;
}

static bool
riscv_record_pcrel_hi_reloc (riscv_pcrel_relocs *p,
			     bfd_vma addr,
			     bfd_vma value,
			     int type,
			     bool absolute)
{
  bfd_vma offset = absolute ? value : value - addr;
  riscv_pcrel_hi_reloc entry = {addr, offset, type, absolute};
  riscv_pcrel_hi_reloc **slot =
    (riscv_pcrel_hi_reloc **) htab_find_slot (p->hi_relocs, &entry, INSERT);

  BFD_ASSERT (*slot == NULL);
  *slot = (riscv_pcrel_hi_reloc *) bfd_malloc (sizeof (riscv_pcrel_hi_reloc));
  if (*slot == NULL)
    return false;
  **slot = entry;
  return true;
}

static bool
riscv_record_pcrel_lo_reloc (riscv_pcrel_relocs *p,
			     bfd_vma addr,
			     Elf_Internal_Rela *reloc,
			     asection *input_section,
			     struct bfd_link_info *info,
			     reloc_howto_type *howto,
			     bfd_byte *contents)
{
  riscv_pcrel_lo_reloc *entry;
  entry = (riscv_pcrel_lo_reloc *) bfd_malloc (sizeof (riscv_pcrel_lo_reloc));
  if (entry == NULL)
    return false;
  *entry = (riscv_pcrel_lo_reloc) {addr, reloc, input_section, info,
				   howto, contents, p->lo_relocs};
  p->lo_relocs = entry;
  return true;
}

static bool
riscv_resolve_pcrel_lo_relocs (riscv_pcrel_relocs *p)
{
  riscv_pcrel_lo_reloc *r;

  for (r = p->lo_relocs; r != NULL; r = r->next)
    {
      bfd *input_bfd = r->input_section->owner;

      riscv_pcrel_hi_reloc search = {r->address, 0, 0, 0};
      riscv_pcrel_hi_reloc *entry = htab_find (p->hi_relocs, &search);
      /* There may be a risk if the %pcrel_lo with addend refers to
	 an IFUNC symbol.  The %pcrel_hi has been relocated to plt,
	 so the corresponding %pcrel_lo with addend looks wrong.  */
      char *string = NULL;
      if (entry == NULL)
	string = _("%pcrel_lo missing matching %pcrel_hi");
      else if (entry->type == R_RISCV_GOT_HI20
	       && r->reloc->r_addend != 0)
	string = _("%pcrel_lo with addend isn't allowed for R_RISCV_GOT_HI20");
      else if (RISCV_CONST_HIGH_PART (entry->value)
	       != RISCV_CONST_HIGH_PART (entry->value + r->reloc->r_addend))
	{
	  /* Check the overflow when adding reloc addend.  */
	  string = bfd_asprintf (_("%%pcrel_lo overflow with an addend,"
				   " the value of %%pcrel_hi is 0x%" PRIx64
				   " without any addend, but may be 0x%" PRIx64
				   " after adding the %%pcrel_lo addend"),
				 (int64_t) RISCV_CONST_HIGH_PART (entry->value),
				 (int64_t) RISCV_CONST_HIGH_PART
				 (entry->value + r->reloc->r_addend));
	  if (string == NULL)
	    string = _("%pcrel_lo overflow with an addend");
	}

      if (string != NULL)
	{
	  (*r->info->callbacks->reloc_dangerous)
	    (r->info, string, input_bfd, r->input_section, r->reloc->r_offset);
	  return true;
	}

      perform_relocation (r->howto, r->reloc, entry->value, r->input_section,
			  input_bfd, r->contents);

      /* The corresponding R_RISCV_GOT_PCREL_HI20 and R_RISCV_PCREL_HI20 are
	 converted to R_RISCV_HI20, so try to convert R_RISCV_PCREL_LO12_I/S
	 to R_RISCV_LO12_I/S.  */
      if (entry->absolute)
	{
	  switch (ELF32_R_TYPE (r->reloc->r_info))
	    {
	    case R_RISCV_PCREL_LO12_I:
	      r->reloc->r_info = ELF32_R_INFO (0, R_RISCV_LO12_I);
	      r->reloc->r_addend += entry->value;
	      break;
	    case R_RISCV_PCREL_LO12_S:
	      r->reloc->r_info = ELF32_R_INFO (0, R_RISCV_LO12_S);
	      r->reloc->r_addend += entry->value;
	      break;
	    default:
	      /* This shouldn't happen, so just skip it.  */
	      break;
	    }
	}
    }

  return true;
}

/* Relocate a RISC-V ELF section.

   The RELOCATE_SECTION function is called by the new ELF backend linker
   to handle the relocations for a section.

   The relocs are always passed as Rela structures.

   This function is responsible for adjusting the section contents as
   necessary, and (if generating a relocatable output file) adjusting
   the reloc addend as necessary.

   This function does not have to worry about setting the reloc
   address or the reloc symbol index.

   LOCAL_SYMS is a pointer to the swapped in local symbols.

   LOCAL_SECTIONS is an array giving the section in the input file
   corresponding to the st_shndx field of each local symbol.

   The global hash table entry for the global symbols can be found
   via elf_sym_hashes (input_bfd).

   When generating relocatable output, this function must handle
   STB_LOCAL/STT_SECTION symbols specially.  The output symbol is
   going to be the section symbol corresponding to the output
   section, which means that the addend must be adjusted
   accordingly.  */

static int
riscv_elf_relocate_section (bfd *output_bfd,
			    struct bfd_link_info *info,
			    bfd *input_bfd,
			    asection *input_section,
			    bfd_byte *contents,
			    Elf_Internal_Rela *relocs,
			    Elf_Internal_Sym *local_syms,
			    asection **local_sections)
{
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;
  riscv_pcrel_relocs pcrel_relocs;
  bool ret = false;
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (input_bfd);
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (input_bfd);
  bfd_vma *local_got_offsets = elf_local_got_offsets (input_bfd);
  bfd_vma uleb128_set_vma = 0;
  Elf_Internal_Rela *uleb128_set_rel = NULL;
  bool absolute;

  if (!riscv_init_pcrel_relocs (&pcrel_relocs))
    return false;

  relend = relocs + input_section->reloc_count;
  for (rel = relocs; rel < relend; rel++)
    {
      unsigned long r_symndx;
      struct elf_link_hash_entry *h;
      Elf_Internal_Sym *sym;
      asection *sec;
      bfd_vma relocation;
      bfd_reloc_status_type r = bfd_reloc_ok;
      const char *name = NULL;
      bfd_vma off, ie_off, desc_off;
      bool unresolved_reloc, is_ie = false, is_desc = false;
      bfd_vma pc = sec_addr (input_section) + rel->r_offset;
      int r_type = ELF32_R_TYPE (rel->r_info), tls_type;
      reloc_howto_type *howto = riscv_elf_rtype_to_howto (input_bfd, r_type);
      const char *msg = NULL;
      bool resolved_to_zero;
      bool via_plt = false;
      bool relative_got = false;

      if (howto == NULL)
	continue;

      /* This is a final link.  */
      r_symndx = ELF32_R_SYM (rel->r_info);
      h = NULL;
      sym = NULL;
      sec = NULL;
      unresolved_reloc = false;
      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];
	  relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);

	  /* Relocate against local STT_GNU_IFUNC symbol.  */
	  if (!bfd_link_relocatable (info)
	      && ELF_ST_TYPE (sym->st_info) == STT_GNU_IFUNC)
	    {
	      h = riscv_elf_get_local_sym_hash (htab, input_bfd, rel, false);
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
	  if (warned)
	    {
	      /* To avoid generating warning messages about truncated
		 relocations, set the relocation's address to be the same as
		 the start of this section.  */
	      if (input_section->output_section != NULL)
		relocation = input_section->output_section->vma;
	      else
		relocation = 0;
	    }
	}

      if (sec != NULL && discarded_section (sec))
	RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					 rel, 1, relend, R_RISCV_NONE,
					 howto, 0, contents);

      if (bfd_link_relocatable (info))
	continue;

      /* Since STT_GNU_IFUNC symbol must go through PLT, we handle
	 it here if it is defined in a non-shared object.  */
      if (h != NULL
	  && h->type == STT_GNU_IFUNC
	  && h->def_regular)
	{
	  asection *plt, *base_got;

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
		continue;

	      abort ();
	    }
	  else if (h->plt.offset == (bfd_vma) -1
		   /* The following relocation may not need the .plt entries
		      when all references to a STT_GNU_IFUNC symbols are done
		      via GOT or static function pointers.  */
		   && r_type != R_RISCV_32
		   && r_type != R_RISCV_64
		   && r_type != R_RISCV_HI20
		   && r_type != R_RISCV_GOT_HI20
		   && r_type != R_RISCV_LO12_I
		   && r_type != R_RISCV_LO12_S)
	    goto bad_ifunc_reloc;

	  /* STT_GNU_IFUNC symbol must go through PLT.  */
	  plt = htab->elf.splt ? htab->elf.splt : htab->elf.iplt;
	  relocation = plt->output_section->vma
		       + plt->output_offset
		       + h->plt.offset;

	  switch (r_type)
	    {
	    case R_RISCV_32:
	    case R_RISCV_64:
	      if (rel->r_addend != 0)
		{
		  if (h->root.root.string)
		    name = h->root.root.string;
		  else
		    name = bfd_elf_sym_name (input_bfd, symtab_hdr, sym, NULL);

		  _bfd_error_handler
		    /* xgettext:c-format */
		    (_("%pB: relocation %s against STT_GNU_IFUNC "
		       "symbol `%s' has non-zero addend: %" PRId64),
		     input_bfd, howto->name, name, (int64_t) rel->r_addend);
		  bfd_set_error (bfd_error_bad_value);
		  return false;
		}

		/* Generate dynamic relocation only when there is a non-GOT
		   reference in a shared object or there is no PLT.  */
		if ((bfd_link_pic (info) && h->non_got_ref)
		    || h->plt.offset == (bfd_vma) -1)
		  {
		    Elf_Internal_Rela outrel;

		    /* Need a dynamic relocation to get the real function
		       address.  */
		    outrel.r_offset = _bfd_elf_section_offset (output_bfd,
							       info,
							       input_section,
							       rel->r_offset);
		    if (outrel.r_offset == (bfd_vma) -1
			|| outrel.r_offset == (bfd_vma) -2)
		      abort ();

		    outrel.r_offset += input_section->output_section->vma
				       + input_section->output_offset;

		    if (h->dynindx == -1
			|| h->forced_local
			|| bfd_link_executable (info))
		      {
			info->callbacks->minfo
			  (_("Local IFUNC function `%s' in %pB\n"),
			   h->root.root.string,
			   h->root.u.def.section->owner);

			/* This symbol is resolved locally.  */
			outrel.r_info = ELF32_R_INFO (0, R_RISCV_IRELATIVE);
			outrel.r_addend = h->root.u.def.value
			  + h->root.u.def.section->output_section->vma
			  + h->root.u.def.section->output_offset;
		      }
		    else
		      {
			outrel.r_info = ELF32_R_INFO (h->dynindx, r_type);
			outrel.r_addend = 0;
		      }

		    /* Dynamic relocations are stored in
		       1. .rela.ifunc section in PIC object.
		       2. .rela.got section in dynamic executable.
		       3. .rela.iplt section in static executable.  */
		    if (bfd_link_pic (info))
		      riscv_elf_append_rela (output_bfd, htab->elf.irelifunc,
					     &outrel);
		    else if (htab->elf.splt != NULL)
		      riscv_elf_append_rela (output_bfd, htab->elf.srelgot,
					     &outrel);
		    else
		      {
			/* Do not use riscv_elf_append_rela to add dynamic
			   relocs into .rela.iplt, since it may cause the
			   overwrite problems.  This is same as what we did
			   in the riscv_elf_finish_dynamic_symbol.  */
			const struct elf_backend_data *bed =
				get_elf_backend_data (output_bfd);
			bfd_vma iplt_idx = htab->last_iplt_index--;
			bfd_byte *loc = htab->elf.irelplt->contents
					+ iplt_idx * sizeof (Elf32_External_Rela);
			bed->s->swap_reloca_out (output_bfd, &outrel, loc);
		      }

		    /* If this reloc is against an external symbol, we
		       do not want to fiddle with the addend.  Otherwise,
		       we need to include the symbol value so that it
		       becomes an addend for the dynamic reloc.  For an
		       internal symbol, we have updated addend.  */
		    continue;
		  }
		goto do_relocation;

	      case R_RISCV_GOT_HI20:
		base_got = htab->elf.sgot;
		off = h->got.offset;

		if (base_got == NULL)
		  abort ();

		if (off == (bfd_vma) -1)
		  {
		    bfd_vma plt_idx;

		    /* We can't use h->got.offset here to save state, or
		       even just remember the offset, as finish_dynamic_symbol
		       would use that as offset into .got.  */

		    if (htab->elf.splt != NULL)
		      {
			plt_idx = (h->plt.offset - htab->plt_header_size)
				  / htab->plt_entry_size;
			off = GOTPLT_HEADER_SIZE + (plt_idx * GOT_ENTRY_SIZE);
			base_got = htab->elf.sgotplt;
		      }
		    else
		      {
			plt_idx = h->plt.offset / htab->plt_entry_size;
			off = plt_idx * GOT_ENTRY_SIZE;
			base_got = htab->elf.igotplt;
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
			   is done in the finish_dynamic_symbol routine.   */
			if ((off & 1) != 0)
			  off &= ~1;
			else
			  {
			    bfd_put_32 (output_bfd, relocation,
					base_got->contents + off);
			    /* Note that this is harmless for the case,
			       as -1 | 1 still is -1.  */
			    h->got.offset |= 1;
			  }
		      }
		  }

		relocation = base_got->output_section->vma
			     + base_got->output_offset + off;

		if (!riscv_record_pcrel_hi_reloc (&pcrel_relocs, pc,
						  relocation, r_type,
						  false))
		  r = bfd_reloc_overflow;
		goto do_relocation;

	      case R_RISCV_CALL:
	      case R_RISCV_CALL_PLT:
	      case R_RISCV_HI20:
	      case R_RISCV_LO12_I:
	      case R_RISCV_LO12_S:
		goto do_relocation;

	      case R_RISCV_PCREL_HI20:
		if (!riscv_record_pcrel_hi_reloc (&pcrel_relocs, pc,
						  relocation, r_type,
						  false))
		  r = bfd_reloc_overflow;
		goto do_relocation;

	    default:
	    bad_ifunc_reloc:
	      if (h->root.root.string)
		name = h->root.root.string;
	      else
		/* The entry of local ifunc is fake in global hash table,
		   we should find the name by the original local symbol.  */
		name = bfd_elf_sym_name (input_bfd, symtab_hdr, sym, NULL);

	      _bfd_error_handler
	      /* xgettext:c-format */
	      (_("%pB: relocation %s against STT_GNU_IFUNC "
		 "symbol `%s' isn't supported"), input_bfd,
	       howto->name, name);
	      bfd_set_error (bfd_error_bad_value);
	      return false;
	    }
	}

    skip_ifunc:
      if (h != NULL)
	name = h->root.root.string;
      else
	{
	  name = (bfd_elf_string_from_elf_section
		  (input_bfd, symtab_hdr->sh_link, sym->st_name));
	  if (name == NULL || *name == '\0')
	    name = bfd_section_name (sec);
	}

      resolved_to_zero = (h != NULL
			  && UNDEFWEAK_NO_DYNAMIC_RELOC (info, h));

      /* Refer to the PLT entry.  This check has to match the check in
	 _bfd_riscv_relax_section.  */
      via_plt = (htab->elf.splt != NULL
		 && h != NULL
		 && h->plt.offset != MINUS_ONE);

      switch (r_type)
	{
	case R_RISCV_NONE:
	case R_RISCV_RELAX:
	case R_RISCV_TPREL_ADD:
	case R_RISCV_TLSDESC_CALL:
	case R_RISCV_COPY:
	case R_RISCV_JUMP_SLOT:
	case R_RISCV_RELATIVE:
	  /* These require nothing of us at all.  */
	  continue;

	case R_RISCV_HI20:
	case R_RISCV_BRANCH:
	case R_RISCV_RVC_BRANCH:
	case R_RISCV_RVC_LUI:
	case R_RISCV_LO12_I:
	case R_RISCV_LO12_S:
	case R_RISCV_SET6:
	case R_RISCV_SET8:
	case R_RISCV_SET16:
	case R_RISCV_SET32:
	case R_RISCV_32_PCREL:
	case R_RISCV_DELETE:
	  /* These require no special handling beyond perform_relocation.  */
	  break;

	case R_RISCV_SET_ULEB128:
	  if (uleb128_set_rel == NULL)
	    {
	      /* Saved for later usage.  */
	      uleb128_set_vma = relocation;
	      uleb128_set_rel = rel;
	      continue;
	    }
	  else
	    {
	      msg = ("Mismatched R_RISCV_SET_ULEB128, it must be paired with"
		     " and applied before R_RISCV_SUB_ULEB128");
	      r = bfd_reloc_dangerous;
	    }
	  break;

	case R_RISCV_SUB_ULEB128:
	  if (uleb128_set_rel != NULL
	      && uleb128_set_rel->r_offset == rel->r_offset)
	    {
	      relocation = uleb128_set_vma - relocation
			   + uleb128_set_rel->r_addend;
	      uleb128_set_vma = 0;
	      uleb128_set_rel = NULL;

	      /* PR31179, the addend of SUB_ULEB128 should be zero if using
		 .uleb128, but we make it non-zero by accident in assembler,
		 so just ignore it in perform_relocation, and make assembler
		 continue doing the right thing.  Don't reset the addend of
		 SUB_ULEB128 to zero here since it will break the --emit-reloc,
		 even though the non-zero addend is unexpected.

		 We encourage people to rebuild their stuff to get the
		 non-zero addend of SUB_ULEB128, but that might need some
		 times, so report warnings to inform people need to rebuild
		 if --check-uleb128 is enabled.  However, since the failed
		 .reloc cases for ADD/SET/SUB/ULEB128 are rarely to use, it
		 may acceptable that stop supproting them until people rebuld
		 their stuff, maybe half-year or one year later.  I believe
		 this might be the least harmful option that we should go.

		 Or maybe we should teach people that don't write the
		 .reloc R_RISCV_SUB* with non-zero constant, and report
		 warnings/errors in assembler.  */
	      if (htab->params->check_uleb128
		  && rel->r_addend != 0)
		_bfd_error_handler (_("%pB: warning: R_RISCV_SUB_ULEB128 with"
				      " non-zero addend, please rebuild by"
				      " binutils 2.42 or up"), input_bfd);
	    }
	  else
	    {
	      msg = ("Mismatched R_RISCV_SUB_ULEB128, it must be paired with"
		     " and applied after R_RISCV_SET_ULEB128");
	      r = bfd_reloc_dangerous;
	    }
	  break;

	case R_RISCV_GOT_HI20:
	  if (h != NULL)
	    {
	      off = h->got.offset;
	      BFD_ASSERT (off != (bfd_vma) -1);

	      if (RISCV_RESOLVED_LOCALLY (info, h))
		{
		  /* We must initialize this entry in the global offset table.
		     Since the offset must always be a multiple of the word
		     size, we use the least significant bit to record whether
		     we have initialized it already.

		     When doing a dynamic link, we create a .rela.got
		     relocation entry to initialize the value.  This
		     is done in the finish_dynamic_symbol routine.  */
		  if ((off & 1) != 0)
		    off &= ~1;
		  else
		    {
		      /* If a symbol is not dynamic and is not undefined weak,
			 bind it locally and generate a RELATIVE relocation
			 under PIC mode.  */
		      if (h->dynindx == -1
			  && !h->forced_local
			  && h->root.type != bfd_link_hash_undefweak
			  && bfd_link_pic (info)
			  && !bfd_is_abs_section(h->root.u.def.section))
			relative_got = true;

		      bfd_put_32 (output_bfd, relocation,
				  htab->elf.sgot->contents + off);
		      h->got.offset |= 1;
		    }
		}
	      else
		unresolved_reloc = false;
	    }
	  else
	    {
	      BFD_ASSERT (local_got_offsets != NULL
			  && local_got_offsets[r_symndx] != (bfd_vma) -1);

	      off = local_got_offsets[r_symndx];

	      /* The offset must always be a multiple of the word size.
		 So, we can use the least significant bit to record
		 whether we have already processed this entry.  */
	      if ((off & 1) != 0)
		off &= ~1;
	      else
		{
		  if (bfd_link_pic (info))
		    relative_got = true;

		  bfd_put_32 (output_bfd, relocation,
			      htab->elf.sgot->contents + off);
		  local_got_offsets[r_symndx] |= 1;
		}
	    }

	  /* We need to generate a R_RISCV_RELATIVE relocation later in the
	     riscv_elf_finish_dynamic_symbol if h->dynindx != -1;  Otherwise,
	     generate a R_RISCV_RELATIVE relocation here now.  */
	  if (relative_got)
	    {
	      asection *s = htab->elf.srelgot;
	      BFD_ASSERT (s != NULL);

	      Elf_Internal_Rela outrel;
	      outrel.r_offset = sec_addr (htab->elf.sgot) + off;
	      outrel.r_info = ELF32_R_INFO (0, R_RISCV_RELATIVE);
	      outrel.r_addend = relocation;
	      riscv_elf_append_rela (output_bfd, s, &outrel);
	    }

	  if (rel->r_addend != 0)
	    {
	      msg = _("The addend isn't allowed for R_RISCV_GOT_HI20");
	      r = bfd_reloc_dangerous;
	    }
	  else
	    {
	      /* Address of got entry.  */
	      relocation = sec_addr (htab->elf.sgot) + off;
	      absolute = riscv_zero_pcrel_hi_reloc (rel, info, pc,
						    &relocation, contents,
						    howto);
	      /* Update howto if relocation is changed.  */
	      howto = riscv_elf_rtype_to_howto (input_bfd,
						ELF32_R_TYPE (rel->r_info));
	      if (howto == NULL)
		r = bfd_reloc_notsupported;
	      else if (!riscv_record_pcrel_hi_reloc (&pcrel_relocs, pc,
						     relocation + rel->r_addend,
						     r_type, absolute))
		r = bfd_reloc_overflow;
	    }
	  break;

	case R_RISCV_ADD8:
	case R_RISCV_ADD16:
	case R_RISCV_ADD32:
	case R_RISCV_ADD64:
	  {
	    bfd_vma old_value = bfd_get (howto->bitsize, input_bfd,
					 contents + rel->r_offset);
	    relocation = old_value + relocation;
	  }
	  break;

	case R_RISCV_SUB6:
	  {
	    bfd_vma old_value = bfd_get (howto->bitsize, input_bfd,
					 contents + rel->r_offset);
	    relocation = (old_value & ~howto->dst_mask)
			 | (((old_value & howto->dst_mask) - relocation)
			    & howto->dst_mask);
	  }
	  break;

	case R_RISCV_SUB8:
	case R_RISCV_SUB16:
	case R_RISCV_SUB32:
	case R_RISCV_SUB64:
	  {
	    bfd_vma old_value = bfd_get (howto->bitsize, input_bfd,
					 contents + rel->r_offset);
	    relocation = old_value - relocation;
	  }
	  break;

	case R_RISCV_CALL:
	case R_RISCV_CALL_PLT:
	  /* Handle a call to an undefined weak function.  This won't be
	     relaxed, so we have to handle it here.  */
	  if (h != NULL && h->root.type == bfd_link_hash_undefweak && !via_plt)
	    {
	      /* We can use x0 as the base register.  */
	      bfd_vma insn = bfd_getl32 (contents + rel->r_offset + 4);
	      insn &= ~(OP_MASK_RS1 << OP_SH_RS1);
	      bfd_putl32 (insn, contents + rel->r_offset + 4);
	      /* Set the relocation value so that we get 0 after the pc
		 relative adjustment.  */
	      relocation = sec_addr (input_section) + rel->r_offset;
	    }
	  /* Fall through.  */

	case R_RISCV_JAL:
	case R_RISCV_RVC_JUMP:
	  if (via_plt)
	    {
	      relocation = sec_addr (htab->elf.splt) + h->plt.offset;
	      unresolved_reloc = false;
	    }
	  else if (bfd_link_pic (info)
		   && h != NULL
		   && h->plt.offset == MINUS_ONE
		   && !SYMBOL_REFERENCES_LOCAL (info, h)
		   && (input_section->flags & SEC_ALLOC) != 0
		   && (input_section->flags & SEC_READONLY) != 0
		   && ELF_ST_VISIBILITY (h->other) == STV_DEFAULT)
	    {
	      /* PR 28509, when generating the shared object, these
		 referenced symbols may bind externally, which means
		 they will be exported to the dynamic symbol table,
		 and are preemptible by default.  These symbols cannot
		 be referenced by the non-pic relocations, like
		 R_RISCV_JAL and R_RISCV_RVC_JUMP relocations.

		 However, consider that linker may relax the R_RISCV_CALL
		 relocations to R_RISCV_JAL or R_RISCV_RVC_JUMP, if
		 these relocations are relocated to the plt entries,
		 then we won't report error for them.

		 Perhaps we also need the similar checks for the
		 R_RISCV_BRANCH and R_RISCV_RVC_BRANCH relocations.  */
	      msg = bfd_asprintf (_("%%X%%P: relocation %s against `%s'"
				    " which may bind externally"
				    " can not be used"
				    " when making a shared object;"
				    " recompile with -fPIC\n"),
				  howto->name, h->root.root.string);
	      r = bfd_reloc_notsupported;
	    }
	  break;

	case R_RISCV_TPREL_HI20:
	  relocation = tpoff (info, relocation);
	  break;

	case R_RISCV_TPREL_LO12_I:
	case R_RISCV_TPREL_LO12_S:
	  relocation = tpoff (info, relocation);
	  break;

	case R_RISCV_TPREL_I:
	case R_RISCV_TPREL_S:
	  relocation = tpoff (info, relocation);
	  if (VALID_ITYPE_IMM (relocation + rel->r_addend))
	    {
	      /* We can use tp as the base register.  */
	      bfd_vma insn = bfd_getl32 (contents + rel->r_offset);
	      insn &= ~(OP_MASK_RS1 << OP_SH_RS1);
	      insn |= X_TP << OP_SH_RS1;
	      bfd_putl32 (insn, contents + rel->r_offset);
	    }
	  else
	    r = bfd_reloc_overflow;
	  break;

	case R_RISCV_GPREL_I:
	case R_RISCV_GPREL_S:
	  {
	    bfd_vma gp = riscv_global_pointer_value (info);
	    bool x0_base = VALID_ITYPE_IMM (relocation + rel->r_addend);
	    if (x0_base || VALID_ITYPE_IMM (relocation + rel->r_addend - gp))
	      {
		/* We can use x0 or gp as the base register.  */
		bfd_vma insn = bfd_getl32 (contents + rel->r_offset);
		insn &= ~(OP_MASK_RS1 << OP_SH_RS1);
		if (!x0_base)
		  {
		    rel->r_addend -= gp;
		    insn |= X_GP << OP_SH_RS1;
		  }
		bfd_putl32 (insn, contents + rel->r_offset);
	      }
	    else
	      r = bfd_reloc_overflow;
	    break;
	  }

	case R_RISCV_PCREL_HI20:
	  absolute = riscv_zero_pcrel_hi_reloc (rel, info, pc, &relocation,
						contents, howto);
	  /* Update howto if relocation is changed.  */
	  howto = riscv_elf_rtype_to_howto (input_bfd,
					    ELF32_R_TYPE (rel->r_info));
	  if (howto == NULL)
	    r = bfd_reloc_notsupported;
	  else if (!riscv_record_pcrel_hi_reloc (&pcrel_relocs, pc,
						 relocation + rel->r_addend,
						 r_type, absolute))
	    r = bfd_reloc_overflow;
	  break;

	case R_RISCV_PCREL_LO12_I:
	case R_RISCV_PCREL_LO12_S:
	  /* We don't allow section symbols plus addends as the auipc address,
	     because then riscv_relax_delete_bytes would have to search through
	     all relocs to update these addends.  This is also ambiguous, as
	     we do allow offsets to be added to the target address, which are
	     not to be used to find the auipc address.  */
	  if (((sym != NULL && (ELF_ST_TYPE (sym->st_info) == STT_SECTION))
	       || (h != NULL && h->type == STT_SECTION))
	      && rel->r_addend)
	    {
	      msg = _("%pcrel_lo section symbol with an addend");
	      r = bfd_reloc_dangerous;
	      break;
	    }

	  if (riscv_record_pcrel_lo_reloc (&pcrel_relocs, relocation, rel,
					   input_section, info, howto,
					   contents))
	    continue;
	  r = bfd_reloc_overflow;
	  break;

	case R_RISCV_TLS_DTPREL32:
	case R_RISCV_TLS_DTPREL64:
	  relocation = dtpoff (info, relocation);
	  break;

	case R_RISCV_TLSDESC_LOAD_LO12:
	case R_RISCV_TLSDESC_ADD_LO12:
	  if (rel->r_addend)
	    {
	      msg = _("%tlsdesc_lo with addend");
	      r = bfd_reloc_dangerous;
	      break;
	    }

	  if (riscv_record_pcrel_lo_reloc (&pcrel_relocs, relocation, rel,
					   input_section, info, howto,
					   contents))
	      continue;
	  r = bfd_reloc_overflow;
	  break;

	case R_RISCV_32:
	  /* Non ABS symbol should be blocked in check_relocs.  */
	  if (ARCH_SIZE > 32)
	    break;
	  /* Fall through.  */

	case R_RISCV_64:
	  if ((input_section->flags & SEC_ALLOC) == 0)
	    break;

	  if (RISCV_GENERATE_DYNAMIC_RELOC (howto->pc_relative, info, h,
					    resolved_to_zero))
	    {
	      Elf_Internal_Rela outrel;
	      asection *sreloc;

	      /* When generating a shared object, these relocations
		 are copied into the output file to be resolved at run
		 time.  */

	      outrel.r_offset =
		_bfd_elf_section_offset (output_bfd, info, input_section,
					 rel->r_offset);
	      bool skip = false;
	      bool relocate = false;
	      if (outrel.r_offset == (bfd_vma) -1)
		skip = true;
	      else if (outrel.r_offset == (bfd_vma) -2)
		{
		  skip = true;
		  relocate = true;
		}
	      else if (h != NULL && bfd_is_abs_symbol (&h->root))
		{
		  /* Don't need dynamic reloc when the ABS symbol is
		     non-dynamic or forced to local.  Maybe just use
		     SYMBOL_REFERENCES_LOCAL to check?  */
		  skip = (h->forced_local || (h->dynindx == -1));
		  relocate = skip;
		}

	      outrel.r_offset += sec_addr (input_section);

	      if (skip)
		memset (&outrel, 0, sizeof outrel);	/* R_RISCV_NONE.  */
	      else if (RISCV_COPY_INPUT_RELOC (info, h))
		{
		  /* Maybe just use !SYMBOL_REFERENCES_LOCAL to check?  */
		  outrel.r_info = ELF32_R_INFO (h->dynindx, r_type);
		  outrel.r_addend = rel->r_addend;
		}
	      else
		{
		  /* This symbol is local, or marked to become local.  */
		  outrel.r_info = ELF32_R_INFO (0, R_RISCV_RELATIVE);
		  outrel.r_addend = relocation + rel->r_addend;
		}

	      sreloc = elf_section_data (input_section)->sreloc;
	      riscv_elf_append_rela (output_bfd, sreloc, &outrel);
	      if (!relocate)
		continue;
	    }
	  break;

	case R_RISCV_TLSDESC_HI20:
	  is_desc = true;
	  goto tls;

	case R_RISCV_TLS_GOT_HI20:
	  is_ie = true;
	  goto tls;

	case R_RISCV_TLS_GD_HI20:
	tls:
	  if (h != NULL)
	    {
	      off = h->got.offset;
	      h->got.offset |= 1;
	    }
	  else
	    {
	      off = local_got_offsets[r_symndx];
	      local_got_offsets[r_symndx] |= 1;
	    }

	  tls_type = _bfd_riscv_elf_tls_type (input_bfd, h, r_symndx);
	  BFD_ASSERT (tls_type & (GOT_TLS_IE | GOT_TLS_GD | GOT_TLSDESC));
	  /* When more than one TLS type is used, the GD slot comes first,
	     then IE, then finally TLSDESC.  */
	  ie_off = 0;
	  if (tls_type & GOT_TLS_GD)
	    ie_off += TLS_GD_GOT_ENTRY_SIZE;

	  desc_off = ie_off;
	  if (tls_type & GOT_TLS_IE)
	    desc_off += TLS_IE_GOT_ENTRY_SIZE;

	  if ((off & 1) != 0)
	    off &= ~1;
	  else
	    {
	      Elf_Internal_Rela outrel;
	      int indx = 0;
	      bool need_relocs = false;

	      if (htab->elf.srelgot == NULL)
		abort ();

	      bool dyn = elf_hash_table (info)->dynamic_sections_created;
	      RISCV_TLS_GD_IE_NEED_DYN_RELOC (info, dyn, h, indx, need_relocs);

	      /* The GOT entries have not been initialized yet.  Do it
		 now, and emit any relocations.  */
	      if (tls_type & GOT_TLS_GD)
		{
		  if (need_relocs)
		    {
		      outrel.r_offset = sec_addr (htab->elf.sgot) + off;
		      outrel.r_addend = 0;
		      outrel.r_info = ELF32_R_INFO (indx, R_RISCV_TLS_DTPMOD32);
		      bfd_put_32 (output_bfd, 0,
				  htab->elf.sgot->contents + off);
		      riscv_elf_append_rela (output_bfd, htab->elf.srelgot, &outrel);
		      if (indx == 0)
			{
			  BFD_ASSERT (! unresolved_reloc);
			  bfd_put_32 (output_bfd,
				      dtpoff (info, relocation),
				      (htab->elf.sgot->contents
				       + off + RISCV_ELF_WORD_BYTES));
			}
		      else
			{
			  bfd_put_32 (output_bfd, 0,
				      (htab->elf.sgot->contents
				       + off + RISCV_ELF_WORD_BYTES));
			  outrel.r_info = ELF32_R_INFO (indx, R_RISCV_TLS_DTPREL32);
			  outrel.r_offset += RISCV_ELF_WORD_BYTES;
			  riscv_elf_append_rela (output_bfd, htab->elf.srelgot, &outrel);
			}
		    }
		  else
		    {
		      /* If we are not emitting relocations for a
			 general dynamic reference, then we must be in a
			 static link or an executable link with the
			 symbol binding locally.  Mark it as belonging
			 to module 1, the executable.  */
		      bfd_put_32 (output_bfd, 1,
				  htab->elf.sgot->contents + off);
		      bfd_put_32 (output_bfd,
				  dtpoff (info, relocation),
				  (htab->elf.sgot->contents
				   + off + RISCV_ELF_WORD_BYTES));
		   }
		}

	      if (tls_type & GOT_TLS_IE)
		{
		  if (need_relocs)
		    {
		      bfd_put_32 (output_bfd, 0,
				  htab->elf.sgot->contents + off + ie_off);
		      outrel.r_offset = sec_addr (htab->elf.sgot)
					+ off + ie_off;
		      outrel.r_addend = 0;
		      if (indx == 0)
			outrel.r_addend = tpoff (info, relocation);
		      outrel.r_info = ELF32_R_INFO (indx, R_RISCV_TLS_TPREL32);
		      riscv_elf_append_rela (output_bfd, htab->elf.srelgot, &outrel);
		    }
		  else
		    {
		      bfd_put_32 (output_bfd, tpoff (info, relocation),
				  htab->elf.sgot->contents + off + ie_off);
		    }
		}

	      if (tls_type & GOT_TLSDESC)
		{
		  /* TLSDESC is always handled by the dynamic linker and always need
		   * a relocation.  */
		  bfd_put_32 (output_bfd, 0,
			      htab->elf.sgot->contents + off + desc_off);
		  outrel.r_offset = sec_addr (htab->elf.sgot)
				    + off + desc_off;
		  outrel.r_addend = 0;
		  if (indx == 0)
		    outrel.r_addend = tlsdescoff (info, relocation);
		  outrel.r_info = ELF32_R_INFO (indx, R_RISCV_TLSDESC);
		  riscv_elf_append_rela (output_bfd, htab->elf.srelgot, &outrel);
		}
	    }

	  BFD_ASSERT (off < (bfd_vma) -2);
	  relocation = sec_addr (htab->elf.sgot) + off;
	  if (is_ie)
	    relocation += ie_off;
	  else if (is_desc)
	    relocation += desc_off;
	  if (!riscv_record_pcrel_hi_reloc (&pcrel_relocs, pc,
					    relocation, r_type,
					    false))
	    r = bfd_reloc_overflow;
	  unresolved_reloc = false;
	  break;

	default:
	  r = bfd_reloc_notsupported;
	}

      /* Dynamic relocs are not propagated for SEC_DEBUGGING sections
	 because such sections are not SEC_ALLOC and thus ld.so will
	 not process them.  */
      if (unresolved_reloc
	  && !((input_section->flags & SEC_DEBUGGING) != 0
	       && h->def_dynamic)
	  && _bfd_elf_section_offset (output_bfd, info, input_section,
				      rel->r_offset) != (bfd_vma) -1)
	{
	  msg = bfd_asprintf (_("%%X%%P: unresolvable %s relocation against "
				"symbol `%s'\n"),
			      howto->name,
			      h->root.root.string);
	  r = bfd_reloc_notsupported;
	}

 do_relocation:
      if (r == bfd_reloc_ok)
	r = perform_relocation (howto, rel, relocation, input_section,
				input_bfd, contents);

      /* We should have already detected the error and set message before.
	 If the error message isn't set since the linker runs out of memory
	 or we don't set it before, then we should set the default message
	 with the "internal error" string here.  */
      switch (r)
	{
	case bfd_reloc_ok:
	  continue;

	case bfd_reloc_overflow:
	  info->callbacks->reloc_overflow
	    (info, (h ? &h->root : NULL), name, howto->name,
	     (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
	  break;

	case bfd_reloc_undefined:
	  info->callbacks->undefined_symbol
	    (info, name, input_bfd, input_section, rel->r_offset,
	     true);
	  break;

	case bfd_reloc_outofrange:
	  if (msg == NULL)
	    msg = _("%X%P: internal error: out of range error\n");
	  break;

	case bfd_reloc_notsupported:
	  if (msg == NULL)
	    msg = _("%X%P: internal error: unsupported relocation error\n");
	  break;

	case bfd_reloc_dangerous:
	  /* The error message should already be set.  */
	  if (msg == NULL)
	    msg = _("dangerous relocation error");
	  info->callbacks->reloc_dangerous
	    (info, msg, input_bfd, input_section, rel->r_offset);
	  break;

	default:
	  msg = _("%X%P: internal error: unknown error\n");
	  break;
	}

      /* Do not report error message for the dangerous relocation again.  */
      if (msg && r != bfd_reloc_dangerous)
	info->callbacks->einfo (msg);

      /* We already reported the error via a callback, so don't try to report
	 it again by returning false.  That leads to spurious errors.  */
      ret = true;
      goto out;
    }

  ret = riscv_resolve_pcrel_lo_relocs (&pcrel_relocs);
 out:
  riscv_free_pcrel_relocs (&pcrel_relocs);
  return ret;
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bool
riscv_elf_finish_dynamic_symbol (bfd *output_bfd,
				 struct bfd_link_info *info,
				 struct elf_link_hash_entry *h,
				 Elf_Internal_Sym *sym)
{
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  const struct elf_backend_data *bed = get_elf_backend_data (output_bfd);

  if (h->plt.offset != (bfd_vma) -1)
    {
      /* We've decided to create a PLT entry for this symbol.  */
      bfd_byte *loc;
      bfd_vma plt_idx, got_offset, got_address;
      Elf_Internal_Rela rela;
      asection *plt, *gotplt, *relplt;

      /* When building a static executable, use .iplt, .igot.plt and
	 .rela.iplt sections for STT_GNU_IFUNC symbols.  */
      if (htab->elf.splt != NULL)
        {
          plt = htab->elf.splt;
          gotplt = htab->elf.sgotplt;
          relplt = htab->elf.srelplt;
        }
      else
        {
          plt = htab->elf.iplt;
          gotplt = htab->elf.igotplt;
          relplt = htab->elf.irelplt;
        }

      /* This symbol has an entry in the procedure linkage table.  Set
         it up.  */
      if ((h->dynindx == -1
	   && !((h->forced_local || bfd_link_executable (info))
		&& h->def_regular
		&& h->type == STT_GNU_IFUNC))
	  || plt == NULL
	  || gotplt == NULL
	  || relplt == NULL)
	abort ();

      /* Calculate the index of the entry and the offset of .got.plt entry.
	 For static executables, we don't reserve anything.  */
      if (plt == htab->elf.splt)
	{
	  plt_idx = (h->plt.offset - htab->plt_header_size)
		     / htab->plt_entry_size;
	  got_offset = GOTPLT_HEADER_SIZE + (plt_idx * GOT_ENTRY_SIZE);
	}
      else
	{
	  plt_idx = h->plt.offset / htab->plt_entry_size;
	  got_offset = plt_idx * GOT_ENTRY_SIZE;
	}

      /* Calculate the address of the .got.plt entry.  */
      got_address = sec_addr (gotplt) + got_offset;


      /* Fill in the PLT entry itself.  */
      if (! htab->make_plt_entry (output_bfd, gotplt, got_offset,
				  plt, h->plt.offset))
	return false;


      /* Fill in the initial value of the .got.plt entry.  */
      loc = gotplt->contents + (got_address - sec_addr (gotplt));
      bfd_put_32 (output_bfd, sec_addr (plt), loc);

      rela.r_offset = got_address;

      if (h->dynindx == -1
	  || ((bfd_link_executable (info)
	       || ELF_ST_VISIBILITY (h->other) != STV_DEFAULT)
	      && h->def_regular
	      && h->type == STT_GNU_IFUNC))
	{
	  info->callbacks->minfo (_("Local IFUNC function `%s' in %pB\n"),
				  h->root.root.string,
				  h->root.u.def.section->owner);

	  /* If an STT_GNU_IFUNC symbol is locally defined, generate
	     R_RISCV_IRELATIVE instead of R_RISCV_JUMP_SLOT.  */
	  asection *sec = h->root.u.def.section;
	  rela.r_info = ELF32_R_INFO (0, R_RISCV_IRELATIVE);
	  rela.r_addend = h->root.u.def.value
			  + sec->output_section->vma
			  + sec->output_offset;
	}
      else
	{
	  /* Fill in the entry in the .rela.plt section.  */
	  rela.r_info = ELF32_R_INFO (h->dynindx, R_RISCV_JUMP_SLOT);
	  rela.r_addend = 0;
	}

      loc = relplt->contents + plt_idx * sizeof (Elf32_External_Rela);
      bed->s->swap_reloca_out (output_bfd, &rela, loc);

      if (!h->def_regular)
	{
	  /* Mark the symbol as undefined, rather than as defined in
	     the .plt section.  Leave the value alone.  */
	  sym->st_shndx = SHN_UNDEF;
	  /* If the symbol is weak, we do need to clear the value.
	     Otherwise, the PLT entry would provide a definition for
	     the symbol even if the symbol wasn't defined anywhere,
	     and so the symbol would never be NULL.  */
	  if (!h->ref_regular_nonweak)
	    sym->st_value = 0;
	}
    }

  if (h->got.offset != (bfd_vma) -1
      && !(riscv_elf_hash_entry (h)->tls_type & (GOT_TLS_GD | GOT_TLS_IE | GOT_TLSDESC))
      && !UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
    {
      asection *sgot;
      asection *srela;
      Elf_Internal_Rela rela;
      bool use_elf_append_rela = true;

      /* This symbol has an entry in the GOT.  Set it up.  */

      sgot = htab->elf.sgot;
      srela = htab->elf.srelgot;
      BFD_ASSERT (sgot != NULL && srela != NULL);

      rela.r_offset = sec_addr (sgot) + (h->got.offset &~ (bfd_vma) 1);

      /* Handle the ifunc symbol in GOT entry.  */
      if (h->def_regular
	  && h->type == STT_GNU_IFUNC)
	{
	  if (h->plt.offset == (bfd_vma) -1)
	    {
	      /* STT_GNU_IFUNC is referenced without PLT.  */

	      if (htab->elf.splt == NULL)
		{
		  /* Use .rela.iplt section to store .got relocations
		     in static executable.  */
		  srela = htab->elf.irelplt;

		  /* Do not use riscv_elf_append_rela to add dynamic
		     relocs.  */
		  use_elf_append_rela = false;
		}

	      if (SYMBOL_REFERENCES_LOCAL (info, h))
		{
		  info->callbacks->minfo (_("Local IFUNC function `%s' in %pB\n"),
					  h->root.root.string,
					  h->root.u.def.section->owner);

		  rela.r_info = ELF32_R_INFO (0, R_RISCV_IRELATIVE);
		  rela.r_addend = (h->root.u.def.value
				   + h->root.u.def.section->output_section->vma
				   + h->root.u.def.section->output_offset);
		}
	      else
		{
		  /* Generate R_RISCV_32.  */
		  goto do_reloc_nn;
		}
	    }
	  else if (bfd_link_pic (info))
	    {
	      /* Generate R_RISCV_32.  */
	      goto do_reloc_nn;
	    }
	  else
	    {
	      asection *plt;

	      if (!h->pointer_equality_needed)
		abort ();

	      /* For non-shared object, we can't use .got.plt, which
		 contains the real function address if we need pointer
		 equality.  We load the GOT entry with the PLT entry.  */
	      plt = htab->elf.splt ? htab->elf.splt : htab->elf.iplt;
	      bfd_put_32 (output_bfd, (plt->output_section->vma
				       + plt->output_offset
				       + h->plt.offset),
			  htab->elf.sgot->contents
			  + (h->got.offset & ~(bfd_vma) 1));
	      return true;
	    }
	}
      else if (bfd_link_pic (info)
	       && SYMBOL_REFERENCES_LOCAL (info, h))
	{
	  /* If this is a local symbol reference, we just want to emit
	     a RELATIVE reloc.  This can happen if it is a -Bsymbolic link,
	     or a pie link, or the symbol was forced to be local because
	     of a version file.  The entry in the global offset table will
	     already have been initialized in the relocate_section function.  */
	  BFD_ASSERT ((h->got.offset & 1) != 0);
	  asection *sec = h->root.u.def.section;
	  rela.r_info = ELF32_R_INFO (0, R_RISCV_RELATIVE);
	  rela.r_addend = (h->root.u.def.value
			   + sec->output_section->vma
			   + sec->output_offset);
	}
      else
	{
  do_reloc_nn:
	  BFD_ASSERT ((h->got.offset & 1) == 0);
	  BFD_ASSERT (h->dynindx != -1);
	  rela.r_info = ELF32_R_INFO (h->dynindx, R_RISCV_32);
	  rela.r_addend = 0;
	  bfd_put_32 (output_bfd, 0,
		      sgot->contents + (h->got.offset & ~(bfd_vma) 1));
	}

      if (use_elf_append_rela)
	riscv_elf_append_rela (output_bfd, srela, &rela);
      else
	{
	  /* Use riscv_elf_append_rela to add the dynamic relocs into
	     .rela.iplt may cause the overwrite problems.  Since we insert
	     the relocs for PLT didn't handle the reloc_index of .rela.iplt,
	     but the riscv_elf_append_rela adds the relocs to the place
	     that are calculated from the reloc_index (in seqential).

	     One solution is that add these dynamic relocs (GOT IFUNC)
	     from the last of .rela.iplt section.  */
	  bfd_vma iplt_idx = htab->last_iplt_index--;
	  bfd_byte *loc = srela->contents
			  + iplt_idx * sizeof (Elf32_External_Rela);
	  bed->s->swap_reloca_out (output_bfd, &rela, loc);
	}
    }

  if (h->needs_copy)
    {
      Elf_Internal_Rela rela;
      asection *s;

      /* This symbols needs a copy reloc.  Set it up.  */
      BFD_ASSERT (h->dynindx != -1);

      rela.r_offset = sec_addr (h->root.u.def.section) + h->root.u.def.value;
      rela.r_info = ELF32_R_INFO (h->dynindx, R_RISCV_COPY);
      rela.r_addend = 0;
      if (h->root.u.def.section == htab->elf.sdynrelro)
	s = htab->elf.sreldynrelro;
      else
	s = htab->elf.srelbss;
      riscv_elf_append_rela (output_bfd, s, &rela);
    }

  /* Mark some specially defined symbols as absolute.  */
  if (h == htab->elf.hdynamic
      || (h == htab->elf.hgot || h == htab->elf.hplt))
    sym->st_shndx = SHN_ABS;

  return true;
}

/* Finish up local dynamic symbol handling.  We set the contents of
   various dynamic sections here.  */

static int
riscv_elf_finish_local_dynamic_symbol (void **slot, void *inf)
{
  struct elf_link_hash_entry *h = (struct elf_link_hash_entry *) *slot;
  struct bfd_link_info *info = (struct bfd_link_info *) inf;

  return riscv_elf_finish_dynamic_symbol (info->output_bfd, info, h, NULL);
}

/* Finish up the dynamic sections.  */

static bool
riscv_finish_dyn (bfd *output_bfd, struct bfd_link_info *info,
		  bfd *dynobj, asection *sdyn)
{
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  const struct elf_backend_data *bed = get_elf_backend_data (output_bfd);
  size_t dynsize = bed->s->sizeof_dyn;
  bfd_byte *dyncon, *dynconend;

  dynconend = sdyn->contents + sdyn->size;
  for (dyncon = sdyn->contents; dyncon < dynconend; dyncon += dynsize)
    {
      Elf_Internal_Dyn dyn;
      asection *s;

      bed->s->swap_dyn_in (dynobj, dyncon, &dyn);

      switch (dyn.d_tag)
	{
	case DT_PLTGOT:
	  s = htab->elf.sgotplt;
	  dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
	  break;
	case DT_JMPREL:
	  s = htab->elf.srelplt;
	  dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
	  break;
	case DT_PLTRELSZ:
	  s = htab->elf.srelplt;
	  dyn.d_un.d_val = s->size;
	  break;
	default:
	  continue;
	}

      bed->s->swap_dyn_out (output_bfd, &dyn, dyncon);
    }
  return true;
}

static bool
riscv_elf_finish_dynamic_sections (bfd *output_bfd,
				   struct bfd_link_info *info)
{
  bfd *dynobj;
  asection *sdyn;
  struct riscv_elf_link_hash_table *htab;

  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);
  dynobj = htab->elf.dynobj;

  sdyn = bfd_get_linker_section (dynobj, ".dynamic");

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      asection *splt;
      bool ret;

      splt = htab->elf.splt;
      BFD_ASSERT (splt != NULL && sdyn != NULL);

      ret = riscv_finish_dyn (output_bfd, info, dynobj, sdyn);

      if (!ret)
	return ret;

      /* Fill in the head and tail entries in the procedure linkage table.  */
      if (splt->size > 0)
	{
	  ret = htab->make_plt_header (output_bfd, htab);
	  if (!ret)
	    return ret;

	  elf_section_data (splt->output_section)->this_hdr.sh_entsize
	    = htab->plt_entry_size;
	}
    }

  if (htab->elf.sgotplt && htab->elf.sgotplt->size > 0)
    {
      asection *output_section = htab->elf.sgotplt->output_section;

      if (bfd_is_abs_section (output_section))
	{
	  (*_bfd_error_handler)
	    (_("discarded output section: `%pA'"), htab->elf.sgotplt);
	  return false;
	}

      /* Write the first two entries in .got.plt, needed for the dynamic
	 linker.  */
      bfd_put_32 (output_bfd, (bfd_vma) -1, htab->elf.sgotplt->contents);
      bfd_put_32 (output_bfd, (bfd_vma) 0,
		  htab->elf.sgotplt->contents + GOT_ENTRY_SIZE);

      elf_section_data (output_section)->this_hdr.sh_entsize = GOT_ENTRY_SIZE;
    }

  if (htab->elf.sgot && htab->elf.sgot->size > 0)
    {
      asection *output_section = htab->elf.sgot->output_section;

      if (!bfd_is_abs_section (output_section))
	{
	  /* Set the first entry in the global offset table to the address of
	     the dynamic section.  */
	  bfd_vma val = sdyn ? sec_addr (sdyn) : 0;
	  bfd_put_32 (output_bfd, val, htab->elf.sgot->contents);

	  elf_section_data (output_section)->this_hdr.sh_entsize = GOT_ENTRY_SIZE;
	}
    }

  /* Fill PLT and GOT entries for local STT_GNU_IFUNC symbols.  */
  htab_traverse (htab->loc_hash_table,
		 riscv_elf_finish_local_dynamic_symbol,
		 info);

  return true;
}

/* Return address for Ith PLT stub in section PLT, for relocation REL
   or (bfd_vma) -1 if it should not be included.  */

static bfd_vma
riscv_elf_plt_sym_val (bfd_vma i, const asection *plt,
		       const arelent *rel ATTRIBUTE_UNUSED)
{
  unsigned plt_type = _bfd_riscv_elf_tdata (plt->owner)->plt_type;
  switch (plt_type)
    {
    case PLT_NORMAL:
      return plt->vma + (PLT_HEADER_SIZE) + (i * PLT_ENTRY_SIZE);

    case PLT_ZICFILP_UNLABELED:
      return plt->vma + PLT_ZICFILP_UNLABELED_HEADER_SIZE + (i * PLT_ZICFILP_UNLABELED_ENTRY_SIZE);

    default:
      abort ();
    }
}

/* Used to decide how to sort relocs in an optimal manner for the
   dynamic linker, before writing them out.  */

static enum elf_reloc_type_class
riscv_reloc_type_class (const struct bfd_link_info *info,
			const asection *rel_sec ATTRIBUTE_UNUSED,
			const Elf_Internal_Rela *rela)
{
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);

  if (htab->elf.dynsym != NULL
      && htab->elf.dynsym->contents != NULL)
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
				       (htab->elf.dynsym->contents
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

  switch (ELF32_R_TYPE (rela->r_info))
    {
    case R_RISCV_IRELATIVE:
      return reloc_class_ifunc;
    case R_RISCV_RELATIVE:
      return reloc_class_relative;
    case R_RISCV_JUMP_SLOT:
      return reloc_class_plt;
    case R_RISCV_COPY:
      return reloc_class_copy;
    default:
      return reloc_class_normal;
    }
}

/* Given the ELF header flags in FLAGS, it returns a string that describes the
   float ABI.  */

static const char *
riscv_float_abi_string (flagword flags)
{
  switch (flags & EF_RISCV_FLOAT_ABI)
    {
    case EF_RISCV_FLOAT_ABI_SOFT:
      return "soft-float";
      break;
    case EF_RISCV_FLOAT_ABI_SINGLE:
      return "single-float";
      break;
    case EF_RISCV_FLOAT_ABI_DOUBLE:
      return "double-float";
      break;
    case EF_RISCV_FLOAT_ABI_QUAD:
      return "quad-float";
      break;
    default:
      abort ();
    }
}

/* The information of architecture elf attributes.  */
static riscv_subset_list_t in_subsets;
static riscv_subset_list_t out_subsets;
static riscv_subset_list_t merged_subsets;

/* Predicator for standard extension.  */

static bool
riscv_std_ext_p (const char *name)
{
  return (strlen (name) == 1) && (name[0] != 'x') && (name[0] != 's');
}

/* Update the output subset's version to match the input when the input
   subset's version is newer.  */

static void
riscv_update_subset_version (struct riscv_subset_t *in,
			     struct riscv_subset_t *out)
{
  if (in == NULL || out == NULL)
    return;

  /* Update the output ISA versions to the newest ones, but otherwise don't
     provide any errors or warnings about mis-matched ISA versions as it's
     generally too tricky to check for these at link time. */
  if ((in->major_version > out->major_version)
      || (in->major_version == out->major_version
	  && in->minor_version > out->minor_version)
      || (out->major_version == RISCV_UNKNOWN_VERSION))
    {
      out->major_version = in->major_version;
      out->minor_version = in->minor_version;
    }
}

/* Return true if subset is 'i' or 'e'.  */

static bool
riscv_i_or_e_p (bfd *ibfd,
		const char *arch,
		struct riscv_subset_t *subset)
{
  if ((strcasecmp (subset->name, "e") != 0)
      && (strcasecmp (subset->name, "i") != 0))
    {
      _bfd_error_handler
	(_("error: %pB: corrupted ISA string '%s'.  "
	   "First letter should be 'i' or 'e' but got '%s'"),
	   ibfd, arch, subset->name);
      return false;
    }
  return true;
}

/* Merge standard extensions.

   Return Value:
     Return FALSE if failed to merge.

   Arguments:
     `bfd`: bfd handler.
     `in_arch`: Raw ISA string for input object.
     `out_arch`: Raw ISA string for output object.
     `pin`: Subset list for input object.
     `pout`: Subset list for output object.  */

static bool
riscv_merge_std_ext (bfd *ibfd,
		     const char *in_arch,
		     const char *out_arch,
		     struct riscv_subset_t **pin,
		     struct riscv_subset_t **pout)
{
  const char *standard_exts = "mafdqlcbjtpvnh";
  const char *p;
  struct riscv_subset_t *in = *pin;
  struct riscv_subset_t *out = *pout;

  /* First letter should be 'i' or 'e'.  */
  if (!riscv_i_or_e_p (ibfd, in_arch, in))
    return false;

  if (!riscv_i_or_e_p (ibfd, out_arch, out))
    return false;

  if (strcasecmp (in->name, out->name) != 0)
    {
      /* TODO: We might allow merge 'i' with 'e'.  */
      _bfd_error_handler
	(_("error: %pB: mis-matched ISA string to merge '%s' and '%s'"),
	 ibfd, in->name, out->name);
      return false;
    }

  riscv_update_subset_version(in, out);
  riscv_add_subset (&merged_subsets,
		    out->name, out->major_version, out->minor_version);

  in = in->next;
  out = out->next;

  /* Handle standard extension first.  */
  for (p = standard_exts; *p; ++p)
    {
      struct riscv_subset_t *ext_in, *ext_out, *ext_merged;
      char find_ext[2] = {*p, '\0'};
      bool find_in, find_out;

      find_in = riscv_lookup_subset (&in_subsets, find_ext, &ext_in);
      find_out = riscv_lookup_subset (&out_subsets, find_ext, &ext_out);

      if (!find_in && !find_out)
	continue;

      if (find_in && find_out)
	riscv_update_subset_version(ext_in, ext_out);

      ext_merged = find_out ? ext_out : ext_in;
      riscv_add_subset (&merged_subsets, ext_merged->name,
			ext_merged->major_version, ext_merged->minor_version);
    }

  /* Skip all standard extensions.  */
  while ((in != NULL) && riscv_std_ext_p (in->name)) in = in->next;
  while ((out != NULL) && riscv_std_ext_p (out->name)) out = out->next;

  *pin = in;
  *pout = out;

  return true;
}

/* Merge multi letter extensions.  PIN is a pointer to the head of the input
   object subset list.  Likewise for POUT and the output object.  Return TRUE
   on success and FALSE when a conflict is found.  */

static bool
riscv_merge_multi_letter_ext (riscv_subset_t **pin,
			      riscv_subset_t **pout)
{
  riscv_subset_t *in = *pin;
  riscv_subset_t *out = *pout;
  riscv_subset_t *tail;

  int cmp;

  while (in && out)
    {
      cmp = riscv_compare_subsets (in->name, out->name);

      if (cmp < 0)
	{
	  /* `in' comes before `out', append `in' and increment.  */
	  riscv_add_subset (&merged_subsets, in->name, in->major_version,
			    in->minor_version);
	  in = in->next;
	}
      else if (cmp > 0)
	{
	  /* `out' comes before `in', append `out' and increment.  */
	  riscv_add_subset (&merged_subsets, out->name, out->major_version,
			    out->minor_version);
	  out = out->next;
	}
      else
	{
	  /* Both present, check version and increment both.  */
	  riscv_update_subset_version (in, out);

	  riscv_add_subset (&merged_subsets, out->name, out->major_version,
			    out->minor_version);
	  out = out->next;
	  in = in->next;
	}
    }

  if (in || out)
    {
      /* If we're here, either `in' or `out' is running longer than
	 the other. So, we need to append the corresponding tail.  */
      tail = in ? in : out;
      while (tail)
	{
	  riscv_add_subset (&merged_subsets, tail->name, tail->major_version,
			    tail->minor_version);
	  tail = tail->next;
	}
    }

  return true;
}

/* Merge Tag_RISCV_arch attribute.  */

static char *
riscv_merge_arch_attr_info (bfd *ibfd, char *in_arch, char *out_arch)
{
  riscv_subset_t *in, *out;
  static char *merged_arch_str = NULL;

  unsigned xlen_in, xlen_out;
  merged_subsets.head = NULL;
  merged_subsets.tail = NULL;

  riscv_parse_subset_t riscv_rps_ld_in =
    {&in_subsets, _bfd_error_handler, &xlen_in, NULL, false};
  riscv_parse_subset_t riscv_rps_ld_out =
    {&out_subsets, _bfd_error_handler, &xlen_out, NULL, false};

  if (in_arch == NULL && out_arch == NULL)
    return NULL;
  if (in_arch == NULL && out_arch != NULL)
    return out_arch;
  if (in_arch != NULL && out_arch == NULL)
    return in_arch;

  /* Parse subset from ISA string.  */
  if (!riscv_parse_subset (&riscv_rps_ld_in, in_arch))
    return NULL;
  if (!riscv_parse_subset (&riscv_rps_ld_out, out_arch))
    return NULL;

  /* Checking XLEN.  */
  if (xlen_out != xlen_in)
    {
      _bfd_error_handler
	(_("error: %pB: ISA string of input (%s) doesn't match "
	   "output (%s)"), ibfd, in_arch, out_arch);
      return NULL;
    }

  /* Merge subset list.  */
  in = in_subsets.head;
  out = out_subsets.head;

  /* Merge standard extension.  */
  if (!riscv_merge_std_ext (ibfd, in_arch, out_arch, &in, &out))
    return NULL;

  /* Merge all non-single letter extensions with single call.  */
  if (!riscv_merge_multi_letter_ext (&in, &out))
    return NULL;

  if (xlen_in != xlen_out)
    {
      _bfd_error_handler
	(_("error: %pB: XLEN of input (%u) doesn't match "
	   "output (%u)"), ibfd, xlen_in, xlen_out);
      return NULL;
    }

  if (xlen_in != ARCH_SIZE)
    {
      _bfd_error_handler
	(_("error: %pB: unsupported XLEN (%u), you might be "
	   "using wrong emulation"), ibfd, xlen_in);
      return NULL;
    }

  /* Free the previous merged_arch_str which called xmalloc.  */
  free (merged_arch_str);

  merged_arch_str = riscv_arch_str (ARCH_SIZE, &merged_subsets,
				    false/* update */);

  /* Release the subset lists.  */
  riscv_release_subset_list (&in_subsets);
  riscv_release_subset_list (&out_subsets);
  riscv_release_subset_list (&merged_subsets);

  return merged_arch_str;
}

/* Merge object attributes from IBFD into output_bfd of INFO.
   Raise an error if there are conflicting attributes.  */

static bool
riscv_merge_attributes (bfd *ibfd, struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;
  obj_attribute *in_attr;
  obj_attribute *out_attr;
  bool result = true;
  bool priv_attrs_merged = false;
  const char *sec_name = get_elf_backend_data (ibfd)->obj_attrs_section;
  unsigned int i;

  /* Skip linker created files.  */
  if (ibfd->flags & BFD_LINKER_CREATED)
    return true;

  /* Skip any input that doesn't have an attribute section.
     This enables to link object files without attribute section with
     any others.  */
  if (bfd_get_section_by_name (ibfd, sec_name) == NULL)
    return true;

  if (!elf_known_obj_attributes_proc (obfd)[0].i)
    {
      /* This is the first object.  Copy the attributes.  */
      _bfd_elf_copy_obj_attributes (ibfd, obfd);

      out_attr = elf_known_obj_attributes_proc (obfd);

      /* Use the Tag_null value to indicate the attributes have been
	 initialized.  */
      out_attr[0].i = 1;

      return true;
    }

  in_attr = elf_known_obj_attributes_proc (ibfd);
  out_attr = elf_known_obj_attributes_proc (obfd);

  for (i = LEAST_KNOWN_OBJ_ATTRIBUTE; i < NUM_KNOWN_OBJ_ATTRIBUTES; i++)
    {
    switch (i)
      {
      case Tag_RISCV_arch:
	if (!out_attr[Tag_RISCV_arch].s)
	  out_attr[Tag_RISCV_arch].s = in_attr[Tag_RISCV_arch].s;
	else if (in_attr[Tag_RISCV_arch].s
		 && out_attr[Tag_RISCV_arch].s)
	  {
	    /* Check compatible.  */
	    char *merged_arch =
		riscv_merge_arch_attr_info (ibfd,
					    in_attr[Tag_RISCV_arch].s,
					    out_attr[Tag_RISCV_arch].s);
	    if (merged_arch == NULL)
	      {
		result = false;
		out_attr[Tag_RISCV_arch].s = "";
	      }
	    else
	      out_attr[Tag_RISCV_arch].s = merged_arch;
	  }
	break;

      case Tag_RISCV_priv_spec:
      case Tag_RISCV_priv_spec_minor:
      case Tag_RISCV_priv_spec_revision:
	/* If we have handled the privileged elf attributes, then skip it.  */
	if (!priv_attrs_merged)
	  {
	    unsigned int Tag_a = Tag_RISCV_priv_spec;
	    unsigned int Tag_b = Tag_RISCV_priv_spec_minor;
	    unsigned int Tag_c = Tag_RISCV_priv_spec_revision;
	    enum riscv_spec_class in_priv_spec = PRIV_SPEC_CLASS_NONE;
	    enum riscv_spec_class out_priv_spec = PRIV_SPEC_CLASS_NONE;

	    /* Get the privileged spec class from elf attributes.  */
	    riscv_get_priv_spec_class_from_numbers (in_attr[Tag_a].i,
						    in_attr[Tag_b].i,
						    in_attr[Tag_c].i,
						    &in_priv_spec);
	    riscv_get_priv_spec_class_from_numbers (out_attr[Tag_a].i,
						    out_attr[Tag_b].i,
						    out_attr[Tag_c].i,
						    &out_priv_spec);

	    /* Allow to link the object without the privileged specs.  */
	    if (out_priv_spec == PRIV_SPEC_CLASS_NONE)
	      {
		out_attr[Tag_a].i = in_attr[Tag_a].i;
		out_attr[Tag_b].i = in_attr[Tag_b].i;
		out_attr[Tag_c].i = in_attr[Tag_c].i;
	      }
	    else if (in_priv_spec != PRIV_SPEC_CLASS_NONE
		     && in_priv_spec != out_priv_spec)
	      {
		/* The abandoned privileged spec v1.9.1 can not be linked with
		   others since the conflicts.  Keep the check since compatible
		   issue.  */
		if (in_priv_spec == PRIV_SPEC_CLASS_1P9P1
		    || out_priv_spec == PRIV_SPEC_CLASS_1P9P1)
		  {
		    _bfd_error_handler
		      (_("warning: privileged spec version 1.9.1 can not be "
			 "linked with other spec versions"));
		  }

		/* Update the output privileged spec to the newest one.  */
		if (in_priv_spec > out_priv_spec)
		  {
		    out_attr[Tag_a].i = in_attr[Tag_a].i;
		    out_attr[Tag_b].i = in_attr[Tag_b].i;
		    out_attr[Tag_c].i = in_attr[Tag_c].i;
		  }
	      }
	    priv_attrs_merged = true;
	  }
	break;

      case Tag_RISCV_unaligned_access:
	out_attr[i].i |= in_attr[i].i;
	break;

      case Tag_RISCV_stack_align:
	if (out_attr[i].i == 0)
	  out_attr[i].i = in_attr[i].i;
	else if (in_attr[i].i != 0
		 && out_attr[i].i != 0
		 && out_attr[i].i != in_attr[i].i)
	  {
	    _bfd_error_handler
	      (_("error: %pB use %u-byte stack aligned but the output "
		 "use %u-byte stack aligned"),
	       ibfd, in_attr[i].i, out_attr[i].i);
	    result = false;
	  }
	break;

      default:
	result &= _bfd_elf_merge_unknown_attribute_low (ibfd, obfd, i);
      }

      /* If out_attr was copied from in_attr then it won't have a type yet.  */
      if (in_attr[i].type && !out_attr[i].type)
	out_attr[i].type = in_attr[i].type;
    }

  /* Merge Tag_compatibility attributes and any common GNU ones.  */
  if (!_bfd_elf_merge_object_attributes (ibfd, info))
    return false;

  /* Check for any attributes not known on RISC-V.  */
  result &= _bfd_elf_merge_unknown_attribute_list (ibfd, obfd);

  return result;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bool
_bfd_riscv_elf_merge_private_bfd_data (bfd *ibfd, struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;
  flagword new_flags, old_flags;

  if (!is_riscv_elf (ibfd) || !is_riscv_elf (obfd))
    return true;

  if (strcmp (bfd_get_target (ibfd), bfd_get_target (obfd)) != 0)
    {
      (*_bfd_error_handler)
	(_("%pB: ABI is incompatible with that of the selected emulation:\n"
	   "  target emulation `%s' does not match `%s'"),
	 ibfd, bfd_get_target (ibfd), bfd_get_target (obfd));
      return false;
    }

  if (!_bfd_elf_merge_object_attributes (ibfd, info))
    return false;

  if (!riscv_merge_attributes (ibfd, info))
    return false;

  /* Check to see if the input BFD actually contains any sections.  If not,
     its flags may not have been initialized either, but it cannot actually
     cause any incompatibility.  Do not short-circuit dynamic objects; their
     section list may be emptied by elf_link_add_object_symbols.

     Also check to see if there are no code sections in the input.  In this
     case, there is no need to check for code specific flags.  */
  if (!(ibfd->flags & DYNAMIC))
    {
      bool null_input_bfd = true;
      bool only_data_sections = true;
      asection *sec;

      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
	{
	  null_input_bfd = false;

	  if ((bfd_section_flags (sec)
	       & (SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS))
	      == (SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS))
	    {
	      only_data_sections = false;
	      break;
	    }
	}

      if (null_input_bfd || only_data_sections)
	return true;
    }

  new_flags = elf_elfheader (ibfd)->e_flags;
  old_flags = elf_elfheader (obfd)->e_flags;

  if (!elf_flags_init (obfd))
    {
      elf_flags_init (obfd) = true;
      elf_elfheader (obfd)->e_flags = new_flags;
      return true;
    }

  /* Disallow linking different float ABIs.  */
  if ((old_flags ^ new_flags) & EF_RISCV_FLOAT_ABI)
    {
      (*_bfd_error_handler)
	(_("%pB: can't link %s modules with %s modules"), ibfd,
	 riscv_float_abi_string (new_flags),
	 riscv_float_abi_string (old_flags));
      goto fail;
    }

  /* Disallow linking RVE and non-RVE.  */
  if ((old_flags ^ new_flags) & EF_RISCV_RVE)
    {
      (*_bfd_error_handler)
       (_("%pB: can't link RVE with other target"), ibfd);
      goto fail;
    }

  /* Allow linking RVC and non-RVC, and keep the RVC flag.  */
  elf_elfheader (obfd)->e_flags |= new_flags & EF_RISCV_RVC;

  /* Allow linking TSO and non-TSO, and keep the TSO flag.  */
  elf_elfheader (obfd)->e_flags |= new_flags & EF_RISCV_TSO;

  return true;

 fail:
  bfd_set_error (bfd_error_bad_value);
  return false;
}

/* Ignore and report warning for the unknwon elf attribute.  */

static bool
riscv_elf_obj_attrs_handle_unknown (bfd *abfd, int tag)
{
  _bfd_error_handler
    /* xgettext:c-format */
    (_("warning: %pB: unknown RISCV ABI object attribute %d"),
     abfd, tag);
  return true;
}

/* A second format for recording PC-relative hi relocations.  This stores the
   information required to relax them to GP-relative addresses.  */

typedef struct riscv_pcgp_hi_reloc riscv_pcgp_hi_reloc;
struct riscv_pcgp_hi_reloc
{
  bfd_vma hi_sec_off;
  bfd_vma hi_addend;
  bfd_vma hi_addr;
  unsigned hi_sym;
  asection *sym_sec;
  bool undefined_weak;
  riscv_pcgp_hi_reloc *next;
};

typedef struct riscv_pcgp_lo_reloc riscv_pcgp_lo_reloc;
struct riscv_pcgp_lo_reloc
{
  bfd_vma hi_sec_off;
  riscv_pcgp_lo_reloc *next;
};

typedef struct
{
  riscv_pcgp_hi_reloc *hi;
  riscv_pcgp_lo_reloc *lo;
} riscv_pcgp_relocs;

/* Initialize the pcgp reloc info in P.  */

static bool
riscv_init_pcgp_relocs (riscv_pcgp_relocs *p)
{
  p->hi = NULL;
  p->lo = NULL;
  return true;
}

/* Free the pcgp reloc info in P.  */

static void
riscv_free_pcgp_relocs (riscv_pcgp_relocs *p,
			bfd *abfd ATTRIBUTE_UNUSED,
			asection *sec ATTRIBUTE_UNUSED)
{
  riscv_pcgp_hi_reloc *c;
  riscv_pcgp_lo_reloc *l;

  for (c = p->hi; c != NULL; )
    {
      riscv_pcgp_hi_reloc *next = c->next;
      free (c);
      c = next;
    }

  for (l = p->lo; l != NULL; )
    {
      riscv_pcgp_lo_reloc *next = l->next;
      free (l);
      l = next;
    }
}

/* Record pcgp hi part reloc info in P, using HI_SEC_OFF as the lookup index.
   The HI_ADDEND, HI_ADDR, HI_SYM, and SYM_SEC args contain info required to
   relax the corresponding lo part reloc.  */

static bool
riscv_record_pcgp_hi_reloc (riscv_pcgp_relocs *p, bfd_vma hi_sec_off,
			    bfd_vma hi_addend, bfd_vma hi_addr,
			    unsigned hi_sym, asection *sym_sec,
			    bool undefined_weak)
{
  riscv_pcgp_hi_reloc *new = bfd_malloc (sizeof (*new));
  if (!new)
    return false;
  new->hi_sec_off = hi_sec_off;
  new->hi_addend = hi_addend;
  new->hi_addr = hi_addr;
  new->hi_sym = hi_sym;
  new->sym_sec = sym_sec;
  new->undefined_weak = undefined_weak;
  new->next = p->hi;
  p->hi = new;
  return true;
}

/* Look up hi part pcgp reloc info in P, using HI_SEC_OFF as the lookup index.
   This is used by a lo part reloc to find the corresponding hi part reloc.  */

static riscv_pcgp_hi_reloc *
riscv_find_pcgp_hi_reloc (riscv_pcgp_relocs *p, bfd_vma hi_sec_off)
{
  riscv_pcgp_hi_reloc *c;

  for (c = p->hi; c != NULL; c = c->next)
    if (c->hi_sec_off == hi_sec_off)
      return c;
  return NULL;
}

/* Record pcgp lo part reloc info in P, using HI_SEC_OFF as the lookup info.
   This is used to record relocs that can't be relaxed.  */

static bool
riscv_record_pcgp_lo_reloc (riscv_pcgp_relocs *p, bfd_vma hi_sec_off)
{
  riscv_pcgp_lo_reloc *new = bfd_malloc (sizeof (*new));
  if (!new)
    return false;
  new->hi_sec_off = hi_sec_off;
  new->next = p->lo;
  p->lo = new;
  return true;
}

/* Look up lo part pcgp reloc info in P, using HI_SEC_OFF as the lookup index.
   This is used by a hi part reloc to find the corresponding lo part reloc.  */

static bool
riscv_find_pcgp_lo_reloc (riscv_pcgp_relocs *p, bfd_vma hi_sec_off)
{
  riscv_pcgp_lo_reloc *c;

  for (c = p->lo; c != NULL; c = c->next)
    if (c->hi_sec_off == hi_sec_off)
      return true;
  return false;
}

static void
riscv_update_pcgp_relocs (riscv_pcgp_relocs *p, asection *deleted_sec,
			  bfd_vma deleted_addr, size_t deleted_count)
{
  /* Bytes have already been deleted and toaddr should match the old section
     size for our checks, so adjust it here.  */
  bfd_vma toaddr = deleted_sec->size + deleted_count;
  riscv_pcgp_lo_reloc *l;
  riscv_pcgp_hi_reloc *h;

  /* Update section offsets of corresponding pcrel_hi relocs for the pcrel_lo
     entries where they occur after the deleted bytes.  */
  for (l = p->lo; l != NULL; l = l->next)
    if (l->hi_sec_off > deleted_addr
	&& l->hi_sec_off < toaddr)
      l->hi_sec_off -= deleted_count;

  /* Update both section offsets, and symbol values of pcrel_hi relocs where
     these values occur after the deleted bytes.  */
  for (h = p->hi; h != NULL; h = h->next)
    {
      if (h->hi_sec_off > deleted_addr
	  && h->hi_sec_off < toaddr)
	h->hi_sec_off -= deleted_count;
      if (h->sym_sec == deleted_sec
	  && h->hi_addr > deleted_addr
	  && h->hi_addr < toaddr)
      h->hi_addr -= deleted_count;
    }
}

/* Delete some bytes, adjust relcocations and symbol table from a section.  */

static bool
_riscv_relax_delete_bytes (bfd *abfd,
			   asection *sec,
			   bfd_vma addr,
			   size_t count,
			   struct bfd_link_info *link_info,
			   riscv_pcgp_relocs *p,
			   bfd_vma delete_total,
			   bfd_vma toaddr)
{
  unsigned int i, symcount;
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (abfd);
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  unsigned int sec_shndx = _bfd_elf_section_from_bfd_section (abfd, sec);
  struct bfd_elf_section_data *data = elf_section_data (sec);
  bfd_byte *contents = data->this_hdr.contents;
  size_t bytes_to_move = toaddr - addr - count;

  /* Actually delete the bytes.  */
  sec->size -= count;
  memmove (contents + addr, contents + addr + count + delete_total, bytes_to_move);

  /* Still adjust relocations and symbols in non-linear times.  */
  toaddr = sec->size + count;

  /* Adjust the location of all of the relocs.  Note that we need not
     adjust the addends, since all PC-relative references must be against
     symbols, which we will adjust below.  */
  for (i = 0; i < sec->reloc_count; i++)
    if (data->relocs[i].r_offset > addr && data->relocs[i].r_offset < toaddr)
      data->relocs[i].r_offset -= count;

  /* Adjust the hi_sec_off, and the hi_addr of any entries in the pcgp relocs
     table for which these values occur after the deleted bytes.  */
  if (p)
    riscv_update_pcgp_relocs (p, sec, addr, count);

  /* Adjust the local symbols defined in this section.  */
  for (i = 0; i < symtab_hdr->sh_info; i++)
    {
      Elf_Internal_Sym *sym = (Elf_Internal_Sym *) symtab_hdr->contents + i;
      if (sym->st_shndx == sec_shndx)
	{
	  /* If the symbol is in the range of memory we just moved, we
	     have to adjust its value.  */
	  if (sym->st_value > addr && sym->st_value <= toaddr)
	    sym->st_value -= count;

	  /* If the symbol *spans* the bytes we just deleted (i.e. its
	     *end* is in the moved bytes but its *start* isn't), then we
	     must adjust its size.

	     This test needs to use the original value of st_value, otherwise
	     we might accidentally decrease size when deleting bytes right
	     before the symbol.  But since deleted relocs can't span across
	     symbols, we can't have both a st_value and a st_size decrease,
	     so it is simpler to just use an else.  */
	  else if (sym->st_value <= addr
		   && sym->st_value + sym->st_size > addr
		   && sym->st_value + sym->st_size <= toaddr)
	    sym->st_size -= count;
	}
    }

  /* Now adjust the global symbols defined in this section.  */
  symcount = ((symtab_hdr->sh_size / sizeof (Elf32_External_Sym))
	      - symtab_hdr->sh_info);

  for (i = 0; i < symcount; i++)
    {
      struct elf_link_hash_entry *sym_hash = sym_hashes[i];

      /* The '--wrap SYMBOL' option is causing a pain when the object file,
	 containing the definition of __wrap_SYMBOL, includes a direct
	 call to SYMBOL as well. Since both __wrap_SYMBOL and SYMBOL reference
	 the same symbol (which is __wrap_SYMBOL), but still exist as two
	 different symbols in 'sym_hashes', we don't want to adjust
	 the global symbol __wrap_SYMBOL twice.

	 The same problem occurs with symbols that are versioned_hidden, as
	 foo becomes an alias for foo@BAR, and hence they need the same
	 treatment.  */
      if (link_info->wrap_hash != NULL
	  || sym_hash->versioned != unversioned)
	{
	  struct elf_link_hash_entry **cur_sym_hashes;

	  /* Loop only over the symbols which have already been checked.  */
	  for (cur_sym_hashes = sym_hashes; cur_sym_hashes < &sym_hashes[i];
	       cur_sym_hashes++)
	    {
	      /* If the current symbol is identical to 'sym_hash', that means
		 the symbol was already adjusted (or at least checked).  */
	      if (*cur_sym_hashes == sym_hash)
		break;
	    }
	  /* Don't adjust the symbol again.  */
	  if (cur_sym_hashes < &sym_hashes[i])
	    continue;
	}

      if ((sym_hash->root.type == bfd_link_hash_defined
	   || sym_hash->root.type == bfd_link_hash_defweak)
	  && sym_hash->root.u.def.section == sec)
	{
	  /* As above, adjust the value if needed.  */
	  if (sym_hash->root.u.def.value > addr
	      && sym_hash->root.u.def.value <= toaddr)
	    sym_hash->root.u.def.value -= count;

	  /* As above, adjust the size if needed.  */
	  else if (sym_hash->root.u.def.value <= addr
		   && sym_hash->root.u.def.value + sym_hash->size > addr
		   && sym_hash->root.u.def.value + sym_hash->size <= toaddr)
	    sym_hash->size -= count;
	}
    }

  return true;
}

typedef bool (*relax_delete_t) (bfd *, asection *,
				bfd_vma, size_t,
				struct bfd_link_info *,
				riscv_pcgp_relocs *,
				Elf_Internal_Rela *);

static relax_delete_t riscv_relax_delete_bytes;

/* Do not delete some bytes from a section while relaxing.
   Just mark the deleted bytes as R_RISCV_DELETE.  */

static bool
_riscv_relax_delete_piecewise (bfd *abfd ATTRIBUTE_UNUSED,
			       asection *sec ATTRIBUTE_UNUSED,
			       bfd_vma addr,
			       size_t count,
			       struct bfd_link_info *link_info ATTRIBUTE_UNUSED,
			       riscv_pcgp_relocs *p ATTRIBUTE_UNUSED,
			       Elf_Internal_Rela *rel)
{
  if (rel == NULL)
    return false;
  rel->r_info = ELF32_R_INFO (0, R_RISCV_DELETE);
  rel->r_offset = addr;
  rel->r_addend = count;
  return true;
}

/* Delete some bytes from a section while relaxing.  */

static bool
_riscv_relax_delete_immediate (bfd *abfd,
			       asection *sec,
			       bfd_vma addr,
			       size_t count,
			       struct bfd_link_info *link_info,
			       riscv_pcgp_relocs *p,
			       Elf_Internal_Rela *rel)
{
  if (rel != NULL)
    rel->r_info = ELF32_R_INFO (0, R_RISCV_NONE);
  return _riscv_relax_delete_bytes (abfd, sec, addr, count,
				    link_info, p, 0, sec->size);
}

/* Delete the bytes for R_RISCV_DELETE relocs.  */

static bool
riscv_relax_resolve_delete_relocs (bfd *abfd,
				   asection *sec,
				   struct bfd_link_info *link_info,
				   Elf_Internal_Rela *relocs)
{
  bfd_vma delete_total = 0;
  unsigned int i;

  for (i = 0; i < sec->reloc_count; i++)
    {
      Elf_Internal_Rela *rel = relocs + i;
      if (ELF32_R_TYPE (rel->r_info) != R_RISCV_DELETE)
	continue;

      /* Find the next R_RISCV_DELETE reloc if possible.  */
      Elf_Internal_Rela *rel_next = NULL;
      unsigned int start = rel - relocs;
      for (i = start; i < sec->reloc_count; i++)
	{
	  /* Since we only replace existing relocs and don't add new relocs, the
	     relocs are in sequential order. We can skip the relocs prior to this
	     one, making this search linear time.  */
	  rel_next = relocs + i;
	  if (ELF32_R_TYPE ((rel_next)->r_info) == R_RISCV_DELETE
	      && (rel_next)->r_offset > rel->r_offset)
	    {
	      BFD_ASSERT (rel_next - rel > 0);
	      break;
	    }
	  else
	    rel_next = NULL;
	}

      bfd_vma toaddr = rel_next == NULL ? sec->size : rel_next->r_offset;
      if (!_riscv_relax_delete_bytes (abfd, sec, rel->r_offset, rel->r_addend,
				      link_info, NULL, delete_total, toaddr))
	return false;

      delete_total += rel->r_addend;
      rel->r_info = ELF32_R_INFO (0, R_RISCV_NONE);

      /* Skip ahead to the next delete reloc.  */
      i = rel_next != NULL ? (unsigned int) (rel_next - relocs - 1)
			   : sec->reloc_count;
    }

  return true;
}

typedef bool (*relax_func_t) (bfd *, asection *, asection *,
			      struct bfd_link_info *,
			      Elf_Internal_Rela *,
			      bfd_vma, bfd_vma, bfd_vma, bool *,
			      riscv_pcgp_relocs *,
			      bool undefined_weak);

/* Relax AUIPC + JALR into JAL.  */

static bool
_bfd_riscv_relax_call (bfd *abfd, asection *sec, asection *sym_sec,
		       struct bfd_link_info *link_info,
		       Elf_Internal_Rela *rel,
		       bfd_vma symval,
		       bfd_vma max_alignment,
		       bfd_vma reserve_size ATTRIBUTE_UNUSED,
		       bool *again,
		       riscv_pcgp_relocs *pcgp_relocs,
		       bool undefined_weak ATTRIBUTE_UNUSED)
{
  bfd_byte *contents = elf_section_data (sec)->this_hdr.contents;
  bfd_vma foff = symval - (sec_addr (sec) + rel->r_offset);
  bool near_zero = (symval + RISCV_IMM_REACH / 2) < RISCV_IMM_REACH;
  bfd_vma auipc, jalr;
  int rd, r_type, len = 4, rvc = elf_elfheader (abfd)->e_flags & EF_RISCV_RVC;

  /* If the call crosses section boundaries, an alignment directive could
     cause the PC-relative offset to later increase, so we need to add in the
     max alignment of any section inclusive from the call to the target.
     Otherwise, we only need to use the alignment of the current section.  */
  if (VALID_JTYPE_IMM (foff))
    {
      if (sym_sec->output_section == sec->output_section
	  && sym_sec->output_section != bfd_abs_section_ptr)
	max_alignment = (bfd_vma) 1 << sym_sec->output_section->alignment_power;
      foff += ((bfd_signed_vma) foff < 0 ? -max_alignment : max_alignment);
    }

  /* See if this function call can be shortened.  */
  if (!VALID_JTYPE_IMM (foff) && !(!bfd_link_pic (link_info) && near_zero))
    return true;

  /* Shorten the function call.  */
  BFD_ASSERT (rel->r_offset + 8 <= sec->size);

  auipc = bfd_getl32 (contents + rel->r_offset);
  jalr = bfd_getl32 (contents + rel->r_offset + 4);
  rd = (jalr >> OP_SH_RD) & OP_MASK_RD;
  rvc = rvc && VALID_CJTYPE_IMM (foff);

  /* C.J exists on RV32 and RV64, but C.JAL is RV32-only.  */
  rvc = rvc && (rd == 0 || (rd == X_RA && ARCH_SIZE == 32));

  if (rvc)
    {
      /* Relax to C.J[AL] rd, addr.  */
      r_type = R_RISCV_RVC_JUMP;
      auipc = rd == 0 ? MATCH_C_J : MATCH_C_JAL;
      len = 2;
    }
  else if (VALID_JTYPE_IMM (foff))
    {
      /* Relax to JAL rd, addr.  */
      r_type = R_RISCV_JAL;
      auipc = MATCH_JAL | (rd << OP_SH_RD);
    }
  else
    {
      /* Near zero, relax to JALR rd, x0, addr.  */
      r_type = R_RISCV_LO12_I;
      auipc = MATCH_JALR | (rd << OP_SH_RD);
    }

  /* Replace the R_RISCV_CALL reloc.  */
  rel->r_info = ELF32_R_INFO (ELF32_R_SYM (rel->r_info), r_type);
  /* Replace the AUIPC.  */
  riscv_put_insn (8 * len, auipc, contents + rel->r_offset);

  /* Delete unnecessary JALR and reuse the R_RISCV_RELAX reloc.  */
  *again = true;
  return riscv_relax_delete_bytes (abfd, sec, rel->r_offset + len, 8 - len,
				   link_info, pcgp_relocs, rel + 1);
}

/* Traverse all output sections and return the max alignment.

   If gp is zero, then all the output section alignments are
   possible candidates;  Otherwise, only the output sections
   which are in the [gp-2K, gp+2K) range need to be considered.  */

static bfd_vma
_bfd_riscv_get_max_alignment (asection *sec, bfd_vma gp)
{
  unsigned int max_alignment_power = 0;
  asection *o;

  for (o = sec->output_section->owner->sections; o != NULL; o = o->next)
    {
      bool valid = true;
      if (gp
	  && !(VALID_ITYPE_IMM (sec_addr (o) - gp)
	       || VALID_ITYPE_IMM (sec_addr (o) + o->size - gp)))
	valid = false;

      if (valid && o->alignment_power > max_alignment_power)
	max_alignment_power = o->alignment_power;
    }

  return (bfd_vma) 1 << max_alignment_power;
}

/* Relax non-PIC global variable references to GP-relative references.  */

static bool
_bfd_riscv_relax_lui (bfd *abfd,
		      asection *sec,
		      asection *sym_sec,
		      struct bfd_link_info *link_info,
		      Elf_Internal_Rela *rel,
		      bfd_vma symval,
		      bfd_vma max_alignment,
		      bfd_vma reserve_size,
		      bool *again,
		      riscv_pcgp_relocs *pcgp_relocs,
		      bool undefined_weak)
{
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (link_info);
  bfd_byte *contents = elf_section_data (sec)->this_hdr.contents;
  /* Can relax to x0 even when gp relaxation is disabled.  */
  bfd_vma gp = htab->params->relax_gp
	       ? riscv_global_pointer_value (link_info)
	       : 0;
  bfd_vma data_segment_alignment = link_info->relro
				   ? ELF_MAXPAGESIZE + ELF_COMMONPAGESIZE
				   : ELF_MAXPAGESIZE;
  int use_rvc = elf_elfheader (abfd)->e_flags & EF_RISCV_RVC;

  BFD_ASSERT (rel->r_offset + 4 <= sec->size);

  if (!undefined_weak && gp)
    {
      /* If gp and the symbol are in the same output section, which is not the
	 abs section, then consider only that output section's alignment.  */
      struct bfd_link_hash_entry *h =
	bfd_link_hash_lookup (link_info->hash, RISCV_GP_SYMBOL, false, false,
			      true);
      if (h->u.def.section->output_section == sym_sec->output_section
	  && sym_sec->output_section != bfd_abs_section_ptr)
	max_alignment = (bfd_vma) 1 << sym_sec->output_section->alignment_power;
      else
	{
	  /* Consider output section alignments which are in [gp-2K, gp+2K). */
	  max_alignment = htab->max_alignment_for_gp;
	  if (max_alignment == (bfd_vma) -1)
	    {
	      max_alignment = _bfd_riscv_get_max_alignment (sec, gp);
	      htab->max_alignment_for_gp = max_alignment;
	    }
	}

      /* PR27566, for default linker script, if a symbol's value outsides the
	 bounds of the defined section, then it may cross the data segment
	 alignment, so we should reserve more size about MAXPAGESIZE and
	 COMMONPAGESIZE, since the data segment alignment might move the
	 section forward.  */
      if (symval < sec_addr (sym_sec)
	  || symval > (sec_addr (sym_sec) + sym_sec->size))
	max_alignment = data_segment_alignment > max_alignment
			? data_segment_alignment : max_alignment;
    }

  /* Is the reference in range of x0 or gp?
     Valid gp range conservatively because of alignment issue.

     Should we also consider the alignment issue for x0 base?  */
  if (undefined_weak
      || VALID_ITYPE_IMM (symval)
      || (symval >= gp
	  && VALID_ITYPE_IMM (symval - gp + max_alignment + reserve_size))
      || (symval < gp
	  && VALID_ITYPE_IMM (symval - gp - max_alignment - reserve_size)))
    {
      unsigned sym = ELF32_R_SYM (rel->r_info);
      switch (ELF32_R_TYPE (rel->r_info))
	{
	case R_RISCV_LO12_I:
	  rel->r_info = ELF32_R_INFO (sym, R_RISCV_GPREL_I);
	  return true;

	case R_RISCV_LO12_S:
	  rel->r_info = ELF32_R_INFO (sym, R_RISCV_GPREL_S);
	  return true;

	case R_RISCV_HI20:
	  /* Delete unnecessary LUI and reuse the reloc.  */
	  *again = true;
	  return riscv_relax_delete_bytes (abfd, sec, rel->r_offset, 4,
					   link_info, pcgp_relocs, rel);

	default:
	  abort ();
	}
    }

  /* Can we relax LUI to C.LUI?  Alignment might move the section forward;
     account for this assuming page alignment at worst. In the presence of 
     RELRO segment the linker aligns it by one page size, therefore sections
     after the segment can be moved more than one page. */

  if (use_rvc
      && ELF32_R_TYPE (rel->r_info) == R_RISCV_HI20
      && VALID_CITYPE_LUI_IMM (RISCV_CONST_HIGH_PART (symval))
      && VALID_CITYPE_LUI_IMM (RISCV_CONST_HIGH_PART (symval)
			       + data_segment_alignment))
    {
      /* Replace LUI with C.LUI if legal (i.e., rd != x0 and rd != x2/sp).  */
      bfd_vma lui = bfd_getl32 (contents + rel->r_offset);
      unsigned rd = ((unsigned)lui >> OP_SH_RD) & OP_MASK_RD;
      if (rd == 0 || rd == X_SP)
	return true;

      lui = (lui & (OP_MASK_RD << OP_SH_RD)) | MATCH_C_LUI;
      bfd_putl32 (lui, contents + rel->r_offset);

      /* Replace the R_RISCV_HI20 reloc.  */
      rel->r_info = ELF32_R_INFO (ELF32_R_SYM (rel->r_info), R_RISCV_RVC_LUI);

      /* Delete extra bytes and reuse the R_RISCV_RELAX reloc.  */
      *again = true;
      return riscv_relax_delete_bytes (abfd, sec, rel->r_offset + 2, 2,
				       link_info, pcgp_relocs, rel + 1);
    }

  return true;
}

/* Relax non-PIC TLS references to TP-relative references.  */

static bool
_bfd_riscv_relax_tls_le (bfd *abfd,
			 asection *sec,
			 asection *sym_sec ATTRIBUTE_UNUSED,
			 struct bfd_link_info *link_info,
			 Elf_Internal_Rela *rel,
			 bfd_vma symval,
			 bfd_vma max_alignment ATTRIBUTE_UNUSED,
			 bfd_vma reserve_size ATTRIBUTE_UNUSED,
			 bool *again,
			 riscv_pcgp_relocs *pcgp_relocs,
			 bool undefined_weak ATTRIBUTE_UNUSED)
{
  /* See if this symbol is in range of tp.  */
  if (RISCV_CONST_HIGH_PART (tpoff (link_info, symval)) != 0)
    return true;

  BFD_ASSERT (rel->r_offset + 4 <= sec->size);
  switch (ELF32_R_TYPE (rel->r_info))
    {
    case R_RISCV_TPREL_LO12_I:
      rel->r_info = ELF32_R_INFO (ELF32_R_SYM (rel->r_info), R_RISCV_TPREL_I);
      return true;

    case R_RISCV_TPREL_LO12_S:
      rel->r_info = ELF32_R_INFO (ELF32_R_SYM (rel->r_info), R_RISCV_TPREL_S);
      return true;

    case R_RISCV_TPREL_HI20:
    case R_RISCV_TPREL_ADD:
      /* Delete unnecessary instruction and reuse the reloc.  */
      *again = true;
      return riscv_relax_delete_bytes (abfd, sec, rel->r_offset, 4, link_info,
				       pcgp_relocs, rel);

    default:
      abort ();
    }
}

/* Implement R_RISCV_ALIGN by deleting excess alignment NOPs.
   Once we've handled an R_RISCV_ALIGN, we can't relax anything else.  */

static bool
_bfd_riscv_relax_align (bfd *abfd, asection *sec,
			asection *sym_sec,
			struct bfd_link_info *link_info,
			Elf_Internal_Rela *rel,
			bfd_vma symval,
			bfd_vma max_alignment ATTRIBUTE_UNUSED,
			bfd_vma reserve_size ATTRIBUTE_UNUSED,
			bool *again ATTRIBUTE_UNUSED,
			riscv_pcgp_relocs *pcgp_relocs ATTRIBUTE_UNUSED,
			bool undefined_weak ATTRIBUTE_UNUSED)
{
  bfd_byte *contents = elf_section_data (sec)->this_hdr.contents;
  bfd_vma alignment = 1, pos;
  while (alignment <= rel->r_addend)
    alignment *= 2;

  symval -= rel->r_addend;
  bfd_vma aligned_addr = ((symval - 1) & ~(alignment - 1)) + alignment;
  bfd_vma nop_bytes = aligned_addr - symval;

  /* Once we've handled an R_RISCV_ALIGN, we can't relax anything else.  */
  sec->sec_flg0 = true;

  /* Make sure there are enough NOPs to actually achieve the alignment.  */
  if (rel->r_addend < nop_bytes)
    {
      _bfd_error_handler
	(_("%pB(%pA+%#" PRIx64 "): %" PRId64 " bytes required for alignment "
	   "to %" PRId64 "-byte boundary, but only %" PRId64 " present"),
	 abfd, sym_sec, (uint64_t) rel->r_offset,
	 (int64_t) nop_bytes, (int64_t) alignment, (int64_t) rel->r_addend);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  /* Delete the reloc.  */
  rel->r_info = ELF32_R_INFO (0, R_RISCV_NONE);

  /* If the number of NOPs is already correct, there's nothing to do.  */
  if (nop_bytes == rel->r_addend)
    return true;

  /* Write as many RISC-V NOPs as we need.  */
  for (pos = 0; pos < (nop_bytes & -4); pos += 4)
    bfd_putl32 (RISCV_NOP, contents + rel->r_offset + pos);

  /* Write a final RVC NOP if need be.  */
  if (nop_bytes % 4 != 0)
    bfd_putl16 (RVC_NOP, contents + rel->r_offset + pos);

  /* Delete excess bytes.  */
  return riscv_relax_delete_bytes (abfd, sec, rel->r_offset + nop_bytes,
				   rel->r_addend - nop_bytes, link_info,
				   NULL, NULL);
}

/* Relax PC-relative references to GP-relative references.  */

static bool
_bfd_riscv_relax_pc (bfd *abfd ATTRIBUTE_UNUSED,
		     asection *sec,
		     asection *sym_sec,
		     struct bfd_link_info *link_info,
		     Elf_Internal_Rela *rel,
		     bfd_vma symval,
		     bfd_vma max_alignment,
		     bfd_vma reserve_size,
		     bool *again,
		     riscv_pcgp_relocs *pcgp_relocs,
		     bool undefined_weak)
{
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (link_info);
  /* Can relax to x0 even when gp relaxation is disabled.  */
  bfd_vma gp = htab->params->relax_gp
	       ? riscv_global_pointer_value (link_info)
	       : 0;
  bfd_vma data_segment_alignment = link_info->relro
				   ? ELF_MAXPAGESIZE + ELF_COMMONPAGESIZE
				   : ELF_MAXPAGESIZE;

  BFD_ASSERT (rel->r_offset + 4 <= sec->size);

  /* Chain the _LO relocs to their cooresponding _HI reloc to compute the
     actual target address.  */
  riscv_pcgp_hi_reloc hi_reloc;
  memset (&hi_reloc, 0, sizeof (hi_reloc));
  switch (ELF32_R_TYPE (rel->r_info))
    {
    case R_RISCV_PCREL_LO12_I:
    case R_RISCV_PCREL_LO12_S:
      {
	/* If the %lo has an addend, it isn't for the label pointing at the
	   hi part instruction, but rather for the symbol pointed at by the
	   hi part instruction.  So we must subtract it here for the lookup.
	   It is still used below in the final symbol address.  */
	bfd_vma hi_sec_off = symval - sec_addr (sym_sec) - rel->r_addend;
	riscv_pcgp_hi_reloc *hi = riscv_find_pcgp_hi_reloc (pcgp_relocs,
							    hi_sec_off);
	if (hi == NULL)
	  {
	    riscv_record_pcgp_lo_reloc (pcgp_relocs, hi_sec_off);
	    return true;
	  }

	hi_reloc = *hi;
	symval = hi_reloc.hi_addr;
	sym_sec = hi_reloc.sym_sec;

	/* We can not know whether the undefined weak symbol is referenced
	   according to the information of R_RISCV_PCREL_LO12_I/S.  Therefore,
	   we have to record the 'undefined_weak' flag when handling the
	   corresponding R_RISCV_HI20 reloc in riscv_record_pcgp_hi_reloc.  */
	undefined_weak = hi_reloc.undefined_weak;
      }
      break;

    case R_RISCV_PCREL_HI20:
      /* Mergeable symbols and code might later move out of range.  */
      if (! undefined_weak
	  && sym_sec->flags & (SEC_MERGE | SEC_CODE))
	return true;

      /* If the cooresponding lo relocation has already been seen then it's not
         safe to relax this relocation.  */
      if (riscv_find_pcgp_lo_reloc (pcgp_relocs, rel->r_offset))
	return true;

      break;

    default:
      abort ();
    }

  if (!undefined_weak && gp)
    {
      /* If gp and the symbol are in the same output section, which is not the
	 abs section, then consider only that output section's alignment.  */
      struct bfd_link_hash_entry *h =
	bfd_link_hash_lookup (link_info->hash, RISCV_GP_SYMBOL, false, false,
			      true);
      if (h->u.def.section->output_section == sym_sec->output_section
	  && sym_sec->output_section != bfd_abs_section_ptr)
	max_alignment = (bfd_vma) 1 << sym_sec->output_section->alignment_power;
      else
	{
	  /* Consider output section alignments which are in [gp-2K, gp+2K). */
	  max_alignment = htab->max_alignment_for_gp;
	  if (max_alignment == (bfd_vma) -1)
	    {
	      max_alignment = _bfd_riscv_get_max_alignment (sec, gp);
	      htab->max_alignment_for_gp = max_alignment;
	    }
	}

      /* PR27566, for default linker script, if a symbol's value outsides the
	 bounds of the defined section, then it may cross the data segment
	 alignment, so we should reserve more size about MAXPAGESIZE and
	 COMMONPAGESIZE, since the data segment alignment might move the
	 section forward.  */
      if (symval < sec_addr (sym_sec)
	  || symval > (sec_addr (sym_sec) + sym_sec->size))
	max_alignment = data_segment_alignment > max_alignment
			? data_segment_alignment : max_alignment;
    }

  /* Is the reference in range of x0 or gp?
     Valid gp range conservatively because of alignment issue.

     Should we also consider the alignment issue for x0 base?  */
  if (undefined_weak
      || VALID_ITYPE_IMM (symval)
      || (symval >= gp
	  && VALID_ITYPE_IMM (symval - gp + max_alignment + reserve_size))
      || (symval < gp
	  && VALID_ITYPE_IMM (symval - gp - max_alignment - reserve_size)))
    {
      unsigned sym = hi_reloc.hi_sym;
      switch (ELF32_R_TYPE (rel->r_info))
	{
	case R_RISCV_PCREL_LO12_I:
	  rel->r_info = ELF32_R_INFO (sym, R_RISCV_GPREL_I);
	  rel->r_addend += hi_reloc.hi_addend;
	  return true;

	case R_RISCV_PCREL_LO12_S:
	  rel->r_info = ELF32_R_INFO (sym, R_RISCV_GPREL_S);
	  rel->r_addend += hi_reloc.hi_addend;
	  return true;

	case R_RISCV_PCREL_HI20:
	  riscv_record_pcgp_hi_reloc (pcgp_relocs,
				      rel->r_offset,
				      rel->r_addend,
				      symval,
				      ELF32_R_SYM(rel->r_info),
				      sym_sec,
				      undefined_weak);
	  /* Delete unnecessary AUIPC and reuse the reloc.  */
	  *again = true;
	  riscv_relax_delete_bytes (abfd, sec, rel->r_offset, 4, link_info,
				    pcgp_relocs, rel);
	  return true;

	default:
	  abort ();
	}
    }

  return true;
}

/* Called by after_allocation to set the information of data segment
   before relaxing.  */

void
bfd_elf32_riscv_set_data_segment_info (struct bfd_link_info *info,
                                       int *data_segment_phase)
{
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  htab->data_segment_phase = data_segment_phase;
}

/* Relax a section.

   Pass 0: Shortens code sequences for LUI/CALL/TPREL/PCREL relocs and
	   deletes the obsolete bytes.
   Pass 1: Which cannot be disabled, handles code alignment directives.  */

static bool
_bfd_riscv_relax_section (bfd *abfd, asection *sec,
			  struct bfd_link_info *info,
			  bool *again)
{
  Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (abfd);
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  struct bfd_elf_section_data *data = elf_section_data (sec);
  Elf_Internal_Rela *relocs;
  bool ret = false;
  unsigned int i;
  bfd_vma max_alignment, reserve_size = 0;
  riscv_pcgp_relocs pcgp_relocs;
  static asection *first_section = NULL;

  *again = false;

  if (bfd_link_relocatable (info)
      || sec->sec_flg0
      || sec->reloc_count == 0
      || (sec->flags & SEC_RELOC) == 0
      || (sec->flags & SEC_HAS_CONTENTS) == 0
      || (info->disable_target_specific_optimizations
	  && info->relax_pass == 0)
      /* The exp_seg_relro_adjust is enum phase_enum (0x4),
	 and defined in ld/ldexp.h.  */
      || *(htab->data_segment_phase) == 4)
    return true;

  /* Record the first relax section, so that we can reset the
     max_alignment_for_gp for the repeated relax passes.  */
  if (first_section == NULL)
    first_section = sec;
  else if (first_section == sec)
    htab->max_alignment_for_gp = -1;

  riscv_init_pcgp_relocs (&pcgp_relocs);

  /* Read this BFD's relocs if we haven't done so already.  */
  if (data->relocs)
    relocs = data->relocs;
  else if (!(relocs = _bfd_elf_link_read_relocs (abfd, sec, NULL, NULL,
						 info->keep_memory)))
    goto fail;

  /* Estimate the maximum alignment for all output sections once time
     should be enough.  */
  max_alignment = htab->max_alignment;
  if (max_alignment == (bfd_vma) -1)
    {
      max_alignment = _bfd_riscv_get_max_alignment (sec, 0/* gp */);
      htab->max_alignment = max_alignment;
    }

  /* Examine and consider relaxing each reloc.  */
  for (i = 0; i < sec->reloc_count; i++)
    {
      asection *sym_sec;
      Elf_Internal_Rela *rel = relocs + i;
      relax_func_t relax_func;
      int type = ELF32_R_TYPE (rel->r_info);
      bfd_vma symval;
      char symtype;
      bool undefined_weak = false;

      relax_func = NULL;
      riscv_relax_delete_bytes = NULL;
      if (info->relax_pass == 0)
	{
	  if (type == R_RISCV_CALL
	      || type == R_RISCV_CALL_PLT)
	    relax_func = _bfd_riscv_relax_call;
	  else if (type == R_RISCV_HI20
		   || type == R_RISCV_LO12_I
		   || type == R_RISCV_LO12_S)
	    relax_func = _bfd_riscv_relax_lui;
	  else if (type == R_RISCV_TPREL_HI20
		   || type == R_RISCV_TPREL_ADD
		   || type == R_RISCV_TPREL_LO12_I
		   || type == R_RISCV_TPREL_LO12_S)
	    relax_func = _bfd_riscv_relax_tls_le;
	  else if (!bfd_link_pic (info)
		   && (type == R_RISCV_PCREL_HI20
		       || type == R_RISCV_PCREL_LO12_I
		       || type == R_RISCV_PCREL_LO12_S))
	    relax_func = _bfd_riscv_relax_pc;
	  else
	    continue;
	  riscv_relax_delete_bytes = _riscv_relax_delete_piecewise;

	  /* Only relax this reloc if it is paired with R_RISCV_RELAX.  */
	  if (i == sec->reloc_count - 1
	      || ELF32_R_TYPE ((rel + 1)->r_info) != R_RISCV_RELAX
	      || rel->r_offset != (rel + 1)->r_offset)
	    continue;

	  /* Skip over the R_RISCV_RELAX.  */
	  i++;
	}
      else if (info->relax_pass == 1 && type == R_RISCV_ALIGN)
	{
	  relax_func = _bfd_riscv_relax_align;
	  riscv_relax_delete_bytes = _riscv_relax_delete_immediate;
	}
      else
	continue;

      data->relocs = relocs;

      /* Read this BFD's contents if we haven't done so already.  */
      if (!data->this_hdr.contents
	  && !bfd_malloc_and_get_section (abfd, sec, &data->this_hdr.contents))
	goto fail;

      /* Read this BFD's symbols if we haven't done so already.  */
      if (symtab_hdr->sh_info != 0
	  && !symtab_hdr->contents
	  && !(symtab_hdr->contents =
	       (unsigned char *) bfd_elf_get_elf_syms (abfd, symtab_hdr,
						       symtab_hdr->sh_info,
						       0, NULL, NULL, NULL)))
	goto fail;

      /* Get the value of the symbol referred to by the reloc.  */
      if (ELF32_R_SYM (rel->r_info) < symtab_hdr->sh_info)
	{
	  /* A local symbol.  */
	  Elf_Internal_Sym *isym = ((Elf_Internal_Sym *) symtab_hdr->contents
				    + ELF32_R_SYM (rel->r_info));
	  reserve_size = (isym->st_size - rel->r_addend) > isym->st_size
	    ? 0 : isym->st_size - rel->r_addend;

	  /* Relocate against local STT_GNU_IFUNC symbol.  we have created
	     a fake global symbol entry for this, so deal with the local ifunc
	     as a global.  */
	  if (ELF_ST_TYPE (isym->st_info) == STT_GNU_IFUNC)
	    continue;

	  if (isym->st_shndx == SHN_UNDEF)
	    sym_sec = sec, symval = rel->r_offset;
	  else
	    {
	      BFD_ASSERT (isym->st_shndx < elf_numsections (abfd));
	      sym_sec = elf_elfsections (abfd)[isym->st_shndx]->bfd_section;
#if 0
	      /* The purpose of this code is unknown.  It breaks linker scripts
		 for embedded development that place sections at address zero.
		 This code is believed to be unnecessary.  Disabling it but not
		 yet removing it, in case something breaks.  */
	      if (sec_addr (sym_sec) == 0)
		continue;
#endif
	      symval = isym->st_value;
	    }
	  symtype = ELF_ST_TYPE (isym->st_info);
	}
      else
	{
	  unsigned long indx;
	  struct elf_link_hash_entry *h;

	  indx = ELF32_R_SYM (rel->r_info) - symtab_hdr->sh_info;
	  h = elf_sym_hashes (abfd)[indx];

	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;

	  /* Disable the relaxation for ifunc.  */
	  if (h != NULL && h->type == STT_GNU_IFUNC)
	    continue;

	  /* Maybe we should check UNDEFWEAK_NO_DYNAMIC_RELOC here?  But that
	     will break the undefweak relaxation testcases, so just make sure
	     we won't do relaxations for linker_def symbols in short-term.  */
	  if (h->root.type == bfd_link_hash_undefweak
	      /* The linker_def symbol like __ehdr_start that may be undefweak
		 for now, but will be guaranteed to be defined later.  */
	      && !h->root.linker_def
	      && (relax_func == _bfd_riscv_relax_lui
		  || relax_func == _bfd_riscv_relax_pc))
	    {
	      /* For the lui and auipc relaxations, since the symbol
		 value of an undefined weak symbol is always be zero,
		 we can optimize the patterns into a single LI/MV/ADDI
		 instruction.

		 Note that, creating shared libraries and pie output may
		 break the rule above.  Fortunately, since we do not relax
		 pc relocs when creating shared libraries and pie output,
		 and the absolute address access for R_RISCV_HI20 isn't
		 allowed when "-fPIC" is set, the problem of creating shared
		 libraries can not happen currently.  Once we support the
		 auipc relaxations when creating shared libraries, then we will
		 need the more rigorous checking for this optimization.  */
	      undefined_weak = true;
	    }

	  /* This line has to match the via_pltcheck in
	     riscv_elf_relocate_section in the R_RISCV_CALL[_PLT] case.  */
	  if (h->plt.offset != MINUS_ONE)
	    {
	      sym_sec = htab->elf.splt;
	      symval = h->plt.offset;
	    }
	  else if (undefined_weak)
	    {
	      symval = 0;
	      sym_sec = bfd_und_section_ptr;
	    }
	  else if ((h->root.type == bfd_link_hash_defined
		    || h->root.type == bfd_link_hash_defweak)
		   && h->root.u.def.section != NULL
		   && h->root.u.def.section->output_section != NULL)
	    {
	      symval = h->root.u.def.value;
	      sym_sec = h->root.u.def.section;
	    }
	  else
	    continue;

	  if (h->type != STT_FUNC)
	    reserve_size =
	      (h->size - rel->r_addend) > h->size ? 0 : h->size - rel->r_addend;
	  symtype = h->type;
	}

      if (sym_sec->sec_info_type == SEC_INFO_TYPE_MERGE
          && (sym_sec->flags & SEC_MERGE))
	{
	  /* At this stage in linking, no SEC_MERGE symbol has been
	     adjusted, so all references to such symbols need to be
	     passed through _bfd_merged_section_offset.  (Later, in
	     relocate_section, all SEC_MERGE symbols *except* for
	     section symbols have been adjusted.)

	     gas may reduce relocations against symbols in SEC_MERGE
	     sections to a relocation against the section symbol when
	     the original addend was zero.  When the reloc is against
	     a section symbol we should include the addend in the
	     offset passed to _bfd_merged_section_offset, since the
	     location of interest is the original symbol.  On the
	     other hand, an access to "sym+addend" where "sym" is not
	     a section symbol should not include the addend;  Such an
	     access is presumed to be an offset from "sym";  The
	     location of interest is just "sym".  */
	   if (symtype == STT_SECTION)
	     symval += rel->r_addend;

	   symval = _bfd_merged_section_offset (abfd, &sym_sec,
						elf_section_data (sym_sec)->sec_info,
						symval);

	   if (symtype != STT_SECTION)
	     symval += rel->r_addend;
	}
      else
	symval += rel->r_addend;

      symval += sec_addr (sym_sec);

      if (!relax_func (abfd, sec, sym_sec, info, rel, symval,
		       max_alignment, reserve_size, again,
		       &pcgp_relocs, undefined_weak))
	goto fail;
    }

  /* Resolve R_RISCV_DELETE relocations.  */
  if (!riscv_relax_resolve_delete_relocs (abfd, sec, info, relocs))
    goto fail;

  ret = true;

 fail:
  if (relocs != data->relocs)
    free (relocs);
  riscv_free_pcgp_relocs (&pcgp_relocs, abfd, sec);

  return ret;
}

#if ARCH_SIZE == 32
# define PRSTATUS_SIZE			204
# define PRSTATUS_OFFSET_PR_CURSIG	12
# define PRSTATUS_OFFSET_PR_PID		24
# define PRSTATUS_OFFSET_PR_REG		72
# define ELF_GREGSET_T_SIZE		128
# define PRPSINFO_SIZE			128
# define PRPSINFO_OFFSET_PR_PID		16
# define PRPSINFO_OFFSET_PR_FNAME	32
# define PRPSINFO_OFFSET_PR_PSARGS	48
# define PRPSINFO_PR_FNAME_LENGTH	16
# define PRPSINFO_PR_PSARGS_LENGTH	80
#else
# define PRSTATUS_SIZE			376
# define PRSTATUS_OFFSET_PR_CURSIG	12
# define PRSTATUS_OFFSET_PR_PID		32
# define PRSTATUS_OFFSET_PR_REG		112
# define ELF_GREGSET_T_SIZE		256
# define PRPSINFO_SIZE			136
# define PRPSINFO_OFFSET_PR_PID		24
# define PRPSINFO_OFFSET_PR_FNAME	40
# define PRPSINFO_OFFSET_PR_PSARGS	56
# define PRPSINFO_PR_FNAME_LENGTH	16
# define PRPSINFO_PR_PSARGS_LENGTH	80
#endif

/* Write PRSTATUS and PRPSINFO note into core file.  This will be called
   before the generic code in elf.c.  By checking the compiler defines we
   only perform any action here if the generic code would otherwise not be
   able to help us.  The intention is that bare metal core dumps (where the
   prstatus_t and/or prpsinfo_t might not be available) will use this code,
   while non bare metal tools will use the generic elf code.  */

static char *
riscv_write_core_note (bfd *abfd ATTRIBUTE_UNUSED,
                       char *buf ATTRIBUTE_UNUSED,
                       int *bufsiz ATTRIBUTE_UNUSED,
                       int note_type ATTRIBUTE_UNUSED, ...)
{
  switch (note_type)
    {
    default:
      return NULL;

#if !defined (HAVE_PRPSINFO_T)
    case NT_PRPSINFO:
      {
	char data[PRPSINFO_SIZE] ATTRIBUTE_NONSTRING;
	va_list ap;

	va_start (ap, note_type);
	memset (data, 0, sizeof (data));
	strncpy (data + PRPSINFO_OFFSET_PR_FNAME, va_arg (ap, const char *),
                 PRPSINFO_PR_FNAME_LENGTH);
#if GCC_VERSION == 8000 || GCC_VERSION == 8001
	DIAGNOSTIC_PUSH;
	/* GCC 8.0 and 8.1 warn about 80 equals destination size with
	   -Wstringop-truncation:
	   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=85643
	 */
	DIAGNOSTIC_IGNORE_STRINGOP_TRUNCATION;
#endif
	strncpy (data + PRPSINFO_OFFSET_PR_PSARGS, va_arg (ap, const char *),
                 PRPSINFO_PR_PSARGS_LENGTH);
#if GCC_VERSION == 8000 || GCC_VERSION == 8001
	DIAGNOSTIC_POP;
#endif
	va_end (ap);
	return elfcore_write_note (abfd, buf, bufsiz,
				   "CORE", note_type, data, sizeof (data));
      }
#endif /* !HAVE_PRPSINFO_T */

#if !defined (HAVE_PRSTATUS_T)
    case NT_PRSTATUS:
      {
        char data[PRSTATUS_SIZE];
        va_list ap;
        long pid;
        int cursig;
        const void *greg;

        va_start (ap, note_type);
        memset (data, 0, sizeof(data));
        pid = va_arg (ap, long);
        bfd_put_32 (abfd, pid, data + PRSTATUS_OFFSET_PR_PID);
        cursig = va_arg (ap, int);
        bfd_put_16 (abfd, cursig, data + PRSTATUS_OFFSET_PR_CURSIG);
        greg = va_arg (ap, const void *);
        memcpy (data + PRSTATUS_OFFSET_PR_REG, greg,
                PRSTATUS_SIZE - PRSTATUS_OFFSET_PR_REG - ARCH_SIZE / 8);
        va_end (ap);
        return elfcore_write_note (abfd, buf, bufsiz,
                                   "CORE", note_type, data, sizeof (data));
      }
#endif /* !HAVE_PRSTATUS_T */
    }
}

/* Support for core dump NOTE sections.  */

static bool
riscv_elf_grok_prstatus (bfd *abfd, Elf_Internal_Note *note)
{
  switch (note->descsz)
    {
      default:
	return false;

      case PRSTATUS_SIZE: /* sizeof(struct elf_prstatus) on Linux/RISC-V.  */
	/* pr_cursig */
	elf_tdata (abfd)->core->signal
	  = bfd_get_16 (abfd, note->descdata + PRSTATUS_OFFSET_PR_CURSIG);

	/* pr_pid */
	elf_tdata (abfd)->core->lwpid
	  = bfd_get_32 (abfd, note->descdata + PRSTATUS_OFFSET_PR_PID);
	break;
    }

  /* Make a ".reg/999" section.  */
  return _bfd_elfcore_make_pseudosection (abfd, ".reg", ELF_GREGSET_T_SIZE,
					  note->descpos + PRSTATUS_OFFSET_PR_REG);
}

static bool
riscv_elf_grok_psinfo (bfd *abfd, Elf_Internal_Note *note)
{
  switch (note->descsz)
    {
      default:
	return false;

      case PRPSINFO_SIZE: /* sizeof(struct elf_prpsinfo) on Linux/RISC-V.  */
	/* pr_pid */
	elf_tdata (abfd)->core->pid
	  = bfd_get_32 (abfd, note->descdata + PRPSINFO_OFFSET_PR_PID);

	/* pr_fname */
	elf_tdata (abfd)->core->program = _bfd_elfcore_strndup
	  (abfd, note->descdata + PRPSINFO_OFFSET_PR_FNAME,
           PRPSINFO_PR_FNAME_LENGTH);

	/* pr_psargs */
	elf_tdata (abfd)->core->command = _bfd_elfcore_strndup
	  (abfd, note->descdata + PRPSINFO_OFFSET_PR_PSARGS,
           PRPSINFO_PR_PSARGS_LENGTH);
	break;
    }

  /* Note that for some reason, a spurious space is tacked
     onto the end of the args in some (at least one anyway)
     implementations, so strip it off if it exists.  */

  {
    char *command = elf_tdata (abfd)->core->command;
    int n = strlen (command);

    if (0 < n && command[n - 1] == ' ')
      command[n - 1] = '\0';
  }

  return true;
}

/* Set the right mach type.  */

static bool
riscv_elf_object_p (bfd *abfd)
{
  /* There are only two mach types in RISCV currently.  */
  if (strcmp (abfd->xvec->name, "elf32-littleriscv") == 0
      || strcmp (abfd->xvec->name, "elf32-bigriscv") == 0)
    bfd_default_set_arch_mach (abfd, bfd_arch_riscv, bfd_mach_riscv32);
  else
    bfd_default_set_arch_mach (abfd, bfd_arch_riscv, bfd_mach_riscv64);

  return true;
}

/* Determine whether an object attribute tag takes an integer, a
   string or both.  */

static int
riscv_elf_obj_attrs_arg_type (int tag)
{
  return (tag & 1) != 0 ? ATTR_TYPE_FLAG_STR_VAL : ATTR_TYPE_FLAG_INT_VAL;
}

/* Do not choose mapping symbols as a function name.  */

static bfd_size_type
riscv_maybe_function_sym (const asymbol *sym,
			  asection *sec,
			  bfd_vma *code_off)
{
  if (sym->flags & BSF_LOCAL
      && (riscv_elf_is_mapping_symbols (sym->name)
	  || _bfd_elf_is_local_label_name (sec->owner, sym->name)))
    return 0;

  return _bfd_elf_maybe_function_sym (sym, sec, code_off);
}

/* Treat the following cases as target special symbols, they are
   usually omitted.  */

static bool
riscv_elf_is_target_special_symbol (bfd *abfd, asymbol *sym)
{
  /* PR27584, local and empty symbols.  Since they are usually
     generated for pcrel relocations.  */
  return (!sym->name[0]
	  || _bfd_elf_is_local_label_name (abfd, sym->name)
	  /* PR27916, mapping symbols.  */
	  || riscv_elf_is_mapping_symbols (sym->name));
}

static int
riscv_elf_additional_program_headers (bfd *abfd,
				      struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  int ret = 0;

  /* See if we need a PT_RISCV_ATTRIBUTES segment.  */
  if (bfd_get_section_by_name (abfd, RISCV_ATTRIBUTES_SECTION_NAME))
    ++ret;

  return ret;
}

static bool
riscv_elf_modify_segment_map (bfd *abfd,
			      struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  asection *s;
  struct elf_segment_map *m, **pm;
  size_t amt;

  /* If there is a .riscv.attributes section, we need a PT_RISCV_ATTRIBUTES
     segment.  */
  s = bfd_get_section_by_name (abfd, RISCV_ATTRIBUTES_SECTION_NAME);
  if (s != NULL)
    {
      for (m = elf_seg_map (abfd); m != NULL; m = m->next)
	if (m->p_type == PT_RISCV_ATTRIBUTES)
	  break;
      /* If there is already a PT_RISCV_ATTRIBUTES header, avoid adding
	 another.  */
      if (m == NULL)
	{
	  amt = sizeof (*m);
	  m = bfd_zalloc (abfd, amt);
	  if (m == NULL)
	    return false;

	  m->p_type = PT_RISCV_ATTRIBUTES;
	  m->count = 1;
	  m->sections[0] = s;

	  /* We want to put it after the PHDR and INTERP segments.  */
	  pm = &elf_seg_map (abfd);
	  while (*pm != NULL
		 && ((*pm)->p_type == PT_PHDR
		     || (*pm)->p_type == PT_INTERP))
	    pm = &(*pm)->next;

	  m->next = *pm;
	  *pm = m;
	}
    }

  return true;
}

/* Merge non-visibility st_other attributes.  */

static void
riscv_elf_merge_symbol_attribute (struct elf_link_hash_entry *h,
				  unsigned int st_other,
				  bool definition ATTRIBUTE_UNUSED,
				  bool dynamic ATTRIBUTE_UNUSED)
{
  unsigned int isym_sto = st_other & ~ELF_ST_VISIBILITY (-1);
  unsigned int h_sto = h->other & ~ELF_ST_VISIBILITY (-1);

  if (isym_sto == h_sto)
    return;

  if (isym_sto & ~STO_RISCV_VARIANT_CC)
    _bfd_error_handler (_("unknown attribute for symbol `%s': 0x%02x"),
			h->root.root.string, isym_sto);

  if (isym_sto & STO_RISCV_VARIANT_CC)
    h->other |= STO_RISCV_VARIANT_CC;
}

/* Implement elf_backend_setup_gnu_properties for RISC-V.  It serves as a
   wrapper function for _bfd_riscv_elf_link_setup_gnu_properties to account
   for the effect of GNU properties of the output_bfd.  */

static bfd *
elf32_riscv_link_setup_gnu_properties (struct bfd_link_info *info)
{
  uint32_t and_prop = _bfd_riscv_elf_tdata (info->output_bfd)->gnu_and_prop;

  bfd *pbfd = _bfd_riscv_elf_link_setup_gnu_properties (info, &and_prop);

  _bfd_riscv_elf_tdata (info->output_bfd)->gnu_and_prop = and_prop;

  if (and_prop & GNU_PROPERTY_RISCV_FEATURE_1_CFI_LP_UNLABELED)
    _bfd_riscv_elf_tdata (info->output_bfd)->plt_type = PLT_ZICFILP_UNLABELED;

  setup_plt_values (info->output_bfd, riscv_elf_hash_table (info),
		    _bfd_riscv_elf_tdata (info->output_bfd)->plt_type);

  return pbfd;
}

/* Implement elf_backend_merge_gnu_properties for RISC-V.  It serves as a
   wrapper function for _bfd_riscv_elf_merge_gnu_properties to account
   for the effect of GNU properties of the output_bfd.  */

static bool
elf32_riscv_merge_gnu_properties (struct bfd_link_info *info, bfd *abfd,
				  bfd *bbfd ATTRIBUTE_UNUSED,
				  elf_property *aprop, elf_property *bprop)
{
  uint32_t and_prop = _bfd_riscv_elf_tdata (info->output_bfd)->gnu_and_prop;

  return _bfd_riscv_elf_merge_gnu_properties (info, abfd, aprop, bprop,
					      and_prop);
}

#define TARGET_LITTLE_SYM			riscv_elf32_vec
#define TARGET_LITTLE_NAME			"elf32-littleriscv"
#define TARGET_BIG_SYM				riscv_elf32_be_vec
#define TARGET_BIG_NAME				"elf32-bigriscv"

#define elf_info_to_howto_rel			NULL
#define elf_info_to_howto			riscv_info_to_howto_rela

#define bfd_elf32_bfd_reloc_name_lookup		riscv_reloc_name_lookup
#define bfd_elf32_bfd_link_hash_table_create	\
  riscv_elf_link_hash_table_create
#define bfd_elf32_bfd_reloc_type_lookup		riscv_reloc_type_lookup
#define bfd_elf32_bfd_merge_private_bfd_data	\
  _bfd_riscv_elf_merge_private_bfd_data
#define bfd_elf32_bfd_is_target_special_symbol	\
  riscv_elf_is_target_special_symbol
#define bfd_elf32_bfd_relax_section		_bfd_riscv_relax_section
#define bfd_elf32_mkobject			elf32_riscv_mkobject
#define bfd_elf32_get_synthetic_symtab		\
  elf32_riscv_get_synthetic_symtab

#define elf_backend_reloc_type_class		riscv_reloc_type_class
#define elf_backend_copy_indirect_symbol	riscv_elf_copy_indirect_symbol
#define elf_backend_create_dynamic_sections	\
  riscv_elf_create_dynamic_sections
#define elf_backend_check_relocs		riscv_elf_check_relocs
#define elf_backend_adjust_dynamic_symbol	riscv_elf_adjust_dynamic_symbol
#define elf_backend_late_size_sections		riscv_elf_late_size_sections
#define elf_backend_relocate_section		riscv_elf_relocate_section
#define elf_backend_finish_dynamic_symbol	riscv_elf_finish_dynamic_symbol
#define elf_backend_finish_dynamic_sections	\
  riscv_elf_finish_dynamic_sections
#define elf_backend_plt_sym_val			riscv_elf_plt_sym_val
#define elf_backend_grok_prstatus		riscv_elf_grok_prstatus
#define elf_backend_grok_psinfo			riscv_elf_grok_psinfo
#define elf_backend_object_p			riscv_elf_object_p
#define elf_backend_write_core_note		riscv_write_core_note
#define elf_backend_maybe_function_sym		riscv_maybe_function_sym
#define elf_backend_additional_program_headers \
  riscv_elf_additional_program_headers
#define elf_backend_modify_segment_map		riscv_elf_modify_segment_map
#define elf_backend_merge_symbol_attribute	\
  riscv_elf_merge_symbol_attribute
#define elf_backend_init_index_section		_bfd_elf_init_1_index_section
#define elf_backend_setup_gnu_properties	\
  elf32_riscv_link_setup_gnu_properties
#define elf_backend_merge_gnu_properties	\
  elf32_riscv_merge_gnu_properties

#define elf_backend_can_gc_sections		1
#define elf_backend_can_refcount		1
#define elf_backend_want_got_plt		1
#define elf_backend_plt_readonly		1
#define elf_backend_plt_alignment		4
#define elf_backend_want_plt_sym		1
#define elf_backend_got_header_size		(ARCH_SIZE / 8)
#define elf_backend_want_dynrelro		1
#define elf_backend_rela_normal			1
#define elf_backend_default_execstack		0

#undef  elf_backend_obj_attrs_vendor
#define elf_backend_obj_attrs_vendor		"riscv"
#undef  elf_backend_obj_attrs_arg_type
#define elf_backend_obj_attrs_arg_type		riscv_elf_obj_attrs_arg_type
#undef  elf_backend_obj_attrs_section_type
#define elf_backend_obj_attrs_section_type	SHT_RISCV_ATTRIBUTES
#undef  elf_backend_obj_attrs_section
#define elf_backend_obj_attrs_section		RISCV_ATTRIBUTES_SECTION_NAME
#define elf_backend_obj_attrs_handle_unknown	\
  riscv_elf_obj_attrs_handle_unknown

#include "elf32-target.h"
