#line 1 "../../binutils-gdb/bfd/elfnn-ia64.c"
/* IA-64 support for 64-bit ELF
   Copyright (C) 1998-2025 Free Software Foundation, Inc.
   Contributed by David Mosberger-Tang <davidm@hpl.hp.com>

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
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "opcode/ia64.h"
#include "elf/ia64.h"
#include "objalloc.h"
#include "hashtab.h"
#include "elfxx-ia64.h"

#define ARCH_SIZE	32

#if ARCH_SIZE == 64
#define	LOG_SECTION_ALIGN	3
#endif

#if ARCH_SIZE == 32
#define	LOG_SECTION_ALIGN	2
#endif

#define is_ia64_elf(bfd)			   \
  (bfd_get_flavour (bfd) == bfd_target_elf_flavour \
   && elf_object_id (bfd) == IA64_ELF_DATA)

typedef struct bfd_hash_entry *(*new_hash_entry_func)
  (struct bfd_hash_entry *, struct bfd_hash_table *, const char *);

/* In dynamically (linker-) created sections, we generally need to keep track
   of the place a symbol or expression got allocated to. This is done via hash
   tables that store entries of the following type.  */

struct elf32_ia64_dyn_sym_info
{
  /* The addend for which this entry is relevant.  */
  bfd_vma addend;

  bfd_vma got_offset;
  bfd_vma fptr_offset;
  bfd_vma pltoff_offset;
  bfd_vma plt_offset;
  bfd_vma plt2_offset;
  bfd_vma tprel_offset;
  bfd_vma dtpmod_offset;
  bfd_vma dtprel_offset;

  /* The symbol table entry, if any, that this was derived from.  */
  struct elf_link_hash_entry *h;

  /* Used to count non-got, non-plt relocations for delayed sizing
     of relocation sections.  */
  struct elf32_ia64_dyn_reloc_entry
  {
    struct elf32_ia64_dyn_reloc_entry *next;
    asection *srel;
    int type;
    int count;

    /* Is this reloc against readonly section? */
    bool reltext;
  } *reloc_entries;

  /* TRUE when the section contents have been updated.  */
  unsigned got_done : 1;
  unsigned fptr_done : 1;
  unsigned pltoff_done : 1;
  unsigned tprel_done : 1;
  unsigned dtpmod_done : 1;
  unsigned dtprel_done : 1;

  /* TRUE for the different kinds of linker data we want created.  */
  unsigned want_got : 1;
  unsigned want_gotx : 1;
  unsigned want_fptr : 1;
  unsigned want_ltoff_fptr : 1;
  unsigned want_plt : 1;
  unsigned want_plt2 : 1;
  unsigned want_pltoff : 1;
  unsigned want_tprel : 1;
  unsigned want_dtpmod : 1;
  unsigned want_dtprel : 1;
};

struct elf32_ia64_local_hash_entry
{
  int id;
  unsigned int r_sym;
  /* The number of elements in elf32_ia64_dyn_sym_info array.  */
  unsigned int count;
  /* The number of sorted elements in elf32_ia64_dyn_sym_info array.  */
  unsigned int sorted_count;
  /* The size of elf32_ia64_dyn_sym_info array.  */
  unsigned int size;
  /* The array of elf32_ia64_dyn_sym_info.  */
  struct elf32_ia64_dyn_sym_info *info;

  /* TRUE if this hash entry's addends was translated for
     SHF_MERGE optimization.  */
  unsigned sec_merge_done : 1;
};

struct elf32_ia64_link_hash_entry
{
  struct elf_link_hash_entry root;
  /* The number of elements in elf32_ia64_dyn_sym_info array.  */
  unsigned int count;
  /* The number of sorted elements in elf32_ia64_dyn_sym_info array.  */
  unsigned int sorted_count;
  /* The size of elf32_ia64_dyn_sym_info array.  */
  unsigned int size;
  /* The array of elf32_ia64_dyn_sym_info.  */
  struct elf32_ia64_dyn_sym_info *info;
};

struct elf32_ia64_link_hash_table
{
  /* The main hash table.  */
  struct elf_link_hash_table root;

  asection *fptr_sec;		/* Function descriptor table (or NULL).  */
  asection *rel_fptr_sec;	/* Dynamic relocation section for same.  */
  asection *pltoff_sec;		/* Private descriptors for plt (or NULL).  */
  asection *rel_pltoff_sec;	/* Dynamic relocation section for same.  */

  bfd_size_type minplt_entries;	/* Number of minplt entries.  */
  unsigned self_dtpmod_done : 1;/* Has self DTPMOD entry been finished?  */
  bfd_vma self_dtpmod_offset;	/* .got offset to self DTPMOD entry.  */
  /* There are maybe R_IA64_GPREL22 relocations, including those
     optimized from R_IA64_LTOFF22X, against non-SHF_IA_64_SHORT
     sections.  We need to record those sections so that we can choose
     a proper GP to cover all R_IA64_GPREL22 relocations.  */
  asection *max_short_sec;	/* Maximum short output section.  */
  bfd_vma max_short_offset;	/* Maximum short offset.  */
  asection *min_short_sec;	/* Minimum short output section.  */
  bfd_vma min_short_offset;	/* Minimum short offset.  */

  htab_t loc_hash_table;
  void *loc_hash_memory;
};

struct elf32_ia64_allocate_data
{
  struct bfd_link_info *info;
  bfd_size_type ofs;
  bool only_got;
};

#define elf32_ia64_hash_table(p) \
  ((is_elf_hash_table ((p)->hash)					\
    && elf_hash_table_id (elf_hash_table (p)) == IA64_ELF_DATA)		\
   ? (struct elf32_ia64_link_hash_table *) (p)->hash : NULL)

static struct elf32_ia64_dyn_sym_info * get_dyn_sym_info
  (struct elf32_ia64_link_hash_table *ia64_info,
   struct elf_link_hash_entry *h,
   bfd *abfd, const Elf_Internal_Rela *rel, bool create);
static bool elf32_ia64_dynamic_symbol_p
  (struct elf_link_hash_entry *h, struct bfd_link_info *info, int);
static bool elf32_ia64_choose_gp
  (bfd *abfd, struct bfd_link_info *info, bool final);
static void elf32_ia64_dyn_sym_traverse
  (struct elf32_ia64_link_hash_table *ia64_info,
   bool (*func) (struct elf32_ia64_dyn_sym_info *, void *),
   void * info);
static bool allocate_global_data_got
  (struct elf32_ia64_dyn_sym_info *dyn_i, void * data);
static bool allocate_global_fptr_got
  (struct elf32_ia64_dyn_sym_info *dyn_i, void * data);
static bool allocate_local_got
  (struct elf32_ia64_dyn_sym_info *dyn_i, void * data);
static bool elf32_ia64_hpux_vec
  (const bfd_target *vec);
static bool allocate_dynrel_entries
  (struct elf32_ia64_dyn_sym_info *dyn_i, void * data);
static asection *get_pltoff
  (bfd *abfd, struct bfd_link_info *info,
   struct elf32_ia64_link_hash_table *ia64_info);

/* ia64-specific relocation.  */

/* Given a ELF reloc, return the matching HOWTO structure.  */

static bool
elf32_ia64_info_to_howto (bfd *abfd ATTRIBUTE_UNUSED,
			  arelent *bfd_reloc,
			  Elf_Internal_Rela *elf_reloc)
{
  unsigned int r_type = ELF32_R_TYPE (elf_reloc->r_info);

  bfd_reloc->howto = ia64_elf_lookup_howto (r_type);
  if (bfd_reloc->howto == NULL)
    {
      /* xgettext:c-format */
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			  abfd, r_type);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  return true;
}

#define PLT_HEADER_SIZE		(3 * 16)
#define PLT_MIN_ENTRY_SIZE	(1 * 16)
#define PLT_FULL_ENTRY_SIZE	(2 * 16)
#define PLT_RESERVED_WORDS	3

static const bfd_byte plt_header[PLT_HEADER_SIZE] =
{
  0x0b, 0x10, 0x00, 0x1c, 0x00, 0x21,  /*   [MMI]	mov r2=r14;;	   */
  0xe0, 0x00, 0x08, 0x00, 0x48, 0x00,  /*		addl r14=0,r2	   */
  0x00, 0x00, 0x04, 0x00,	       /*		nop.i 0x0;;	   */
  0x0b, 0x80, 0x20, 0x1c, 0x18, 0x14,  /*   [MMI]	ld8 r16=[r14],8;;  */
  0x10, 0x41, 0x38, 0x30, 0x28, 0x00,  /*		ld8 r17=[r14],8	   */
  0x00, 0x00, 0x04, 0x00,	       /*		nop.i 0x0;;	   */
  0x11, 0x08, 0x00, 0x1c, 0x18, 0x10,  /*   [MIB]	ld8 r1=[r14]	   */
  0x60, 0x88, 0x04, 0x80, 0x03, 0x00,  /*		mov b6=r17	   */
  0x60, 0x00, 0x80, 0x00	       /*		br.few b6;;	   */
};

static const bfd_byte plt_min_entry[PLT_MIN_ENTRY_SIZE] =
{
  0x11, 0x78, 0x00, 0x00, 0x00, 0x24,  /*   [MIB]	mov r15=0	   */
  0x00, 0x00, 0x00, 0x02, 0x00, 0x00,  /*		nop.i 0x0	   */
  0x00, 0x00, 0x00, 0x40	       /*		br.few 0 <PLT0>;;  */
};

static const bfd_byte plt_full_entry[PLT_FULL_ENTRY_SIZE] =
{
  0x0b, 0x78, 0x00, 0x02, 0x00, 0x24,  /*   [MMI]	addl r15=0,r1;;	   */
  0x00, 0x41, 0x3c, 0x70, 0x29, 0xc0,  /*		ld8.acq r16=[r15],8*/
  0x01, 0x08, 0x00, 0x84,	       /*		mov r14=r1;;	   */
  0x11, 0x08, 0x00, 0x1e, 0x18, 0x10,  /*   [MIB]	ld8 r1=[r15]	   */
  0x60, 0x80, 0x04, 0x80, 0x03, 0x00,  /*		mov b6=r16	   */
  0x60, 0x00, 0x80, 0x00	       /*		br.few b6;;	   */
};

#define ELF_DYNAMIC_INTERPRETER "/usr/lib/ld.so.1"

static const bfd_byte oor_brl[16] =
{
  0x05, 0x00, 0x00, 0x00, 0x01, 0x00,  /*  [MLX]	nop.m 0		   */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /*		brl.sptk.few tgt;; */
  0x00, 0x00, 0x00, 0xc0
};

static const bfd_byte oor_ip[48] =
{
  0x04, 0x00, 0x00, 0x00, 0x01, 0x00,  /*  [MLX]	nop.m 0		   */
  0x00, 0x00, 0x00, 0x00, 0x00, 0xe0,  /*		movl r15=0	   */
  0x01, 0x00, 0x00, 0x60,
  0x03, 0x00, 0x00, 0x00, 0x01, 0x00,  /*  [MII]	nop.m 0		   */
  0x00, 0x01, 0x00, 0x60, 0x00, 0x00,  /*		mov r16=ip;;	   */
  0xf2, 0x80, 0x00, 0x80,	       /*		add r16=r15,r16;;  */
  0x11, 0x00, 0x00, 0x00, 0x01, 0x00,  /*  [MIB]	nop.m 0		   */
  0x60, 0x80, 0x04, 0x80, 0x03, 0x00,  /*		mov b6=r16	   */
  0x60, 0x00, 0x80, 0x00	       /*		br b6;;		   */
};

static size_t oor_branch_size = sizeof (oor_brl);

void
bfd_elf32_ia64_after_parse (int itanium)
{
  oor_branch_size = itanium ? sizeof (oor_ip) : sizeof (oor_brl);
}


/* Rename some of the generic section flags to better document how they
   are used here.  */
#define skip_relax_pass_0 sec_flg0
#define skip_relax_pass_1 sec_flg1

/* These functions do relaxation for IA-64 ELF.  */

static void
elf32_ia64_update_short_info (asection *sec, bfd_vma offset,
			      struct elf32_ia64_link_hash_table *ia64_info)
{
  /* Skip ABS and SHF_IA_64_SHORT sections.  */
  if (sec == bfd_abs_section_ptr
      || (sec->flags & SEC_SMALL_DATA) != 0)
    return;

  if (!ia64_info->min_short_sec)
    {
      ia64_info->max_short_sec = sec;
      ia64_info->max_short_offset = offset;
      ia64_info->min_short_sec = sec;
      ia64_info->min_short_offset = offset;
    }
  else if (sec == ia64_info->max_short_sec
	   && offset > ia64_info->max_short_offset)
    ia64_info->max_short_offset = offset;
  else if (sec == ia64_info->min_short_sec
	   && offset < ia64_info->min_short_offset)
    ia64_info->min_short_offset = offset;
  else if (sec->output_section->vma
	   > ia64_info->max_short_sec->vma)
    {
      ia64_info->max_short_sec = sec;
      ia64_info->max_short_offset = offset;
    }
  else if (sec->output_section->vma
	   < ia64_info->min_short_sec->vma)
    {
      ia64_info->min_short_sec = sec;
      ia64_info->min_short_offset = offset;
    }
}

static bool
elf32_ia64_relax_section (bfd *abfd, asection *sec,
			  struct bfd_link_info *link_info,
			  bool *again)
{
  struct one_fixup
    {
      struct one_fixup *next;
      asection *tsec;
      bfd_vma toff;
      bfd_vma trampoff;
    };

  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Rela *internal_relocs;
  Elf_Internal_Rela *irel, *irelend;
  bfd_byte *contents;
  Elf_Internal_Sym *isymbuf = NULL;
  struct elf32_ia64_link_hash_table *ia64_info;
  struct one_fixup *fixups = NULL;
  bool changed_contents = false;
  bool changed_relocs = false;
  bool changed_got = false;
  bool skip_relax_pass_0 = true;
  bool skip_relax_pass_1 = true;
  bfd_vma gp = 0;

  /* Assume we're not going to change any sizes, and we'll only need
     one pass.  */
  *again = false;

  if (bfd_link_relocatable (link_info))
    link_info->callbacks->fatal
      (_("%P: --relax and -r may not be used together\n"));

  /* Don't even try to relax for non-ELF outputs.  */
  if (!is_elf_hash_table (link_info->hash))
    return false;

  /* Nothing to do if there are no relocations or there is no need for
     the current pass.  */
  if (sec->reloc_count == 0
      || (sec->flags & SEC_RELOC) == 0
      || (sec->flags & SEC_HAS_CONTENTS) == 0
      || (link_info->relax_pass == 0 && sec->skip_relax_pass_0)
      || (link_info->relax_pass == 1 && sec->skip_relax_pass_1))
    return true;

  ia64_info = elf32_ia64_hash_table (link_info);
  if (ia64_info == NULL)
    return false;

  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;

  /* Load the relocations for this section.  */
  internal_relocs = (_bfd_elf_link_read_relocs
		     (abfd, sec, NULL, (Elf_Internal_Rela *) NULL,
		      link_info->keep_memory));
  if (internal_relocs == NULL)
    return false;

  irelend = internal_relocs + sec->reloc_count;

  /* Get the section contents.  */
  if (elf_section_data (sec)->this_hdr.contents != NULL)
    contents = elf_section_data (sec)->this_hdr.contents;
  else
    {
      if (!bfd_malloc_and_get_section (abfd, sec, &contents))
	goto error_return;
    }

  for (irel = internal_relocs; irel < irelend; irel++)
    {
      unsigned long r_type = ELF32_R_TYPE (irel->r_info);
      bfd_vma symaddr, reladdr, trampoff, toff, roff;
      asection *tsec;
      struct one_fixup *f;
      bfd_size_type amt;
      bool is_branch;
      struct elf32_ia64_dyn_sym_info *dyn_i;
      char symtype;

      switch (r_type)
	{
	case R_IA64_PCREL21B:
	case R_IA64_PCREL21BI:
	case R_IA64_PCREL21M:
	case R_IA64_PCREL21F:
	  /* In pass 1, all br relaxations are done. We can skip it. */
	  if (link_info->relax_pass == 1)
	    continue;
	  skip_relax_pass_0 = false;
	  is_branch = true;
	  break;

	case R_IA64_PCREL60B:
	  /* We can't optimize brl to br in pass 0 since br relaxations
	     will increase the code size. Defer it to pass 1.  */
	  if (link_info->relax_pass == 0)
	    {
	      skip_relax_pass_1 = false;
	      continue;
	    }
	  is_branch = true;
	  break;

	case R_IA64_GPREL22:
	  /* Update max_short_sec/min_short_sec.  */

	case R_IA64_LTOFF22X:
	case R_IA64_LDXMOV:
	  /* We can't relax ldx/mov in pass 0 since br relaxations will
	     increase the code size. Defer it to pass 1.  */
	  if (link_info->relax_pass == 0)
	    {
	      skip_relax_pass_1 = false;
	      continue;
	    }
	  is_branch = false;
	  break;

	default:
	  continue;
	}

      /* Get the value of the symbol referred to by the reloc.  */
      if (ELF32_R_SYM (irel->r_info) < symtab_hdr->sh_info)
	{
	  /* A local symbol.  */
	  Elf_Internal_Sym *isym;

	  /* Read this BFD's local symbols.  */
	  if (isymbuf == NULL)
	    {
	      isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
	      if (isymbuf == NULL)
		isymbuf = bfd_elf_get_elf_syms (abfd, symtab_hdr,
						symtab_hdr->sh_info, 0,
						NULL, NULL, NULL);
	      if (isymbuf == 0)
		goto error_return;
	    }

	  isym = isymbuf + ELF32_R_SYM (irel->r_info);
	  if (isym->st_shndx == SHN_UNDEF)
	    continue;	/* We can't do anything with undefined symbols.  */
	  else if (isym->st_shndx == SHN_ABS)
	    tsec = bfd_abs_section_ptr;
	  else if (isym->st_shndx == SHN_COMMON)
	    tsec = bfd_com_section_ptr;
	  else if (isym->st_shndx == SHN_IA_64_ANSI_COMMON)
	    tsec = bfd_com_section_ptr;
	  else
	    tsec = bfd_section_from_elf_index (abfd, isym->st_shndx);

	  toff = isym->st_value;
	  dyn_i = get_dyn_sym_info (ia64_info, NULL, abfd, irel, false);
	  symtype = ELF_ST_TYPE (isym->st_info);
	}
      else
	{
	  unsigned long indx;
	  struct elf_link_hash_entry *h;

	  indx = ELF32_R_SYM (irel->r_info) - symtab_hdr->sh_info;
	  h = elf_sym_hashes (abfd)[indx];
	  BFD_ASSERT (h != NULL);

	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;

	  dyn_i = get_dyn_sym_info (ia64_info, h, abfd, irel, false);

	  /* For branches to dynamic symbols, we're interested instead
	     in a branch to the PLT entry.  */
	  if (is_branch && dyn_i && dyn_i->want_plt2)
	    {
	      /* Internal branches shouldn't be sent to the PLT.
		 Leave this for now and we'll give an error later.  */
	      if (r_type != R_IA64_PCREL21B)
		continue;

	      tsec = ia64_info->root.splt;
	      toff = dyn_i->plt2_offset;
	      BFD_ASSERT (irel->r_addend == 0);
	    }

	  /* Can't do anything else with dynamic symbols.  */
	  else if (elf32_ia64_dynamic_symbol_p (h, link_info, r_type))
	    continue;

	  else
	    {
	      /* We can't do anything with undefined symbols.  */
	      if (h->root.type == bfd_link_hash_undefined
		  || h->root.type == bfd_link_hash_undefweak)
		continue;

	      tsec = h->root.u.def.section;
	      toff = h->root.u.def.value;
	    }

	  symtype = h->type;
	}

      if (tsec->sec_info_type == SEC_INFO_TYPE_MERGE)
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
	     toff += irel->r_addend;

	   toff = _bfd_merged_section_offset (abfd, &tsec,
					      elf_section_data (tsec)->sec_info,
					      toff);

	   if (symtype != STT_SECTION)
	     toff += irel->r_addend;
	}
      else
	toff += irel->r_addend;

      symaddr = tsec->output_section->vma + tsec->output_offset + toff;

      roff = irel->r_offset;

      if (is_branch)
	{
	  bfd_signed_vma offset;

	  reladdr = (sec->output_section->vma
		     + sec->output_offset
		     + roff) & (bfd_vma) -4;

	  /* The .plt section is aligned at 32byte and the .text section
	     is aligned at 64byte. The .text section is right after the
	     .plt section.  After the first relaxation pass, linker may
	     increase the gap between the .plt and .text sections up
	     to 32byte.  We assume linker will always insert 32byte
	     between the .plt and .text sections after the first
	     relaxation pass.  */
	  if (tsec == ia64_info->root.splt)
	    offset = -0x1000000 + 32;
	  else
	    offset = -0x1000000;

	  /* If the branch is in range, no need to do anything.  */
	  if ((bfd_signed_vma) (symaddr - reladdr) >= offset
	      && (bfd_signed_vma) (symaddr - reladdr) <= 0x0FFFFF0)
	    {
	      /* If the 60-bit branch is in 21-bit range, optimize it. */
	      if (r_type == R_IA64_PCREL60B)
		{
		  ia64_elf_relax_brl (contents, roff);

		  irel->r_info
		    = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
				    R_IA64_PCREL21B);

		  /* If the original relocation offset points to slot
		     1, change it to slot 2.  */
		  if ((irel->r_offset & 3) == 1)
		    irel->r_offset += 1;

		  changed_contents = true;
		  changed_relocs = true;
		}

	      continue;
	    }
	  else if (r_type == R_IA64_PCREL60B)
	    continue;
	  else if (ia64_elf_relax_br (contents, roff))
	    {
	      irel->r_info
		= ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
				R_IA64_PCREL60B);

	      /* Make the relocation offset point to slot 1.  */
	      irel->r_offset = (irel->r_offset & ~((bfd_vma) 0x3)) + 1;

	      changed_contents = true;
	      changed_relocs = true;
	      continue;
	    }

	  /* We can't put a trampoline in a .init/.fini section. Issue
	     an error.  */
	  if (strcmp (sec->output_section->name, ".init") == 0
	      || strcmp (sec->output_section->name, ".fini") == 0)
	    {
	      _bfd_error_handler
		/* xgettext:c-format */
		(_("%pB: can't relax br at %#" PRIx64 " in section `%pA';"
		   " please use brl or indirect branch"),
		 sec->owner, (uint64_t) roff, sec);
	      bfd_set_error (bfd_error_bad_value);
	      goto error_return;
	    }

	  /* If the branch and target are in the same section, you've
	     got one honking big section and we can't help you unless
	     you are branching backwards.  You'll get an error message
	     later.  */
	  if (tsec == sec && toff > roff)
	    continue;

	  /* Look for an existing fixup to this address.  */
	  for (f = fixups; f ; f = f->next)
	    if (f->tsec == tsec && f->toff == toff)
	      break;

	  if (f == NULL)
	    {
	      /* Two alternatives: If it's a branch to a PLT entry, we can
		 make a copy of the FULL_PLT entry.  Otherwise, we'll have
		 to use a `brl' insn to get where we're going.  */

	      size_t size;

	      if (tsec == ia64_info->root.splt)
		size = sizeof (plt_full_entry);
	      else
		size = oor_branch_size;

	      /* Resize the current section to make room for the new branch. */
	      trampoff = (sec->size + 15) & (bfd_vma) -16;

	      /* If trampoline is out of range, there is nothing we
		 can do.  */
	      offset = trampoff - (roff & (bfd_vma) -4);
	      if (offset < -0x1000000 || offset > 0x0FFFFF0)
		continue;

	      amt = trampoff + size;
	      contents = (bfd_byte *) bfd_realloc (contents, amt);
	      if (contents == NULL)
		goto error_return;
	      sec->size = amt;

	      if (tsec == ia64_info->root.splt)
		{
		  memcpy (contents + trampoff, plt_full_entry, size);

		  /* Hijack the old relocation for use as the PLTOFF reloc.  */
		  irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
					       R_IA64_PLTOFF22);
		  irel->r_offset = trampoff;
		}
	      else
		{
		  if (size == sizeof (oor_ip))
		    {
		      memcpy (contents + trampoff, oor_ip, size);
		      irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
						   R_IA64_PCREL64I);
		      irel->r_addend -= 16;
		      irel->r_offset = trampoff + 2;
		    }
		  else
		    {
		      memcpy (contents + trampoff, oor_brl, size);
		      irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
						   R_IA64_PCREL60B);
		      irel->r_offset = trampoff + 2;
		    }

		}

	      /* Record the fixup so we don't do it again this section.  */
	      f = (struct one_fixup *)
		bfd_malloc ((bfd_size_type) sizeof (*f));
	      f->next = fixups;
	      f->tsec = tsec;
	      f->toff = toff;
	      f->trampoff = trampoff;
	      fixups = f;
	    }
	  else
	    {
	      /* If trampoline is out of range, there is nothing we
		 can do.  */
	      offset = f->trampoff - (roff & (bfd_vma) -4);
	      if (offset < -0x1000000 || offset > 0x0FFFFF0)
		continue;

	      /* Nop out the reloc, since we're finalizing things here.  */
	      irel->r_info = ELF32_R_INFO (0, R_IA64_NONE);
	    }

	  /* Fix up the existing branch to hit the trampoline.  */
	  if (ia64_elf_install_value (contents + roff, offset, r_type)
	      != bfd_reloc_ok)
	    goto error_return;

	  changed_contents = true;
	  changed_relocs = true;
	}
      else
	{
	  /* Fetch the gp.  */
	  if (gp == 0)
	    {
	      bfd *obfd = sec->output_section->owner;
	      gp = _bfd_get_gp_value (obfd);
	      if (gp == 0)
		{
		  if (!elf32_ia64_choose_gp (obfd, link_info, false))
		    goto error_return;
		  gp = _bfd_get_gp_value (obfd);
		}
	    }

	  /* If the data is out of range, do nothing.  */
	  if ((bfd_signed_vma) (symaddr - gp) >= 0x200000
	      ||(bfd_signed_vma) (symaddr - gp) < -0x200000)
	    continue;

	  if (r_type == R_IA64_GPREL22)
	    elf32_ia64_update_short_info (tsec->output_section,
					  tsec->output_offset + toff,
					  ia64_info);
	  else if (r_type == R_IA64_LTOFF22X)
	    {
	      irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
					   R_IA64_GPREL22);
	      changed_relocs = true;
	      if (dyn_i->want_gotx)
		{
		  dyn_i->want_gotx = 0;
		  changed_got |= !dyn_i->want_got;
		}

	      elf32_ia64_update_short_info (tsec->output_section,
					    tsec->output_offset + toff,
					    ia64_info);
	    }
	  else
	    {
	      ia64_elf_relax_ldxmov (contents, roff);
	      irel->r_info = ELF32_R_INFO (0, R_IA64_NONE);
	      changed_contents = true;
	      changed_relocs = true;
	    }
	}
    }

  /* ??? If we created fixups, this may push the code segment large
     enough that the data segment moves, which will change the GP.
     Reset the GP so that we re-calculate next round.  We need to
     do this at the _beginning_ of the next round; now will not do.  */

  /* Clean up and go home.  */
  while (fixups)
    {
      struct one_fixup *f = fixups;
      fixups = fixups->next;
      free (f);
    }

  if (isymbuf != NULL
      && symtab_hdr->contents != (unsigned char *) isymbuf)
    {
      if (! link_info->keep_memory)
	free (isymbuf);
      else
	{
	  /* Cache the symbols for elf_link_input_bfd.  */
	  symtab_hdr->contents = (unsigned char *) isymbuf;
	}
    }

  if (contents != NULL
      && elf_section_data (sec)->this_hdr.contents != contents)
    {
      if (!changed_contents && !link_info->keep_memory)
	free (contents);
      else
	{
	  /* Cache the section contents for elf_link_input_bfd.  */
	  elf_section_data (sec)->this_hdr.contents = contents;
	}
    }

  if (elf_section_data (sec)->relocs != internal_relocs)
    {
      if (!changed_relocs)
	free (internal_relocs);
      else
	elf_section_data (sec)->relocs = internal_relocs;
    }

  if (changed_got)
    {
      struct elf32_ia64_allocate_data data;
      data.info = link_info;
      data.ofs = 0;
      ia64_info->self_dtpmod_offset = (bfd_vma) -1;

      elf32_ia64_dyn_sym_traverse (ia64_info, allocate_global_data_got, &data);
      elf32_ia64_dyn_sym_traverse (ia64_info, allocate_global_fptr_got, &data);
      elf32_ia64_dyn_sym_traverse (ia64_info, allocate_local_got, &data);
      ia64_info->root.sgot->size = data.ofs;

      if (ia64_info->root.dynamic_sections_created
	  && ia64_info->root.srelgot != NULL)
	{
	  /* Resize .rela.got.  */
	  ia64_info->root.srelgot->size = 0;
	  if (bfd_link_pic (link_info)
	      && ia64_info->self_dtpmod_offset != (bfd_vma) -1)
	    ia64_info->root.srelgot->size += sizeof (Elf32_External_Rela);
	  data.only_got = true;
	  elf32_ia64_dyn_sym_traverse (ia64_info, allocate_dynrel_entries,
				       &data);
	}
    }

  if (link_info->relax_pass == 0)
    {
      /* Pass 0 is only needed to relax br.  */
      sec->skip_relax_pass_0 = skip_relax_pass_0;
      sec->skip_relax_pass_1 = skip_relax_pass_1;
    }

  *again = changed_contents || changed_relocs;
  return true;

 error_return:
  if ((unsigned char *) isymbuf != symtab_hdr->contents)
    free (isymbuf);
  if (elf_section_data (sec)->this_hdr.contents != contents)
    free (contents);
  if (elf_section_data (sec)->relocs != internal_relocs)
    free (internal_relocs);
  return false;
}
#undef skip_relax_pass_0
#undef skip_relax_pass_1

/* Return TRUE if NAME is an unwind table section name.  */

static inline bool
is_unwind_section_name (bfd *abfd, const char *name)
{
  if (elf32_ia64_hpux_vec (abfd->xvec)
      && !strcmp (name, ELF_STRING_ia64_unwind_hdr))
    return false;

  return ((startswith (name, ELF_STRING_ia64_unwind)
	   && ! startswith (name, ELF_STRING_ia64_unwind_info))
	  || startswith (name, ELF_STRING_ia64_unwind_once));
}

/* Handle an IA-64 specific section when reading an object file.  This
   is called when bfd_section_from_shdr finds a section with an unknown
   type.  */

static bool
elf32_ia64_section_from_shdr (bfd *abfd,
			      Elf_Internal_Shdr *hdr,
			      const char *name,
			      int shindex)
{
  /* There ought to be a place to keep ELF backend specific flags, but
     at the moment there isn't one.  We just keep track of the
     sections by their name, instead.  Fortunately, the ABI gives
     suggested names for all the MIPS specific sections, so we will
     probably get away with this.  */
  switch (hdr->sh_type)
    {
    case SHT_IA_64_UNWIND:
    case SHT_IA_64_HP_OPT_ANOT:
      break;

    case SHT_IA_64_EXT:
      if (strcmp (name, ELF_STRING_ia64_archext) != 0)
	return false;
      break;

    default:
      return false;
    }

  if (! _bfd_elf_make_section_from_shdr (abfd, hdr, name, shindex))
    return false;

  return true;
}

/* Convert IA-64 specific section flags to bfd internal section flags.  */

/* ??? There is no bfd internal flag equivalent to the SHF_IA_64_NORECOV
   flag.  */

static bool
elf32_ia64_section_flags (const Elf_Internal_Shdr *hdr)
{
  if (hdr->sh_flags & SHF_IA_64_SHORT)
    hdr->bfd_section->flags |= SEC_SMALL_DATA;

  return true;
}

/* Set the correct type for an IA-64 ELF section.  We do this by the
   section name, which is a hack, but ought to work.  */

static bool
elf32_ia64_fake_sections (bfd *abfd, Elf_Internal_Shdr *hdr,
			  asection *sec)
{
  const char *name;

  name = bfd_section_name (sec);

  if (is_unwind_section_name (abfd, name))
    {
      /* We don't have the sections numbered at this point, so sh_info
	 is set later, in elf32_ia64_final_write_processing.  */
      hdr->sh_type = SHT_IA_64_UNWIND;
      hdr->sh_flags |= SHF_LINK_ORDER;
    }
  else if (strcmp (name, ELF_STRING_ia64_archext) == 0)
    hdr->sh_type = SHT_IA_64_EXT;
  else if (strcmp (name, ".HP.opt_annot") == 0)
    hdr->sh_type = SHT_IA_64_HP_OPT_ANOT;
  else if (strcmp (name, ".reloc") == 0)
    /* This is an ugly, but unfortunately necessary hack that is
       needed when producing EFI binaries on IA-64. It tells
       elf.c:elf_fake_sections() not to consider ".reloc" as a section
       containing ELF relocation info.  We need this hack in order to
       be able to generate ELF binaries that can be translated into
       EFI applications (which are essentially COFF objects).  Those
       files contain a COFF ".reloc" section inside an ELF32 object,
       which would normally cause BFD to segfault because it would
       attempt to interpret this section as containing relocation
       entries for section "oc".  With this hack enabled, ".reloc"
       will be treated as a normal data section, which will avoid the
       segfault.  However, you won't be able to create an ELF32 binary
       with a section named "oc" that needs relocations, but that's
       the kind of ugly side-effects you get when detecting section
       types based on their names...  In practice, this limitation is
       unlikely to bite.  */
    hdr->sh_type = SHT_PROGBITS;

  if (sec->flags & SEC_SMALL_DATA)
    hdr->sh_flags |= SHF_IA_64_SHORT;

  /* Some HP linkers look for the SHF_IA_64_HP_TLS flag instead of SHF_TLS. */

  if (elf32_ia64_hpux_vec (abfd->xvec) && (sec->flags & SHF_TLS))
    hdr->sh_flags |= SHF_IA_64_HP_TLS;

  return true;
}

/* The final processing done just before writing out an IA-64 ELF
   object file.  */

static bool
elf32_ia64_final_write_processing (bfd *abfd)
{
  Elf_Internal_Shdr *hdr;
  asection *s;

  for (s = abfd->sections; s; s = s->next)
    {
      hdr = &elf_section_data (s)->this_hdr;
      switch (hdr->sh_type)
	{
	case SHT_IA_64_UNWIND:
	  /* The IA-64 processor-specific ABI requires setting sh_link
	     to the unwind section, whereas HP-UX requires sh_info to
	     do so.  For maximum compatibility, we'll set both for
	     now... */
	  hdr->sh_info = hdr->sh_link;
	  break;
	}
    }

  if (! elf_flags_init (abfd))
    {
      unsigned long flags = 0;

      if (abfd->xvec->byteorder == BFD_ENDIAN_BIG)
	flags |= EF_IA_64_BE;
      if (bfd_get_mach (abfd) == bfd_mach_ia64_elf64)
	flags |= EF_IA_64_ABI64;

      elf_elfheader(abfd)->e_flags = flags;
      elf_flags_init (abfd) = true;
    }
  return _bfd_elf_final_write_processing (abfd);
}

/* Hook called by the linker routine which adds symbols from an object
   file.  We use it to put .comm items in .sbss, and not .bss.  */

static bool
elf32_ia64_add_symbol_hook (bfd *abfd,
			    struct bfd_link_info *info,
			    Elf_Internal_Sym *sym,
			    const char **namep ATTRIBUTE_UNUSED,
			    flagword *flagsp ATTRIBUTE_UNUSED,
			    asection **secp,
			    bfd_vma *valp)
{
  if (sym->st_shndx == SHN_COMMON
      && !bfd_link_relocatable (info)
      && sym->st_size <= elf_gp_size (abfd))
    {
      /* Common symbols less than or equal to -G nn bytes are
	 automatically put into .sbss.  */

      asection *scomm = bfd_get_section_by_name (abfd, ".scommon");

      if (scomm == NULL)
	{
	  scomm = bfd_make_section_with_flags (abfd, ".scommon",
					       (SEC_ALLOC
						| SEC_IS_COMMON
						| SEC_SMALL_DATA
						| SEC_LINKER_CREATED));
	  if (scomm == NULL)
	    return false;
	}

      *secp = scomm;
      *valp = sym->st_size;
    }

  return true;
}

/* Return the number of additional phdrs we will need.  */

static int
elf32_ia64_additional_program_headers (bfd *abfd,
				       struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  asection *s;
  int ret = 0;

  /* See if we need a PT_IA_64_ARCHEXT segment.  */
  s = bfd_get_section_by_name (abfd, ELF_STRING_ia64_archext);
  if (s && (s->flags & SEC_LOAD))
    ++ret;

  /* Count how many PT_IA_64_UNWIND segments we need.  */
  for (s = abfd->sections; s; s = s->next)
    if (is_unwind_section_name (abfd, s->name) && (s->flags & SEC_LOAD))
      ++ret;

  return ret;
}

static bool
elf32_ia64_modify_segment_map (bfd *abfd,
			       struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  struct elf_segment_map *m, **pm;
  Elf_Internal_Shdr *hdr;
  asection *s;

  /* If we need a PT_IA_64_ARCHEXT segment, it must come before
     all PT_LOAD segments.  */
  s = bfd_get_section_by_name (abfd, ELF_STRING_ia64_archext);
  if (s && (s->flags & SEC_LOAD))
    {
      for (m = elf_seg_map (abfd); m != NULL; m = m->next)
	if (m->p_type == PT_IA_64_ARCHEXT)
	  break;
      if (m == NULL)
	{
	  m = ((struct elf_segment_map *)
	       bfd_zalloc (abfd, (bfd_size_type) sizeof *m));
	  if (m == NULL)
	    return false;

	  m->p_type = PT_IA_64_ARCHEXT;
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

  /* Install PT_IA_64_UNWIND segments, if needed.  */
  for (s = abfd->sections; s; s = s->next)
    {
      hdr = &elf_section_data (s)->this_hdr;
      if (hdr->sh_type != SHT_IA_64_UNWIND)
	continue;

      if (s && (s->flags & SEC_LOAD))
	{
	  for (m = elf_seg_map (abfd); m != NULL; m = m->next)
	    if (m->p_type == PT_IA_64_UNWIND)
	      {
		int i;

		/* Look through all sections in the unwind segment
		   for a match since there may be multiple sections
		   to a segment.  */
		for (i = m->count - 1; i >= 0; --i)
		  if (m->sections[i] == s)
		    break;

		if (i >= 0)
		  break;
	      }

	  if (m == NULL)
	    {
	      m = ((struct elf_segment_map *)
		   bfd_zalloc (abfd, (bfd_size_type) sizeof *m));
	      if (m == NULL)
		return false;

	      m->p_type = PT_IA_64_UNWIND;
	      m->count = 1;
	      m->sections[0] = s;
	      m->next = NULL;

	      /* We want to put it last.  */
	      pm = &elf_seg_map (abfd);
	      while (*pm != NULL)
		pm = &(*pm)->next;
	      *pm = m;
	    }
	}
    }

  return true;
}

/* Turn on PF_IA_64_NORECOV if needed.  This involves traversing all of
   the input sections for each output section in the segment and testing
   for SHF_IA_64_NORECOV on each.  */

static bool
elf32_ia64_modify_headers (bfd *abfd, struct bfd_link_info *info)
{
  struct elf_obj_tdata *tdata = elf_tdata (abfd);
  struct elf_segment_map *m;
  Elf_Internal_Phdr *p;

  for (p = tdata->phdr, m = elf_seg_map (abfd); m != NULL; m = m->next, p++)
    if (m->p_type == PT_LOAD)
      {
	int i;
	for (i = m->count - 1; i >= 0; --i)
	  {
	    struct bfd_link_order *order = m->sections[i]->map_head.link_order;

	    while (order != NULL)
	      {
		if (order->type == bfd_indirect_link_order)
		  {
		    asection *is = order->u.indirect.section;
		    bfd_vma flags = elf_section_data(is)->this_hdr.sh_flags;
		    if (flags & SHF_IA_64_NORECOV)
		      {
			p->p_flags |= PF_IA_64_NORECOV;
			goto found;
		      }
		  }
		order = order->next;
	      }
	  }
      found:;
      }

  return _bfd_elf_modify_headers (abfd, info);
}

/* According to the Tahoe assembler spec, all labels starting with a
   '.' are local.  */

static bool
elf32_ia64_is_local_label_name (bfd *abfd ATTRIBUTE_UNUSED,
				const char *name)
{
  return name[0] == '.';
}

/* Should we do dynamic things to this symbol?  */

static bool
elf32_ia64_dynamic_symbol_p (struct elf_link_hash_entry *h,
			     struct bfd_link_info *info, int r_type)
{
  bool ignore_protected
    = ((r_type & 0xf8) == 0x40		/* FPTR relocs */
       || (r_type & 0xf8) == 0x50);	/* LTOFF_FPTR relocs */

  return _bfd_elf_dynamic_symbol_p (h, info, ignore_protected);
}

static struct bfd_hash_entry*
elf32_ia64_new_elf_hash_entry (struct bfd_hash_entry *entry,
			       struct bfd_hash_table *table,
			       const char *string)
{
  struct elf32_ia64_link_hash_entry *ret;
  ret = (struct elf32_ia64_link_hash_entry *) entry;

  /* Allocate the structure if it has not already been allocated by a
     subclass.  */
  if (!ret)
    ret = bfd_hash_allocate (table, sizeof (*ret));

  if (!ret)
    return 0;

  /* Call the allocation method of the superclass.  */
  ret = ((struct elf32_ia64_link_hash_entry *)
	 _bfd_elf_link_hash_newfunc ((struct bfd_hash_entry *) ret,
				     table, string));

  ret->info = NULL;
  ret->count = 0;
  ret->sorted_count = 0;
  ret->size = 0;
  return (struct bfd_hash_entry *) ret;
}

static void
elf32_ia64_hash_copy_indirect (struct bfd_link_info *info,
			       struct elf_link_hash_entry *xdir,
			       struct elf_link_hash_entry *xind)
{
  struct elf32_ia64_link_hash_entry *dir, *ind;

  dir = (struct elf32_ia64_link_hash_entry *) xdir;
  ind = (struct elf32_ia64_link_hash_entry *) xind;

  /* Copy down any references that we may have already seen to the
     symbol which just became indirect.  */

  if (dir->root.versioned != versioned_hidden)
    dir->root.ref_dynamic |= ind->root.ref_dynamic;
  dir->root.ref_regular |= ind->root.ref_regular;
  dir->root.ref_regular_nonweak |= ind->root.ref_regular_nonweak;
  dir->root.needs_plt |= ind->root.needs_plt;

  if (ind->root.root.type != bfd_link_hash_indirect)
    return;

  /* Copy over the got and plt data.  This would have been done
     by check_relocs.  */

  if (ind->info != NULL)
    {
      struct elf32_ia64_dyn_sym_info *dyn_i;
      unsigned int count;

      free (dir->info);

      dir->info = ind->info;
      dir->count = ind->count;
      dir->sorted_count = ind->sorted_count;
      dir->size = ind->size;

      ind->info = NULL;
      ind->count = 0;
      ind->sorted_count = 0;
      ind->size = 0;

      /* Fix up the dyn_sym_info pointers to the global symbol.  */
      for (count = dir->count, dyn_i = dir->info;
	   count != 0;
	   count--, dyn_i++)
	dyn_i->h = &dir->root;
    }

  /* Copy over the dynindx.  */

  if (ind->root.dynindx != -1)
    {
      if (dir->root.dynindx != -1)
	_bfd_elf_strtab_delref (elf_hash_table (info)->dynstr,
				dir->root.dynstr_index);
      dir->root.dynindx = ind->root.dynindx;
      dir->root.dynstr_index = ind->root.dynstr_index;
      ind->root.dynindx = -1;
      ind->root.dynstr_index = 0;
    }
}

static void
elf32_ia64_hash_hide_symbol (struct bfd_link_info *info,
			     struct elf_link_hash_entry *xh,
			     bool force_local)
{
  struct elf32_ia64_link_hash_entry *h;
  struct elf32_ia64_dyn_sym_info *dyn_i;
  unsigned int count;

  h = (struct elf32_ia64_link_hash_entry *)xh;

  _bfd_elf_link_hash_hide_symbol (info, &h->root, force_local);

  for (count = h->count, dyn_i = h->info;
       count != 0;
       count--, dyn_i++)
    {
      dyn_i->want_plt2 = 0;
      dyn_i->want_plt = 0;
    }
}

/* Compute a hash of a local hash entry.  */

static hashval_t
elf32_ia64_local_htab_hash (const void *ptr)
{
  struct elf32_ia64_local_hash_entry *entry
    = (struct elf32_ia64_local_hash_entry *) ptr;

  return ELF_LOCAL_SYMBOL_HASH (entry->id, entry->r_sym);
}

/* Compare local hash entries.  */

static int
elf32_ia64_local_htab_eq (const void *ptr1, const void *ptr2)
{
  struct elf32_ia64_local_hash_entry *entry1
    = (struct elf32_ia64_local_hash_entry *) ptr1;
  struct elf32_ia64_local_hash_entry *entry2
    = (struct elf32_ia64_local_hash_entry *) ptr2;

  return entry1->id == entry2->id && entry1->r_sym == entry2->r_sym;
}

/* Free the global elf32_ia64_dyn_sym_info array.  */

static bool
elf32_ia64_global_dyn_info_free (struct elf_link_hash_entry *xentry,
				 void *unused ATTRIBUTE_UNUSED)
{
  struct elf32_ia64_link_hash_entry *entry
    = (struct elf32_ia64_link_hash_entry *) xentry;

  free (entry->info);
  entry->info = NULL;
  entry->count = 0;
  entry->sorted_count = 0;
  entry->size = 0;

  return true;
}

/* Free the local elf32_ia64_dyn_sym_info array.  */

static int
elf32_ia64_local_dyn_info_free (void **slot,
				void * unused ATTRIBUTE_UNUSED)
{
  struct elf32_ia64_local_hash_entry *entry
    = (struct elf32_ia64_local_hash_entry *) *slot;

  free (entry->info);
  entry->info = NULL;
  entry->count = 0;
  entry->sorted_count = 0;
  entry->size = 0;

  return true;
}

/* Destroy IA-64 linker hash table.  */

static void
elf32_ia64_link_hash_table_free (bfd *obfd)
{
  struct elf32_ia64_link_hash_table *ia64_info
    = (struct elf32_ia64_link_hash_table *) obfd->link.hash;
  if (ia64_info->loc_hash_table)
    {
      htab_traverse (ia64_info->loc_hash_table,
		     elf32_ia64_local_dyn_info_free, NULL);
      htab_delete (ia64_info->loc_hash_table);
    }
  if (ia64_info->loc_hash_memory)
    objalloc_free ((struct objalloc *) ia64_info->loc_hash_memory);
  elf_link_hash_traverse (&ia64_info->root,
			  elf32_ia64_global_dyn_info_free, NULL);
  _bfd_elf_link_hash_table_free (obfd);
}

/* Create the derived linker hash table.  The IA-64 ELF port uses this
   derived hash table to keep information specific to the IA-64 ElF
   linker (without using static variables).  */

static struct bfd_link_hash_table *
elf32_ia64_hash_table_create (bfd *abfd)
{
  struct elf32_ia64_link_hash_table *ret;

  ret = bfd_zmalloc ((bfd_size_type) sizeof (*ret));
  if (!ret)
    return NULL;

  if (!_bfd_elf_link_hash_table_init (&ret->root, abfd,
				      elf32_ia64_new_elf_hash_entry,
				      sizeof (struct elf32_ia64_link_hash_entry)))
    {
      free (ret);
      return NULL;
    }

  ret->loc_hash_table = htab_try_create (1024, elf32_ia64_local_htab_hash,
					 elf32_ia64_local_htab_eq, NULL);
  ret->loc_hash_memory = objalloc_create ();
  if (!ret->loc_hash_table || !ret->loc_hash_memory)
    {
      elf32_ia64_link_hash_table_free (abfd);
      return NULL;
    }
  ret->root.root.hash_table_free = elf32_ia64_link_hash_table_free;
  ret->root.dt_pltgot_required = true;

  return &ret->root.root;
}

/* Traverse both local and global hash tables.  */

struct elf32_ia64_dyn_sym_traverse_data
{
  bool (*func) (struct elf32_ia64_dyn_sym_info *, void *);
  void * data;
};

static bool
elf32_ia64_global_dyn_sym_thunk (struct elf_link_hash_entry *xentry,
				 void * xdata)
{
  struct elf32_ia64_link_hash_entry *entry
    = (struct elf32_ia64_link_hash_entry *) xentry;
  struct elf32_ia64_dyn_sym_traverse_data *data
    = (struct elf32_ia64_dyn_sym_traverse_data *) xdata;
  struct elf32_ia64_dyn_sym_info *dyn_i;
  unsigned int count;

  for (count = entry->count, dyn_i = entry->info;
       count != 0;
       count--, dyn_i++)
    if (! (*data->func) (dyn_i, data->data))
      return false;
  return true;
}

static int
elf32_ia64_local_dyn_sym_thunk (void **slot, void * xdata)
{
  struct elf32_ia64_local_hash_entry *entry
    = (struct elf32_ia64_local_hash_entry *) *slot;
  struct elf32_ia64_dyn_sym_traverse_data *data
    = (struct elf32_ia64_dyn_sym_traverse_data *) xdata;
  struct elf32_ia64_dyn_sym_info *dyn_i;
  unsigned int count;

  for (count = entry->count, dyn_i = entry->info;
       count != 0;
       count--, dyn_i++)
    if (! (*data->func) (dyn_i, data->data))
      return false;
  return true;
}

static void
elf32_ia64_dyn_sym_traverse (struct elf32_ia64_link_hash_table *ia64_info,
			     bool (*func) (struct elf32_ia64_dyn_sym_info *,
					   void *),
			     void * data)
{
  struct elf32_ia64_dyn_sym_traverse_data xdata;

  xdata.func = func;
  xdata.data = data;

  elf_link_hash_traverse (&ia64_info->root,
			  elf32_ia64_global_dyn_sym_thunk, &xdata);
  htab_traverse (ia64_info->loc_hash_table,
		 elf32_ia64_local_dyn_sym_thunk, &xdata);
}

static bool
elf32_ia64_create_dynamic_sections (bfd *abfd,
				    struct bfd_link_info *info)
{
  struct elf32_ia64_link_hash_table *ia64_info;
  asection *s;

  if (! _bfd_elf_create_dynamic_sections (abfd, info))
    return false;

  ia64_info = elf32_ia64_hash_table (info);
  if (ia64_info == NULL)
    return false;

  {
    flagword flags = bfd_section_flags (ia64_info->root.sgot);
    bfd_set_section_flags (ia64_info->root.sgot, SEC_SMALL_DATA | flags);
    /* The .got section is always aligned at 8 bytes.  */
    if (!bfd_set_section_alignment (ia64_info->root.sgot, 3))
      return false;
  }

  if (!get_pltoff (abfd, info, ia64_info))
    return false;

  s = bfd_make_section_anyway_with_flags (abfd, ".rela.IA_64.pltoff",
					  (SEC_ALLOC | SEC_LOAD
					   | SEC_HAS_CONTENTS
					   | SEC_IN_MEMORY
					   | SEC_LINKER_CREATED
					   | SEC_READONLY));
  if (s == NULL
      || !bfd_set_section_alignment (s, LOG_SECTION_ALIGN))
    return false;
  ia64_info->rel_pltoff_sec = s;

  return true;
}

/* Find and/or create a hash entry for local symbol.  */
static struct elf32_ia64_local_hash_entry *
get_local_sym_hash (struct elf32_ia64_link_hash_table *ia64_info,
		    bfd *abfd, const Elf_Internal_Rela *rel,
		    bool create)
{
  struct elf32_ia64_local_hash_entry e, *ret;
  asection *sec = abfd->sections;
  hashval_t h = ELF_LOCAL_SYMBOL_HASH (sec->id,
				       ELF32_R_SYM (rel->r_info));
  void **slot;

  e.id = sec->id;
  e.r_sym = ELF32_R_SYM (rel->r_info);
  slot = htab_find_slot_with_hash (ia64_info->loc_hash_table, &e, h,
				   create ? INSERT : NO_INSERT);

  if (!slot)
    return NULL;

  if (*slot)
    return (struct elf32_ia64_local_hash_entry *) *slot;

  ret = (struct elf32_ia64_local_hash_entry *)
	objalloc_alloc ((struct objalloc *) ia64_info->loc_hash_memory,
			sizeof (struct elf32_ia64_local_hash_entry));
  if (ret)
    {
      memset (ret, 0, sizeof (*ret));
      ret->id = sec->id;
      ret->r_sym = ELF32_R_SYM (rel->r_info);
      *slot = ret;
    }
  return ret;
}

/* Used to sort elf32_ia64_dyn_sym_info array.  */

static int
addend_compare (const void *xp, const void *yp)
{
  const struct elf32_ia64_dyn_sym_info *x
    = (const struct elf32_ia64_dyn_sym_info *) xp;
  const struct elf32_ia64_dyn_sym_info *y
    = (const struct elf32_ia64_dyn_sym_info *) yp;

  return x->addend < y->addend ? -1 : x->addend > y->addend ? 1 : 0;
}

/* Sort elf32_ia64_dyn_sym_info array and remove duplicates.  */

static unsigned int
sort_dyn_sym_info (struct elf32_ia64_dyn_sym_info *info,
		   unsigned int count)
{
  bfd_vma curr, prev, got_offset;
  unsigned int i, kept, dupes, diff, dest, src, len;

  qsort (info, count, sizeof (*info), addend_compare);

  /* Find the first duplicate.  */
  prev = info [0].addend;
  got_offset = info [0].got_offset;
  for (i = 1; i < count; i++)
    {
      curr = info [i].addend;
      if (curr == prev)
	{
	  /* For duplicates, make sure that GOT_OFFSET is valid.  */
	  if (got_offset == (bfd_vma) -1)
	    got_offset = info [i].got_offset;
	  break;
	}
      got_offset = info [i].got_offset;
      prev = curr;
    }

  /* We may move a block of elements to here.  */
  dest = i++;

  /* Remove duplicates.  */
  if (i < count)
    {
      while (i < count)
	{
	  /* For duplicates, make sure that the kept one has a valid
	     got_offset.  */
	  kept = dest - 1;
	  if (got_offset != (bfd_vma) -1)
	    info [kept].got_offset = got_offset;

	  curr = info [i].addend;
	  got_offset = info [i].got_offset;

	  /* Move a block of elements whose first one is different from
	     the previous.  */
	  if (curr == prev)
	    {
	      for (src = i + 1; src < count; src++)
		{
		  if (info [src].addend != curr)
		    break;
		  /* For duplicates, make sure that GOT_OFFSET is
		     valid.  */
		  if (got_offset == (bfd_vma) -1)
		    got_offset = info [src].got_offset;
		}

	      /* Make sure that the kept one has a valid got_offset.  */
	      if (got_offset != (bfd_vma) -1)
		info [kept].got_offset = got_offset;
	    }
	  else
	    src = i;

	  if (src >= count)
	    break;

	  /* Find the next duplicate.  SRC will be kept.  */
	  prev = info [src].addend;
	  got_offset = info [src].got_offset;
	  for (dupes = src + 1; dupes < count; dupes ++)
	    {
	      curr = info [dupes].addend;
	      if (curr == prev)
		{
		  /* Make sure that got_offset is valid.  */
		  if (got_offset == (bfd_vma) -1)
		    got_offset = info [dupes].got_offset;

		  /* For duplicates, make sure that the kept one has
		     a valid got_offset.  */
		  if (got_offset != (bfd_vma) -1)
		    info [dupes - 1].got_offset = got_offset;
		  break;
		}
	      got_offset = info [dupes].got_offset;
	      prev = curr;
	    }

	  /* How much to move.  */
	  len = dupes - src;
	  i = dupes + 1;

	  if (len == 1 && dupes < count)
	    {
	      /* If we only move 1 element, we combine it with the next
		 one.  There must be at least a duplicate.  Find the
		 next different one.  */
	      for (diff = dupes + 1, src++; diff < count; diff++, src++)
		{
		  if (info [diff].addend != curr)
		    break;
		  /* Make sure that got_offset is valid.  */
		  if (got_offset == (bfd_vma) -1)
		    got_offset = info [diff].got_offset;
		}

	      /* Makre sure that the last duplicated one has an valid
		 offset.  */
	      BFD_ASSERT (curr == prev);
	      if (got_offset != (bfd_vma) -1)
		info [diff - 1].got_offset = got_offset;

	      if (diff < count)
		{
		  /* Find the next duplicate.  Track the current valid
		     offset.  */
		  prev = info [diff].addend;
		  got_offset = info [diff].got_offset;
		  for (dupes = diff + 1; dupes < count; dupes ++)
		    {
		      curr = info [dupes].addend;
		      if (curr == prev)
			{
			  /* For duplicates, make sure that GOT_OFFSET
			     is valid.  */
			  if (got_offset == (bfd_vma) -1)
			    got_offset = info [dupes].got_offset;
			  break;
			}
		      got_offset = info [dupes].got_offset;
		      prev = curr;
		      diff++;
		    }

		  len = diff - src + 1;
		  i = diff + 1;
		}
	    }

	  memmove (&info [dest], &info [src], len * sizeof (*info));

	  dest += len;
	}

      count = dest;
    }
  else
    {
      /* When we get here, either there is no duplicate at all or
	 the only duplicate is the last element.  */
      if (dest < count)
	{
	  /* If the last element is a duplicate, make sure that the
	     kept one has a valid got_offset.  We also update count.  */
	  if (got_offset != (bfd_vma) -1)
	    info [dest - 1].got_offset = got_offset;
	  count = dest;
	}
    }

  return count;
}

/* Find and/or create a descriptor for dynamic symbol info.  This will
   vary based on global or local symbol, and the addend to the reloc.

   We don't sort when inserting.  Also, we sort and eliminate
   duplicates if there is an unsorted section.  Typically, this will
   only happen once, because we do all insertions before lookups.  We
   then use bsearch to do a lookup.  This also allows lookups to be
   fast.  So we have fast insertion (O(log N) due to duplicate check),
   fast lookup (O(log N)) and one sort (O(N log N) expected time).
   Previously, all lookups were O(N) because of the use of the linked
   list and also all insertions were O(N) because of the check for
   duplicates.  There are some complications here because the array
   size grows occasionally, which may add an O(N) factor, but this
   should be rare.  Also,  we free the excess array allocation, which
   requires a copy which is O(N), but this only happens once.  */

static struct elf32_ia64_dyn_sym_info *
get_dyn_sym_info (struct elf32_ia64_link_hash_table *ia64_info,
		  struct elf_link_hash_entry *h, bfd *abfd,
		  const Elf_Internal_Rela *rel, bool create)
{
  struct elf32_ia64_dyn_sym_info **info_p, *info, *dyn_i, key;
  unsigned int *count_p, *sorted_count_p, *size_p;
  unsigned int count, sorted_count, size;
  bfd_vma addend = rel ? rel->r_addend : 0;
  bfd_size_type amt;

  if (h)
    {
      struct elf32_ia64_link_hash_entry *global_h;

      global_h = (struct elf32_ia64_link_hash_entry *) h;
      info_p = &global_h->info;
      count_p = &global_h->count;
      sorted_count_p = &global_h->sorted_count;
      size_p = &global_h->size;
    }
  else
    {
      struct elf32_ia64_local_hash_entry *loc_h;

      loc_h = get_local_sym_hash (ia64_info, abfd, rel, create);
      if (!loc_h)
	{
	  BFD_ASSERT (!create);
	  return NULL;
	}

      info_p = &loc_h->info;
      count_p = &loc_h->count;
      sorted_count_p = &loc_h->sorted_count;
      size_p = &loc_h->size;
    }

  count = *count_p;
  sorted_count = *sorted_count_p;
  size = *size_p;
  info = *info_p;
  if (create)
    {
      /* When we create the array, we don't check for duplicates,
	 except in the previously sorted section if one exists, and
	 against the last inserted entry.  This allows insertions to
	 be fast.  */
      if (info)
	{
	  if (sorted_count)
	    {
	      /* Try bsearch first on the sorted section.  */
	      key.addend = addend;
	      dyn_i = bsearch (&key, info, sorted_count,
			       sizeof (*info), addend_compare);
	      if (dyn_i)
		return dyn_i;
	    }

	  if (count != 0)
	    {
	      /* Do a quick check for the last inserted entry.  */
	      dyn_i = info + count - 1;
	      if (dyn_i->addend == addend)
		return dyn_i;
	    }
	}

      if (size == 0)
	{
	  /* It is the very first element. We create the array of size
	     1.  */
	  size = 1;
	  amt = size * sizeof (*info);
	  info = bfd_malloc (amt);
	}
      else if (size <= count)
	{
	  /* We double the array size every time when we reach the
	     size limit.  */
	  size += size;
	  amt = size * sizeof (*info);
	  info = bfd_realloc (info, amt);
	}
      else
	goto has_space;

      if (info == NULL)
	return NULL;
      *size_p = size;
      *info_p = info;

    has_space:
      /* Append the new one to the array.  */
      dyn_i = info + count;
      memset (dyn_i, 0, sizeof (*dyn_i));
      dyn_i->got_offset = (bfd_vma) -1;
      dyn_i->addend = addend;

      /* We increment count only since the new ones are unsorted and
	 may have duplicate.  */
      (*count_p)++;
    }
  else
    {
      /* It is a lookup without insertion.  Sort array if part of the
	 array isn't sorted.  */
      if (count != sorted_count)
	{
	  count = sort_dyn_sym_info (info, count);
	  *count_p = count;
	  *sorted_count_p = count;
	}

      /* Free unused memory.  */
      if (size != count)
	{
	  amt = count * sizeof (*info);
	  info = bfd_realloc (info, amt);
	  *size_p = count;
	  if (info == NULL && count != 0)
	    /* realloc should never fail since we are reducing size here,
	       but if it does use the old array.  */
	    info = *info_p;
	  else
	    *info_p = info;
	}

      if (count == 0)
	dyn_i = NULL;
      else
	{
	  key.addend = addend;
	  dyn_i = bsearch (&key, info, count, sizeof (*info), addend_compare);
	}
    }

  return dyn_i;
}

static asection *
get_got (bfd *abfd, struct bfd_link_info *info,
	 struct elf32_ia64_link_hash_table *ia64_info)
{
  asection *got;
  bfd *dynobj;

  got = ia64_info->root.sgot;
  if (!got)
    {
      flagword flags;

      dynobj = ia64_info->root.dynobj;
      if (!dynobj)
	ia64_info->root.dynobj = dynobj = abfd;
      if (!_bfd_elf_create_got_section (dynobj, info))
	return NULL;

      got = ia64_info->root.sgot;

      /* The .got section is always aligned at 8 bytes.  */
      if (!bfd_set_section_alignment (got, 3))
	return NULL;

      flags = bfd_section_flags (got);
      if (!bfd_set_section_flags (got, SEC_SMALL_DATA | flags))
	return NULL;
    }

  return got;
}

/* Create function descriptor section (.opd).  This section is called .opd
   because it contains "official procedure descriptors".  The "official"
   refers to the fact that these descriptors are used when taking the address
   of a procedure, thus ensuring a unique address for each procedure.  */

static asection *
get_fptr (bfd *abfd, struct bfd_link_info *info,
	  struct elf32_ia64_link_hash_table *ia64_info)
{
  asection *fptr;
  bfd *dynobj;

  fptr = ia64_info->fptr_sec;
  if (!fptr)
    {
      dynobj = ia64_info->root.dynobj;
      if (!dynobj)
	ia64_info->root.dynobj = dynobj = abfd;

      fptr = bfd_make_section_anyway_with_flags (dynobj, ".opd",
						 (SEC_ALLOC
						  | SEC_LOAD
						  | SEC_HAS_CONTENTS
						  | SEC_IN_MEMORY
						  | (bfd_link_pie (info)
						     ? 0 : SEC_READONLY)
						  | SEC_LINKER_CREATED));
      if (!fptr
	  || !bfd_set_section_alignment (fptr, 4))
	{
	  BFD_ASSERT (0);
	  return NULL;
	}

      ia64_info->fptr_sec = fptr;

      if (bfd_link_pie (info))
	{
	  asection *fptr_rel;
	  fptr_rel = bfd_make_section_anyway_with_flags (dynobj, ".rela.opd",
							 (SEC_ALLOC | SEC_LOAD
							  | SEC_HAS_CONTENTS
							  | SEC_IN_MEMORY
							  | SEC_LINKER_CREATED
							  | SEC_READONLY));
	  if (fptr_rel == NULL
	      || !bfd_set_section_alignment (fptr_rel, LOG_SECTION_ALIGN))
	    {
	      BFD_ASSERT (0);
	      return NULL;
	    }

	  ia64_info->rel_fptr_sec = fptr_rel;
	}
    }

  return fptr;
}

static asection *
get_pltoff (bfd *abfd, struct bfd_link_info *info ATTRIBUTE_UNUSED,
	    struct elf32_ia64_link_hash_table *ia64_info)
{
  asection *pltoff;
  bfd *dynobj;

  pltoff = ia64_info->pltoff_sec;
  if (!pltoff)
    {
      dynobj = ia64_info->root.dynobj;
      if (!dynobj)
	ia64_info->root.dynobj = dynobj = abfd;

      pltoff = bfd_make_section_anyway_with_flags (dynobj,
						   ELF_STRING_ia64_pltoff,
						   (SEC_ALLOC
						    | SEC_LOAD
						    | SEC_HAS_CONTENTS
						    | SEC_IN_MEMORY
						    | SEC_SMALL_DATA
						    | SEC_LINKER_CREATED));
      if (!pltoff
	  || !bfd_set_section_alignment (pltoff, 4))
	{
	  BFD_ASSERT (0);
	  return NULL;
	}

      ia64_info->pltoff_sec = pltoff;
    }

  return pltoff;
}

static asection *
get_reloc_section (bfd *abfd,
		   struct elf32_ia64_link_hash_table *ia64_info,
		   asection *sec, bool create)
{
  const char *srel_name;
  asection *srel;
  bfd *dynobj;

  srel_name = (bfd_elf_string_from_elf_section
	       (abfd, elf_elfheader(abfd)->e_shstrndx,
		_bfd_elf_single_rel_hdr (sec)->sh_name));
  if (srel_name == NULL)
    return NULL;

  dynobj = ia64_info->root.dynobj;
  if (!dynobj)
    ia64_info->root.dynobj = dynobj = abfd;

  srel = bfd_get_linker_section (dynobj, srel_name);
  if (srel == NULL && create)
    {
      srel = bfd_make_section_anyway_with_flags (dynobj, srel_name,
						 (SEC_ALLOC | SEC_LOAD
						  | SEC_HAS_CONTENTS
						  | SEC_IN_MEMORY
						  | SEC_LINKER_CREATED
						  | SEC_READONLY));
      if (srel == NULL
	  || !bfd_set_section_alignment (srel, LOG_SECTION_ALIGN))
	return NULL;
    }

  return srel;
}

static bool
count_dyn_reloc (bfd *abfd, struct elf32_ia64_dyn_sym_info *dyn_i,
		 asection *srel, int type, bool reltext)
{
  struct elf32_ia64_dyn_reloc_entry *rent;

  for (rent = dyn_i->reloc_entries; rent; rent = rent->next)
    if (rent->srel == srel && rent->type == type)
      break;

  if (!rent)
    {
      rent = ((struct elf32_ia64_dyn_reloc_entry *)
	      bfd_alloc (abfd, (bfd_size_type) sizeof (*rent)));
      if (!rent)
	return false;

      rent->next = dyn_i->reloc_entries;
      rent->srel = srel;
      rent->type = type;
      rent->count = 0;
      dyn_i->reloc_entries = rent;
    }
  rent->reltext = reltext;
  rent->count++;

  return true;
}

static bool
elf32_ia64_check_relocs (bfd *abfd, struct bfd_link_info *info,
			 asection *sec,
			 const Elf_Internal_Rela *relocs)
{
  struct elf32_ia64_link_hash_table *ia64_info;
  const Elf_Internal_Rela *relend;
  Elf_Internal_Shdr *symtab_hdr;
  const Elf_Internal_Rela *rel;
  asection *got, *fptr, *srel, *pltoff;
  enum {
    NEED_GOT = 1,
    NEED_GOTX = 2,
    NEED_FPTR = 4,
    NEED_PLTOFF = 8,
    NEED_MIN_PLT = 16,
    NEED_FULL_PLT = 32,
    NEED_DYNREL = 64,
    NEED_LTOFF_FPTR = 128,
    NEED_TPREL = 256,
    NEED_DTPMOD = 512,
    NEED_DTPREL = 1024
  };
  int need_entry;
  struct elf_link_hash_entry *h;
  unsigned long r_symndx;
  bool maybe_dynamic;

  if (bfd_link_relocatable (info))
    return true;

  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  ia64_info = elf32_ia64_hash_table (info);
  if (ia64_info == NULL)
    return false;

  got = fptr = srel = pltoff = NULL;

  relend = relocs + sec->reloc_count;

  /* We scan relocations first to create dynamic relocation arrays.  We
     modified get_dyn_sym_info to allow fast insertion and support fast
     lookup in the next loop.  */
  for (rel = relocs; rel < relend; ++rel)
    {
      r_symndx = ELF32_R_SYM (rel->r_info);
      if (r_symndx >= symtab_hdr->sh_info)
	{
	  long indx = r_symndx - symtab_hdr->sh_info;
	  h = elf_sym_hashes (abfd)[indx];
	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;
	}
      else
	h = NULL;

      /* We can only get preliminary data on whether a symbol is
	 locally or externally defined, as not all of the input files
	 have yet been processed.  Do something with what we know, as
	 this may help reduce memory usage and processing time later.  */
      maybe_dynamic = (h && ((!bfd_link_executable (info)
			      && (!SYMBOLIC_BIND (info, h)
				  || info->unresolved_syms_in_shared_libs == RM_IGNORE))
			     || !h->def_regular
			     || h->root.type == bfd_link_hash_defweak));

      need_entry = 0;
      switch (ELF32_R_TYPE (rel->r_info))
	{
	case R_IA64_TPREL64MSB:
	case R_IA64_TPREL64LSB:
	  if (bfd_link_pic (info) || maybe_dynamic)
	    need_entry = NEED_DYNREL;
	  break;

	case R_IA64_LTOFF_TPREL22:
	  need_entry = NEED_TPREL;
	  if (bfd_link_pic (info))
	    info->flags |= DF_STATIC_TLS;
	  break;

	case R_IA64_DTPREL32MSB:
	case R_IA64_DTPREL32LSB:
	case R_IA64_DTPREL64MSB:
	case R_IA64_DTPREL64LSB:
	  if (bfd_link_pic (info) || maybe_dynamic)
	    need_entry = NEED_DYNREL;
	  break;

	case R_IA64_LTOFF_DTPREL22:
	  need_entry = NEED_DTPREL;
	  break;

	case R_IA64_DTPMOD64MSB:
	case R_IA64_DTPMOD64LSB:
	  if (bfd_link_pic (info) || maybe_dynamic)
	    need_entry = NEED_DYNREL;
	  break;

	case R_IA64_LTOFF_DTPMOD22:
	  need_entry = NEED_DTPMOD;
	  break;

	case R_IA64_LTOFF_FPTR22:
	case R_IA64_LTOFF_FPTR64I:
	case R_IA64_LTOFF_FPTR32MSB:
	case R_IA64_LTOFF_FPTR32LSB:
	case R_IA64_LTOFF_FPTR64MSB:
	case R_IA64_LTOFF_FPTR64LSB:
	  need_entry = NEED_FPTR | NEED_GOT | NEED_LTOFF_FPTR;
	  break;

	case R_IA64_FPTR64I:
	case R_IA64_FPTR32MSB:
	case R_IA64_FPTR32LSB:
	case R_IA64_FPTR64MSB:
	case R_IA64_FPTR64LSB:
	  if (bfd_link_pic (info) || h)
	    need_entry = NEED_FPTR | NEED_DYNREL;
	  else
	    need_entry = NEED_FPTR;
	  break;

	case R_IA64_LTOFF22:
	case R_IA64_LTOFF64I:
	  need_entry = NEED_GOT;
	  break;

	case R_IA64_LTOFF22X:
	  need_entry = NEED_GOTX;
	  break;

	case R_IA64_PLTOFF22:
	case R_IA64_PLTOFF64I:
	case R_IA64_PLTOFF64MSB:
	case R_IA64_PLTOFF64LSB:
	  need_entry = NEED_PLTOFF;
	  if (h)
	    {
	      if (maybe_dynamic)
		need_entry |= NEED_MIN_PLT;
	    }
	  else
	    {
	      (*info->callbacks->warning)
		(info, _("@pltoff reloc against local symbol"), 0,
		 abfd, 0, (bfd_vma) 0);
	    }
	  break;

	case R_IA64_PCREL21B:
	case R_IA64_PCREL60B:
	  /* Depending on where this symbol is defined, we may or may not
	     need a full plt entry.  Only skip if we know we'll not need
	     the entry -- static or symbolic, and the symbol definition
	     has already been seen.  */
	  if (maybe_dynamic && rel->r_addend == 0)
	    need_entry = NEED_FULL_PLT;
	  break;

	case R_IA64_IMM14:
	case R_IA64_IMM22:
	case R_IA64_IMM64:
	case R_IA64_DIR32MSB:
	case R_IA64_DIR32LSB:
	case R_IA64_DIR64MSB:
	case R_IA64_DIR64LSB:
	  /* Shared objects will always need at least a REL relocation.  */
	  if (bfd_link_pic (info) || maybe_dynamic)
	    need_entry = NEED_DYNREL;
	  break;

	case R_IA64_IPLTMSB:
	case R_IA64_IPLTLSB:
	  /* Shared objects will always need at least a REL relocation.  */
	  if (bfd_link_pic (info) || maybe_dynamic)
	    need_entry = NEED_DYNREL;
	  break;

	case R_IA64_PCREL22:
	case R_IA64_PCREL64I:
	case R_IA64_PCREL32MSB:
	case R_IA64_PCREL32LSB:
	case R_IA64_PCREL64MSB:
	case R_IA64_PCREL64LSB:
	  if (maybe_dynamic)
	    need_entry = NEED_DYNREL;
	  break;
	}

      if (!need_entry)
	continue;

      if ((need_entry & NEED_FPTR) != 0
	  && rel->r_addend)
	{
	  (*info->callbacks->warning)
	    (info, _("non-zero addend in @fptr reloc"), 0,
	     abfd, 0, (bfd_vma) 0);
	}

      if (get_dyn_sym_info (ia64_info, h, abfd, rel, true) == NULL)
	return false;
    }

  /* Now, we only do lookup without insertion, which is very fast
     with the modified get_dyn_sym_info.  */
  for (rel = relocs; rel < relend; ++rel)
    {
      struct elf32_ia64_dyn_sym_info *dyn_i;
      int dynrel_type = R_IA64_NONE;

      r_symndx = ELF32_R_SYM (rel->r_info);
      if (r_symndx >= symtab_hdr->sh_info)
	{
	  /* We're dealing with a global symbol -- find its hash entry
	     and mark it as being referenced.  */
	  long indx = r_symndx - symtab_hdr->sh_info;
	  h = elf_sym_hashes (abfd)[indx];
	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;

	  /* PR15323, ref flags aren't set for references in the same
	     object.  */
	  h->ref_regular = 1;
	}
      else
	h = NULL;

      /* We can only get preliminary data on whether a symbol is
	 locally or externally defined, as not all of the input files
	 have yet been processed.  Do something with what we know, as
	 this may help reduce memory usage and processing time later.  */
      maybe_dynamic = (h && ((!bfd_link_executable (info)
			      && (!SYMBOLIC_BIND (info, h)
				  || info->unresolved_syms_in_shared_libs == RM_IGNORE))
			     || !h->def_regular
			     || h->root.type == bfd_link_hash_defweak));

      need_entry = 0;
      switch (ELF32_R_TYPE (rel->r_info))
	{
	case R_IA64_TPREL64MSB:
	case R_IA64_TPREL64LSB:
	  if (bfd_link_pic (info) || maybe_dynamic)
	    need_entry = NEED_DYNREL;
	  dynrel_type = R_IA64_TPREL64LSB;
	  if (bfd_link_pic (info))
	    info->flags |= DF_STATIC_TLS;
	  break;

	case R_IA64_LTOFF_TPREL22:
	  need_entry = NEED_TPREL;
	  if (bfd_link_pic (info))
	    info->flags |= DF_STATIC_TLS;
	  break;

	case R_IA64_DTPREL32MSB:
	case R_IA64_DTPREL32LSB:
	case R_IA64_DTPREL64MSB:
	case R_IA64_DTPREL64LSB:
	  if (bfd_link_pic (info) || maybe_dynamic)
	    need_entry = NEED_DYNREL;
	  dynrel_type = R_IA64_DTPREL32LSB;
	  break;

	case R_IA64_LTOFF_DTPREL22:
	  need_entry = NEED_DTPREL;
	  break;

	case R_IA64_DTPMOD64MSB:
	case R_IA64_DTPMOD64LSB:
	  if (bfd_link_pic (info) || maybe_dynamic)
	    need_entry = NEED_DYNREL;
	  dynrel_type = R_IA64_DTPMOD64LSB;
	  break;

	case R_IA64_LTOFF_DTPMOD22:
	  need_entry = NEED_DTPMOD;
	  break;

	case R_IA64_LTOFF_FPTR22:
	case R_IA64_LTOFF_FPTR64I:
	case R_IA64_LTOFF_FPTR32MSB:
	case R_IA64_LTOFF_FPTR32LSB:
	case R_IA64_LTOFF_FPTR64MSB:
	case R_IA64_LTOFF_FPTR64LSB:
	  need_entry = NEED_FPTR | NEED_GOT | NEED_LTOFF_FPTR;
	  break;

	case R_IA64_FPTR64I:
	case R_IA64_FPTR32MSB:
	case R_IA64_FPTR32LSB:
	case R_IA64_FPTR64MSB:
	case R_IA64_FPTR64LSB:
	  if (bfd_link_pic (info) || h)
	    need_entry = NEED_FPTR | NEED_DYNREL;
	  else
	    need_entry = NEED_FPTR;
	  dynrel_type = R_IA64_FPTR32LSB;
	  break;

	case R_IA64_LTOFF22:
	case R_IA64_LTOFF64I:
	  need_entry = NEED_GOT;
	  break;

	case R_IA64_LTOFF22X:
	  need_entry = NEED_GOTX;
	  break;

	case R_IA64_PLTOFF22:
	case R_IA64_PLTOFF64I:
	case R_IA64_PLTOFF64MSB:
	case R_IA64_PLTOFF64LSB:
	  need_entry = NEED_PLTOFF;
	  if (h)
	    {
	      if (maybe_dynamic)
		need_entry |= NEED_MIN_PLT;
	    }
	  break;

	case R_IA64_PCREL21B:
	case R_IA64_PCREL60B:
	  /* Depending on where this symbol is defined, we may or may not
	     need a full plt entry.  Only skip if we know we'll not need
	     the entry -- static or symbolic, and the symbol definition
	     has already been seen.  */
	  if (maybe_dynamic && rel->r_addend == 0)
	    need_entry = NEED_FULL_PLT;
	  break;

	case R_IA64_IMM14:
	case R_IA64_IMM22:
	case R_IA64_IMM64:
	case R_IA64_DIR32MSB:
	case R_IA64_DIR32LSB:
	case R_IA64_DIR64MSB:
	case R_IA64_DIR64LSB:
	  /* Shared objects will always need at least a REL relocation.  */
	  if (bfd_link_pic (info) || maybe_dynamic)
	    need_entry = NEED_DYNREL;
	  dynrel_type = R_IA64_DIR32LSB;
	  break;

	case R_IA64_IPLTMSB:
	case R_IA64_IPLTLSB:
	  /* Shared objects will always need at least a REL relocation.  */
	  if (bfd_link_pic (info) || maybe_dynamic)
	    need_entry = NEED_DYNREL;
	  dynrel_type = R_IA64_IPLTLSB;
	  break;

	case R_IA64_PCREL22:
	case R_IA64_PCREL64I:
	case R_IA64_PCREL32MSB:
	case R_IA64_PCREL32LSB:
	case R_IA64_PCREL64MSB:
	case R_IA64_PCREL64LSB:
	  if (maybe_dynamic)
	    need_entry = NEED_DYNREL;
	  dynrel_type = R_IA64_PCREL32LSB;
	  break;
	}

      if (!need_entry)
	continue;

      dyn_i = get_dyn_sym_info (ia64_info, h, abfd, rel, false);

      /* Record whether or not this is a local symbol.  */
      dyn_i->h = h;

      /* Create what's needed.  */
      if (need_entry & (NEED_GOT | NEED_GOTX | NEED_TPREL
			| NEED_DTPMOD | NEED_DTPREL))
	{
	  if (!got)
	    {
	      got = get_got (abfd, info, ia64_info);
	      if (!got)
		return false;
	    }
	  if (need_entry & NEED_GOT)
	    dyn_i->want_got = 1;
	  if (need_entry & NEED_GOTX)
	    dyn_i->want_gotx = 1;
	  if (need_entry & NEED_TPREL)
	    dyn_i->want_tprel = 1;
	  if (need_entry & NEED_DTPMOD)
	    dyn_i->want_dtpmod = 1;
	  if (need_entry & NEED_DTPREL)
	    dyn_i->want_dtprel = 1;
	}
      if (need_entry & NEED_FPTR)
	{
	  if (!fptr)
	    {
	      fptr = get_fptr (abfd, info, ia64_info);
	      if (!fptr)
		return false;
	    }

	  /* FPTRs for shared libraries are allocated by the dynamic
	     linker.  Make sure this local symbol will appear in the
	     dynamic symbol table.  */
	  if (!h && bfd_link_pic (info))
	    {
	      if (! (bfd_elf_link_record_local_dynamic_symbol
		     (info, abfd, (long) r_symndx)))
		return false;
	    }

	  dyn_i->want_fptr = 1;
	}
      if (need_entry & NEED_LTOFF_FPTR)
	dyn_i->want_ltoff_fptr = 1;
      if (need_entry & (NEED_MIN_PLT | NEED_FULL_PLT))
	{
	  if (!ia64_info->root.dynobj)
	    ia64_info->root.dynobj = abfd;
	  h->needs_plt = 1;
	  dyn_i->want_plt = 1;
	}
      if (need_entry & NEED_FULL_PLT)
	dyn_i->want_plt2 = 1;
      if (need_entry & NEED_PLTOFF)
	{
	  /* This is needed here, in case @pltoff is used in a non-shared
	     link.  */
	  if (!pltoff)
	    {
	      pltoff = get_pltoff (abfd, info, ia64_info);
	      if (!pltoff)
		return false;
	    }

	  dyn_i->want_pltoff = 1;
	}
      if ((need_entry & NEED_DYNREL) && (sec->flags & SEC_ALLOC))
	{
	  if (!srel)
	    {
	      srel = get_reloc_section (abfd, ia64_info, sec, true);
	      if (!srel)
		return false;
	    }
	  if (!count_dyn_reloc (abfd, dyn_i, srel, dynrel_type,
				(sec->flags & SEC_READONLY) != 0))
	    return false;
	}
    }

  return true;
}

/* For cleanliness, and potentially faster dynamic loading, allocate
   external GOT entries first.  */

static bool
allocate_global_data_got (struct elf32_ia64_dyn_sym_info *dyn_i,
			  void * data)
{
  struct elf32_ia64_allocate_data *x = (struct elf32_ia64_allocate_data *)data;

  if ((dyn_i->want_got || dyn_i->want_gotx)
      && ! dyn_i->want_fptr
      && elf32_ia64_dynamic_symbol_p (dyn_i->h, x->info, 0))
     {
       dyn_i->got_offset = x->ofs;
       x->ofs += 8;
     }
  if (dyn_i->want_tprel)
    {
      dyn_i->tprel_offset = x->ofs;
      x->ofs += 8;
    }
  if (dyn_i->want_dtpmod)
    {
      if (elf32_ia64_dynamic_symbol_p (dyn_i->h, x->info, 0))
	{
	  dyn_i->dtpmod_offset = x->ofs;
	  x->ofs += 8;
	}
      else
	{
	  struct elf32_ia64_link_hash_table *ia64_info;

	  ia64_info = elf32_ia64_hash_table (x->info);
	  if (ia64_info == NULL)
	    return false;

	  if (ia64_info->self_dtpmod_offset == (bfd_vma) -1)
	    {
	      ia64_info->self_dtpmod_offset = x->ofs;
	      x->ofs += 8;
	    }
	  dyn_i->dtpmod_offset = ia64_info->self_dtpmod_offset;
	}
    }
  if (dyn_i->want_dtprel)
    {
      dyn_i->dtprel_offset = x->ofs;
      x->ofs += 8;
    }
  return true;
}

/* Next, allocate all the GOT entries used by LTOFF_FPTR relocs.  */

static bool
allocate_global_fptr_got (struct elf32_ia64_dyn_sym_info *dyn_i,
			  void * data)
{
  struct elf32_ia64_allocate_data *x = (struct elf32_ia64_allocate_data *)data;

  if (dyn_i->want_got
      && dyn_i->want_fptr
      && elf32_ia64_dynamic_symbol_p (dyn_i->h, x->info, R_IA64_FPTR32LSB))
    {
      dyn_i->got_offset = x->ofs;
      x->ofs += 8;
    }
  return true;
}

/* Lastly, allocate all the GOT entries for local data.  */

static bool
allocate_local_got (struct elf32_ia64_dyn_sym_info *dyn_i,
		    void * data)
{
  struct elf32_ia64_allocate_data *x = (struct elf32_ia64_allocate_data *)data;

  if ((dyn_i->want_got || dyn_i->want_gotx)
      && !elf32_ia64_dynamic_symbol_p (dyn_i->h, x->info, 0))
    {
      dyn_i->got_offset = x->ofs;
      x->ofs += 8;
    }
  return true;
}

/* Search for the index of a global symbol in it's defining object file.  */

static long
global_sym_index (struct elf_link_hash_entry *h)
{
  struct elf_link_hash_entry **p;
  bfd *obj;

  BFD_ASSERT (h->root.type == bfd_link_hash_defined
	      || h->root.type == bfd_link_hash_defweak);

  obj = h->root.u.def.section->owner;
  for (p = elf_sym_hashes (obj); *p != h; ++p)
    continue;

  return p - elf_sym_hashes (obj) + elf_tdata (obj)->symtab_hdr.sh_info;
}

/* Allocate function descriptors.  We can do these for every function
   in a main executable that is not exported.  */

static bool
allocate_fptr (struct elf32_ia64_dyn_sym_info *dyn_i, void * data)
{
  struct elf32_ia64_allocate_data *x = (struct elf32_ia64_allocate_data *)data;

  if (dyn_i->want_fptr)
    {
      struct elf_link_hash_entry *h = dyn_i->h;

      if (h)
	while (h->root.type == bfd_link_hash_indirect
	       || h->root.type == bfd_link_hash_warning)
	  h = (struct elf_link_hash_entry *) h->root.u.i.link;

      if (!bfd_link_executable (x->info)
	  && (!h
	      || ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
	      || (h->root.type != bfd_link_hash_undefweak
		  && h->root.type != bfd_link_hash_undefined)))
	{
	  if (h && h->dynindx == -1)
	    {
	      BFD_ASSERT ((h->root.type == bfd_link_hash_defined)
			  || (h->root.type == bfd_link_hash_defweak));

	      if (!bfd_elf_link_record_local_dynamic_symbol
		    (x->info, h->root.u.def.section->owner,
		     global_sym_index (h)))
		return false;
	    }

	  dyn_i->want_fptr = 0;
	}
      else if (h == NULL || h->dynindx == -1)
	{
	  dyn_i->fptr_offset = x->ofs;
	  x->ofs += 16;
	}
      else
	dyn_i->want_fptr = 0;
    }
  return true;
}

/* Allocate all the minimal PLT entries.  */

static bool
allocate_plt_entries (struct elf32_ia64_dyn_sym_info *dyn_i,
		      void * data)
{
  struct elf32_ia64_allocate_data *x = (struct elf32_ia64_allocate_data *)data;

  if (dyn_i->want_plt)
    {
      struct elf_link_hash_entry *h = dyn_i->h;

      if (h)
	while (h->root.type == bfd_link_hash_indirect
	       || h->root.type == bfd_link_hash_warning)
	  h = (struct elf_link_hash_entry *) h->root.u.i.link;

      /* ??? Versioned symbols seem to lose NEEDS_PLT.  */
      if (elf32_ia64_dynamic_symbol_p (h, x->info, 0))
	{
	  bfd_size_type offset = x->ofs;
	  if (offset == 0)
	    offset = PLT_HEADER_SIZE;
	  dyn_i->plt_offset = offset;
	  x->ofs = offset + PLT_MIN_ENTRY_SIZE;

	  dyn_i->want_pltoff = 1;
	}
      else
	{
	  dyn_i->want_plt = 0;
	  dyn_i->want_plt2 = 0;
	}
    }
  return true;
}

/* Allocate all the full PLT entries.  */

static bool
allocate_plt2_entries (struct elf32_ia64_dyn_sym_info *dyn_i,
		       void * data)
{
  struct elf32_ia64_allocate_data *x = (struct elf32_ia64_allocate_data *)data;

  if (dyn_i->want_plt2)
    {
      struct elf_link_hash_entry *h = dyn_i->h;
      bfd_size_type ofs = x->ofs;

      dyn_i->plt2_offset = ofs;
      x->ofs = ofs + PLT_FULL_ENTRY_SIZE;

      while (h->root.type == bfd_link_hash_indirect
	     || h->root.type == bfd_link_hash_warning)
	h = (struct elf_link_hash_entry *) h->root.u.i.link;
      dyn_i->h->plt.offset = ofs;
    }
  return true;
}

/* Allocate all the PLTOFF entries requested by relocations and
   plt entries.  We can't share space with allocated FPTR entries,
   because the latter are not necessarily addressable by the GP.
   ??? Relaxation might be able to determine that they are.  */

static bool
allocate_pltoff_entries (struct elf32_ia64_dyn_sym_info *dyn_i,
			 void * data)
{
  struct elf32_ia64_allocate_data *x = (struct elf32_ia64_allocate_data *)data;

  if (dyn_i->want_pltoff)
    {
      dyn_i->pltoff_offset = x->ofs;
      x->ofs += 16;
    }
  return true;
}

/* Allocate dynamic relocations for those symbols that turned out
   to be dynamic.  */

static bool
allocate_dynrel_entries (struct elf32_ia64_dyn_sym_info *dyn_i,
			 void * data)
{
  struct elf32_ia64_allocate_data *x = (struct elf32_ia64_allocate_data *)data;
  struct elf32_ia64_link_hash_table *ia64_info;
  struct elf32_ia64_dyn_reloc_entry *rent;
  bool dynamic_symbol, shared, resolved_zero;

  ia64_info = elf32_ia64_hash_table (x->info);
  if (ia64_info == NULL)
    return false;

  /* Note that this can't be used in relation to FPTR relocs below.  */
  dynamic_symbol = elf32_ia64_dynamic_symbol_p (dyn_i->h, x->info, 0);

  shared = bfd_link_pic (x->info);
  resolved_zero = (dyn_i->h
		   && ELF_ST_VISIBILITY (dyn_i->h->other)
		   && dyn_i->h->root.type == bfd_link_hash_undefweak);

  /* Take care of the GOT and PLT relocations.  */

  if ((!resolved_zero
       && (dynamic_symbol || shared)
       && (dyn_i->want_got || dyn_i->want_gotx))
      || (dyn_i->want_ltoff_fptr
	  && dyn_i->h
	  && dyn_i->h->dynindx != -1))
    {
      if (!dyn_i->want_ltoff_fptr
	  || !bfd_link_pie (x->info)
	  || dyn_i->h == NULL
	  || dyn_i->h->root.type != bfd_link_hash_undefweak)
	ia64_info->root.srelgot->size += sizeof (Elf32_External_Rela);
    }
  if ((dynamic_symbol || shared) && dyn_i->want_tprel)
    ia64_info->root.srelgot->size += sizeof (Elf32_External_Rela);
  if (dynamic_symbol && dyn_i->want_dtpmod)
    ia64_info->root.srelgot->size += sizeof (Elf32_External_Rela);
  if (dynamic_symbol && dyn_i->want_dtprel)
    ia64_info->root.srelgot->size += sizeof (Elf32_External_Rela);

  if (x->only_got)
    return true;

  if (ia64_info->rel_fptr_sec && dyn_i->want_fptr)
    {
      if (dyn_i->h == NULL || dyn_i->h->root.type != bfd_link_hash_undefweak)
	ia64_info->rel_fptr_sec->size += sizeof (Elf32_External_Rela);
    }

  if (!resolved_zero && dyn_i->want_pltoff)
    {
      bfd_size_type t = 0;

      /* Dynamic symbols get one IPLT relocation.  Local symbols in
	 shared libraries get two REL relocations.  Local symbols in
	 main applications get nothing.  */
      if (dynamic_symbol)
	t = sizeof (Elf32_External_Rela);
      else if (shared)
	t = 2 * sizeof (Elf32_External_Rela);

      ia64_info->rel_pltoff_sec->size += t;
    }

  /* Take care of the normal data relocations.  */

  for (rent = dyn_i->reloc_entries; rent; rent = rent->next)
    {
      int count = rent->count;

      switch (rent->type)
	{
	case R_IA64_FPTR32LSB:
	case R_IA64_FPTR64LSB:
	  /* Allocate one iff !want_fptr and not PIE, which by this point
	     will be true only if we're actually allocating one statically
	     in the main executable.  Position independent executables
	     need a relative reloc.  */
	  if (dyn_i->want_fptr && !bfd_link_pie (x->info))
	    continue;
	  break;
	case R_IA64_PCREL32LSB:
	case R_IA64_PCREL64LSB:
	  if (!dynamic_symbol)
	    continue;
	  break;
	case R_IA64_DIR32LSB:
	case R_IA64_DIR64LSB:
	  if (!dynamic_symbol && !shared)
	    continue;
	  break;
	case R_IA64_IPLTLSB:
	  if (!dynamic_symbol && !shared)
	    continue;
	  /* Use two REL relocations for IPLT relocations
	     against local symbols.  */
	  if (!dynamic_symbol)
	    count *= 2;
	  break;
	case R_IA64_DTPREL32LSB:
	case R_IA64_TPREL64LSB:
	case R_IA64_DTPREL64LSB:
	case R_IA64_DTPMOD64LSB:
	  break;
	default:
	  abort ();
	}
      if (rent->reltext)
	x->info->flags |= DF_TEXTREL;
      rent->srel->size += sizeof (Elf32_External_Rela) * count;
    }

  return true;
}

static bool
elf32_ia64_adjust_dynamic_symbol (struct bfd_link_info *info ATTRIBUTE_UNUSED,
				  struct elf_link_hash_entry *h)
{
  /* ??? Undefined symbols with PLT entries should be re-defined
     to be the PLT entry.  */

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

  /* If this is a reference to a symbol defined by a dynamic object which
     is not a function, we might allocate the symbol in our .dynbss section
     and allocate a COPY dynamic relocation.

     But IA-64 code is canonically PIC, so as a rule we can avoid this sort
     of hackery.  */

  return true;
}

static bool
elf32_ia64_late_size_sections (bfd *output_bfd ATTRIBUTE_UNUSED,
			       struct bfd_link_info *info)
{
  struct elf32_ia64_allocate_data data;
  struct elf32_ia64_link_hash_table *ia64_info;
  asection *sec;
  bfd *dynobj;

  ia64_info = elf32_ia64_hash_table (info);
  if (ia64_info == NULL)
    return false;
  dynobj = ia64_info->root.dynobj;
  if (dynobj == NULL)
    return true;
  ia64_info->self_dtpmod_offset = (bfd_vma) -1;
  data.info = info;

  /* Set the contents of the .interp section to the interpreter.  */
  if (ia64_info->root.dynamic_sections_created
      && bfd_link_executable (info) && !info->nointerp)
    {
      sec = ia64_info->root.interp;
      BFD_ASSERT (sec != NULL);
      sec->contents = (bfd_byte *) ELF_DYNAMIC_INTERPRETER;
      sec->alloced = 1;
      sec->size = strlen (ELF_DYNAMIC_INTERPRETER) + 1;
    }

  /* Allocate the GOT entries.  */

  if (ia64_info->root.sgot)
    {
      data.ofs = 0;
      elf32_ia64_dyn_sym_traverse (ia64_info, allocate_global_data_got, &data);
      elf32_ia64_dyn_sym_traverse (ia64_info, allocate_global_fptr_got, &data);
      elf32_ia64_dyn_sym_traverse (ia64_info, allocate_local_got, &data);
      ia64_info->root.sgot->size = data.ofs;
    }

  /* Allocate the FPTR entries.  */

  if (ia64_info->fptr_sec)
    {
      data.ofs = 0;
      elf32_ia64_dyn_sym_traverse (ia64_info, allocate_fptr, &data);
      ia64_info->fptr_sec->size = data.ofs;
    }

  /* Now that we've seen all of the input files, we can decide which
     symbols need plt entries.  Allocate the minimal PLT entries first.
     We do this even though dynamic_sections_created may be FALSE, because
     this has the side-effect of clearing want_plt and want_plt2.  */

  data.ofs = 0;
  elf32_ia64_dyn_sym_traverse (ia64_info, allocate_plt_entries, &data);

  ia64_info->minplt_entries = 0;
  if (data.ofs)
    {
      ia64_info->minplt_entries
	= (data.ofs - PLT_HEADER_SIZE) / PLT_MIN_ENTRY_SIZE;
    }

  /* Align the pointer for the plt2 entries.  */
  data.ofs = (data.ofs + 31) & (bfd_vma) -32;

  elf32_ia64_dyn_sym_traverse (ia64_info, allocate_plt2_entries, &data);
  if (data.ofs != 0 || ia64_info->root.dynamic_sections_created)
    {
      /* FIXME: we always reserve the memory for dynamic linker even if
	 there are no PLT entries since dynamic linker may assume the
	 reserved memory always exists.  */

      BFD_ASSERT (ia64_info->root.dynamic_sections_created);

      ia64_info->root.splt->size = data.ofs;

      /* If we've got a .plt, we need some extra memory for the dynamic
	 linker.  We stuff these in .got.plt.  */
      ia64_info->root.sgotplt->size = 8 * PLT_RESERVED_WORDS;
    }

  /* Allocate the PLTOFF entries.  */

  if (ia64_info->pltoff_sec)
    {
      data.ofs = 0;
      elf32_ia64_dyn_sym_traverse (ia64_info, allocate_pltoff_entries, &data);
      ia64_info->pltoff_sec->size = data.ofs;
    }

  if (ia64_info->root.dynamic_sections_created)
    {
      /* Allocate space for the dynamic relocations that turned out to be
	 required.  */

      if (bfd_link_pic (info) && ia64_info->self_dtpmod_offset != (bfd_vma) -1)
	ia64_info->root.srelgot->size += sizeof (Elf32_External_Rela);
      data.only_got = false;
      elf32_ia64_dyn_sym_traverse (ia64_info, allocate_dynrel_entries, &data);
    }

  /* We have now determined the sizes of the various dynamic sections.
     Allocate memory for them.  */
  for (sec = dynobj->sections; sec != NULL; sec = sec->next)
    {
      bool strip;

      if (!(sec->flags & SEC_LINKER_CREATED))
	continue;

      /* If we don't need this section, strip it from the output file.
	 There were several sections primarily related to dynamic
	 linking that must be create before the linker maps input
	 sections to output sections.  The linker does that before
	 bfd_elf_size_dynamic_sections is called, and it is that
	 function which decides whether anything needs to go into
	 these sections.  */

      strip = (sec->size == 0);

      if (sec == ia64_info->root.sgot)
	strip = false;
      else if (sec == ia64_info->root.srelgot)
	{
	  if (strip)
	    ia64_info->root.srelgot = NULL;
	  else
	    /* We use the reloc_count field as a counter if we need to
	       copy relocs into the output file.  */
	    sec->reloc_count = 0;
	}
      else if (sec == ia64_info->fptr_sec)
	{
	  if (strip)
	    ia64_info->fptr_sec = NULL;
	}
      else if (sec == ia64_info->rel_fptr_sec)
	{
	  if (strip)
	    ia64_info->rel_fptr_sec = NULL;
	  else
	    /* We use the reloc_count field as a counter if we need to
	       copy relocs into the output file.  */
	    sec->reloc_count = 0;
	}
      else if (sec == ia64_info->root.splt)
	{
	  if (strip)
	    ia64_info->root.splt = NULL;
	}
      else if (sec == ia64_info->pltoff_sec)
	{
	  if (strip)
	    ia64_info->pltoff_sec = NULL;
	}
      else if (sec == ia64_info->rel_pltoff_sec)
	{
	  if (strip)
	    ia64_info->rel_pltoff_sec = NULL;
	  else
	    {
	      ia64_info->root.dt_jmprel_required = true;
	      /* We use the reloc_count field as a counter if we need to
		 copy relocs into the output file.  */
	      sec->reloc_count = 0;
	    }
	}
      else
	{
	  const char *name;

	  /* It's OK to base decisions on the section name, because none
	     of the dynobj section names depend upon the input files.  */
	  name = bfd_section_name (sec);

	  if (strcmp (name, ".got.plt") == 0)
	    strip = false;
	  else if (startswith (name, ".rel"))
	    {
	      if (!strip)
		{
		  /* We use the reloc_count field as a counter if we need to
		     copy relocs into the output file.  */
		  sec->reloc_count = 0;
		}
	    }
	  else
	    continue;
	}

      if (strip)
	sec->flags |= SEC_EXCLUDE;
      else
	{
	  /* Allocate memory for the section contents.  */
	  sec->contents = (bfd_byte *) bfd_zalloc (dynobj, sec->size);
	  if (sec->contents == NULL && sec->size != 0)
	    return false;
	  sec->alloced = 1;
	}
    }

  if (ia64_info->root.dynamic_sections_created)
    {
      /* Add some entries to the .dynamic section.  We fill in the values
	 later (in finish_dynamic_sections) but we must add the entries now
	 so that we get the correct size for the .dynamic section.  */

#define add_dynamic_entry(TAG, VAL) \
  _bfd_elf_add_dynamic_entry (info, TAG, VAL)

      if (!_bfd_elf_add_dynamic_tags (output_bfd, info, true))
	return false;

      if (!add_dynamic_entry (DT_IA_64_PLT_RESERVE, 0))
	return false;
    }

  /* ??? Perhaps force __gp local.  */

  return true;
}

static void
elf32_ia64_install_dyn_reloc (bfd *abfd, struct bfd_link_info *info,
			      asection *sec, asection *srel,
			      bfd_vma offset, unsigned int type,
			      long dynindx, bfd_vma addend)
{
  Elf_Internal_Rela outrel;
  bfd_byte *loc;

  BFD_ASSERT (dynindx != -1);
  outrel.r_info = ELF32_R_INFO (dynindx, type);
  outrel.r_addend = addend;
  outrel.r_offset = _bfd_elf_section_offset (abfd, info, sec, offset);
  if (outrel.r_offset >= (bfd_vma) -2)
    {
      /* Run for the hills.  We shouldn't be outputting a relocation
	 for this.  So do what everyone else does and output a no-op.  */
      outrel.r_info = ELF32_R_INFO (0, R_IA64_NONE);
      outrel.r_addend = 0;
      outrel.r_offset = 0;
    }
  else
    outrel.r_offset += sec->output_section->vma + sec->output_offset;

  loc = srel->contents;
  loc += srel->reloc_count++ * sizeof (Elf32_External_Rela);
  bfd_elf32_swap_reloca_out (abfd, &outrel, loc);
  BFD_ASSERT (sizeof (Elf32_External_Rela) * srel->reloc_count <= srel->size);
}

/* Store an entry for target address TARGET_ADDR in the linkage table
   and return the gp-relative address of the linkage table entry.  */

static bfd_vma
set_got_entry (bfd *abfd, struct bfd_link_info *info,
	       struct elf32_ia64_dyn_sym_info *dyn_i,
	       long dynindx, bfd_vma addend, bfd_vma value,
	       unsigned int dyn_r_type)
{
  struct elf32_ia64_link_hash_table *ia64_info;
  asection *got_sec;
  bool done;
  bfd_vma got_offset;

  ia64_info = elf32_ia64_hash_table (info);
  if (ia64_info == NULL)
    return 0;

  got_sec = ia64_info->root.sgot;

  switch (dyn_r_type)
    {
    case R_IA64_TPREL64LSB:
      done = dyn_i->tprel_done;
      dyn_i->tprel_done = true;
      got_offset = dyn_i->tprel_offset;
      break;
    case R_IA64_DTPMOD64LSB:
      if (dyn_i->dtpmod_offset != ia64_info->self_dtpmod_offset)
	{
	  done = dyn_i->dtpmod_done;
	  dyn_i->dtpmod_done = true;
	}
      else
	{
	  done = ia64_info->self_dtpmod_done;
	  ia64_info->self_dtpmod_done = true;
	  dynindx = 0;
	}
      got_offset = dyn_i->dtpmod_offset;
      break;
    case R_IA64_DTPREL32LSB:
    case R_IA64_DTPREL64LSB:
      done = dyn_i->dtprel_done;
      dyn_i->dtprel_done = true;
      got_offset = dyn_i->dtprel_offset;
      break;
    default:
      done = dyn_i->got_done;
      dyn_i->got_done = true;
      got_offset = dyn_i->got_offset;
      break;
    }

  BFD_ASSERT ((got_offset & 7) == 0);

  if (! done)
    {
      /* Store the target address in the linkage table entry.  */
      bfd_put_64 (abfd, value, got_sec->contents + got_offset);

      /* Install a dynamic relocation if needed.  */
      if (((bfd_link_pic (info)
	    && (!dyn_i->h
		|| ELF_ST_VISIBILITY (dyn_i->h->other) == STV_DEFAULT
		|| dyn_i->h->root.type != bfd_link_hash_undefweak)
	    && dyn_r_type != R_IA64_DTPREL32LSB
	    && dyn_r_type != R_IA64_DTPREL64LSB)
	   || elf32_ia64_dynamic_symbol_p (dyn_i->h, info, dyn_r_type)
	   || (dynindx != -1
	       && (dyn_r_type == R_IA64_FPTR32LSB
		   || dyn_r_type == R_IA64_FPTR64LSB)))
	  && (!dyn_i->want_ltoff_fptr
	      || !bfd_link_pie (info)
	      || !dyn_i->h
	      || dyn_i->h->root.type != bfd_link_hash_undefweak))
	{
	  if (dynindx == -1
	      && dyn_r_type != R_IA64_TPREL64LSB
	      && dyn_r_type != R_IA64_DTPMOD64LSB
	      && dyn_r_type != R_IA64_DTPREL32LSB
	      && dyn_r_type != R_IA64_DTPREL64LSB)
	    {
	      dyn_r_type = R_IA64_REL32LSB;
	      dynindx = 0;
	      addend = value;
	    }

	  if (bfd_big_endian (abfd))
	    {
	      switch (dyn_r_type)
		{
		case R_IA64_REL32LSB:
		  dyn_r_type = R_IA64_REL32MSB;
		  break;
		case R_IA64_DIR32LSB:
		  dyn_r_type = R_IA64_DIR32MSB;
		  break;
		case R_IA64_FPTR32LSB:
		  dyn_r_type = R_IA64_FPTR32MSB;
		  break;
		case R_IA64_DTPREL32LSB:
		  dyn_r_type = R_IA64_DTPREL32MSB;
		  break;
		case R_IA64_REL64LSB:
		  dyn_r_type = R_IA64_REL64MSB;
		  break;
		case R_IA64_DIR64LSB:
		  dyn_r_type = R_IA64_DIR64MSB;
		  break;
		case R_IA64_FPTR64LSB:
		  dyn_r_type = R_IA64_FPTR64MSB;
		  break;
		case R_IA64_TPREL64LSB:
		  dyn_r_type = R_IA64_TPREL64MSB;
		  break;
		case R_IA64_DTPMOD64LSB:
		  dyn_r_type = R_IA64_DTPMOD64MSB;
		  break;
		case R_IA64_DTPREL64LSB:
		  dyn_r_type = R_IA64_DTPREL64MSB;
		  break;
		default:
		  BFD_ASSERT (false);
		  break;
		}
	    }

	  elf32_ia64_install_dyn_reloc (abfd, NULL, got_sec,
					ia64_info->root.srelgot,
					got_offset, dyn_r_type,
					dynindx, addend);
	}
    }

  /* Return the address of the linkage table entry.  */
  value = (got_sec->output_section->vma
	   + got_sec->output_offset
	   + got_offset);

  return value;
}

/* Fill in a function descriptor consisting of the function's code
   address and its global pointer.  Return the descriptor's address.  */

static bfd_vma
set_fptr_entry (bfd *abfd, struct bfd_link_info *info,
		struct elf32_ia64_dyn_sym_info *dyn_i,
		bfd_vma value)
{
  struct elf32_ia64_link_hash_table *ia64_info;
  asection *fptr_sec;

  ia64_info = elf32_ia64_hash_table (info);
  if (ia64_info == NULL)
    return 0;

  fptr_sec = ia64_info->fptr_sec;

  if (!dyn_i->fptr_done)
    {
      dyn_i->fptr_done = 1;

      /* Fill in the function descriptor.  */
      bfd_put_64 (abfd, value, fptr_sec->contents + dyn_i->fptr_offset);
      bfd_put_64 (abfd, _bfd_get_gp_value (abfd),
		  fptr_sec->contents + dyn_i->fptr_offset + 8);
      if (ia64_info->rel_fptr_sec)
	{
	  Elf_Internal_Rela outrel;
	  bfd_byte *loc;

	  if (bfd_little_endian (abfd))
	    outrel.r_info = ELF32_R_INFO (0, R_IA64_IPLTLSB);
	  else
	    outrel.r_info = ELF32_R_INFO (0, R_IA64_IPLTMSB);
	  outrel.r_addend = value;
	  outrel.r_offset = (fptr_sec->output_section->vma
			     + fptr_sec->output_offset
			     + dyn_i->fptr_offset);
	  loc = ia64_info->rel_fptr_sec->contents;
	  loc += ia64_info->rel_fptr_sec->reloc_count++
		 * sizeof (Elf32_External_Rela);
	  bfd_elf32_swap_reloca_out (abfd, &outrel, loc);
	}
    }

  /* Return the descriptor's address.  */
  value = (fptr_sec->output_section->vma
	   + fptr_sec->output_offset
	   + dyn_i->fptr_offset);

  return value;
}

/* Fill in a PLTOFF entry consisting of the function's code address
   and its global pointer.  Return the descriptor's address.  */

static bfd_vma
set_pltoff_entry (bfd *abfd, struct bfd_link_info *info,
		  struct elf32_ia64_dyn_sym_info *dyn_i,
		  bfd_vma value, bool is_plt)
{
  struct elf32_ia64_link_hash_table *ia64_info;
  asection *pltoff_sec;

  ia64_info = elf32_ia64_hash_table (info);
  if (ia64_info == NULL)
    return 0;

  pltoff_sec = ia64_info->pltoff_sec;

  /* Don't do anything if this symbol uses a real PLT entry.  In
     that case, we'll fill this in during finish_dynamic_symbol.  */
  if ((! dyn_i->want_plt || is_plt)
      && !dyn_i->pltoff_done)
    {
      bfd_vma gp = _bfd_get_gp_value (abfd);

      /* Fill in the function descriptor.  */
      bfd_put_64 (abfd, value, pltoff_sec->contents + dyn_i->pltoff_offset);
      bfd_put_64 (abfd, gp, pltoff_sec->contents + dyn_i->pltoff_offset + 8);

      /* Install dynamic relocations if needed.  */
      if (!is_plt
	  && bfd_link_pic (info)
	  && (!dyn_i->h
	      || ELF_ST_VISIBILITY (dyn_i->h->other) == STV_DEFAULT
	      || dyn_i->h->root.type != bfd_link_hash_undefweak))
	{
	  unsigned int dyn_r_type;

	  if (bfd_big_endian (abfd))
	    dyn_r_type = R_IA64_REL32MSB;
	  else
	    dyn_r_type = R_IA64_REL32LSB;

	  elf32_ia64_install_dyn_reloc (abfd, NULL, pltoff_sec,
					ia64_info->rel_pltoff_sec,
					dyn_i->pltoff_offset,
					dyn_r_type, 0, value);
	  elf32_ia64_install_dyn_reloc (abfd, NULL, pltoff_sec,
					ia64_info->rel_pltoff_sec,
					dyn_i->pltoff_offset + ARCH_SIZE / 8,
					dyn_r_type, 0, gp);
	}

      dyn_i->pltoff_done = 1;
    }

  /* Return the descriptor's address.  */
  value = (pltoff_sec->output_section->vma
	   + pltoff_sec->output_offset
	   + dyn_i->pltoff_offset);

  return value;
}

/* Return the base VMA address which should be subtracted from real addresses
   when resolving @tprel() relocation.
   Main program TLS (whose template starts at PT_TLS p_vaddr)
   is assigned offset round(2 * size of pointer, PT_TLS p_align).  */

static bfd_vma
elf32_ia64_tprel_base (struct bfd_link_info *info)
{
  asection *tls_sec = elf_hash_table (info)->tls_sec;
  return tls_sec->vma - align_power ((bfd_vma) ARCH_SIZE / 4,
				     tls_sec->alignment_power);
}

/* Return the base VMA address which should be subtracted from real addresses
   when resolving @dtprel() relocation.
   This is PT_TLS segment p_vaddr.  */

static bfd_vma
elf32_ia64_dtprel_base (struct bfd_link_info *info)
{
  return elf_hash_table (info)->tls_sec->vma;
}

/* Called through qsort to sort the .IA_64.unwind section during a
   non-relocatable link.  Set elf32_ia64_unwind_entry_compare_bfd
   to the output bfd so we can do proper endianness frobbing.  */

static bfd *elf32_ia64_unwind_entry_compare_bfd;

static int
elf32_ia64_unwind_entry_compare (const void * a, const void * b)
{
  bfd_vma av, bv;

  av = bfd_get_64 (elf32_ia64_unwind_entry_compare_bfd, a);
  bv = bfd_get_64 (elf32_ia64_unwind_entry_compare_bfd, b);

  return (av < bv ? -1 : av > bv ? 1 : 0);
}

/* Make sure we've got ourselves a nice fat __gp value.  */
static bool
elf32_ia64_choose_gp (bfd *abfd, struct bfd_link_info *info, bool final)
{
  bfd_vma min_vma = (bfd_vma) -1, max_vma = 0;
  bfd_vma min_short_vma = min_vma, max_short_vma = 0;
  struct elf_link_hash_entry *gp;
  bfd_vma gp_val;
  asection *os;
  struct elf32_ia64_link_hash_table *ia64_info;

  ia64_info = elf32_ia64_hash_table (info);
  if (ia64_info == NULL)
    return false;

  /* Find the min and max vma of all sections marked short.  Also collect
     min and max vma of any type, for use in selecting a nice gp.  */
  for (os = abfd->sections; os ; os = os->next)
    {
      bfd_vma lo, hi;

      if ((os->flags & SEC_ALLOC) == 0)
	continue;

      lo = os->vma;
      /* When this function is called from elf32_ia64_final_link
	 the correct value to use is os->size.  When called from
	 elf32_ia64_relax_section we are in the middle of section
	 sizing; some sections will already have os->size set, others
	 will have os->size zero and os->rawsize the previous size.  */
      hi = os->vma + (!final && os->rawsize ? os->rawsize : os->size);
      if (hi < lo)
	hi = (bfd_vma) -1;

      if (min_vma > lo)
	min_vma = lo;
      if (max_vma < hi)
	max_vma = hi;
      if (os->flags & SEC_SMALL_DATA)
	{
	  if (min_short_vma > lo)
	    min_short_vma = lo;
	  if (max_short_vma < hi)
	    max_short_vma = hi;
	}
    }

  if (ia64_info->min_short_sec)
    {
      if (min_short_vma
	  > (ia64_info->min_short_sec->vma
	     + ia64_info->min_short_offset))
	min_short_vma = (ia64_info->min_short_sec->vma
			 + ia64_info->min_short_offset);
      if (max_short_vma
	  < (ia64_info->max_short_sec->vma
	     + ia64_info->max_short_offset))
	max_short_vma = (ia64_info->max_short_sec->vma
			 + ia64_info->max_short_offset);
    }

  /* See if the user wants to force a value.  */
  gp = elf_link_hash_lookup (elf_hash_table (info), "__gp", false,
			     false, false);

  if (gp
      && (gp->root.type == bfd_link_hash_defined
	  || gp->root.type == bfd_link_hash_defweak))
    {
      asection *gp_sec = gp->root.u.def.section;
      gp_val = (gp->root.u.def.value
		+ gp_sec->output_section->vma
		+ gp_sec->output_offset);
    }
  else
    {
      /* Pick a sensible value.  */

      if (ia64_info->min_short_sec)
	{
	  bfd_vma short_range = max_short_vma - min_short_vma;

	  /* If min_short_sec is set, pick one in the middle bewteen
	     min_short_vma and max_short_vma.  */
	  if (short_range >= 0x400000)
	    goto overflow;
	  gp_val = min_short_vma + short_range / 2;
	}
      else
	{
	  asection *got_sec = ia64_info->root.sgot;

	  /* Start with just the address of the .got.  */
	  if (got_sec)
	    gp_val = got_sec->output_section->vma;
	  else if (max_short_vma != 0)
	    gp_val = min_short_vma;
	  else if (max_vma - min_vma < 0x200000)
	    gp_val = min_vma;
	  else
	    gp_val = max_vma - 0x200000 + 8;
	}

      /* If it is possible to address the entire image, but we
	 don't with the choice above, adjust.  */
      if (max_vma - min_vma < 0x400000
	  && (max_vma - gp_val >= 0x200000
	      || gp_val - min_vma > 0x200000))
	gp_val = min_vma + 0x200000;
      else if (max_short_vma != 0)
	{
	  /* If we don't cover all the short data, adjust.  */
	  if (max_short_vma - gp_val >= 0x200000)
	    gp_val = min_short_vma + 0x200000;

	  /* If we're addressing stuff past the end, adjust back.  */
	  if (gp_val > max_vma)
	    gp_val = max_vma - 0x200000 + 8;
	}
    }

  /* Validate whether all SHF_IA_64_SHORT sections are within
     range of the chosen GP.  */

  if (max_short_vma != 0)
    {
      if (max_short_vma - min_short_vma >= 0x400000)
	{
	overflow:
	  _bfd_error_handler
	    /* xgettext:c-format */
	    (_("%pB: short data segment overflowed (%#" PRIx64 " >= 0x400000)"),
	     abfd, (uint64_t) (max_short_vma - min_short_vma));
	  return false;
	}
      else if ((gp_val > min_short_vma
		&& gp_val - min_short_vma > 0x200000)
	       || (gp_val < max_short_vma
		   && max_short_vma - gp_val >= 0x200000))
	{
	  _bfd_error_handler
	    (_("%pB: __gp does not cover short data segment"), abfd);
	  return false;
	}
    }

  _bfd_set_gp_value (abfd, gp_val);

  return true;
}

static bool
elf32_ia64_final_link (bfd *abfd, struct bfd_link_info *info)
{
  struct elf32_ia64_link_hash_table *ia64_info;
  asection *unwind_output_sec;

  ia64_info = elf32_ia64_hash_table (info);
  if (ia64_info == NULL)
    return false;

  /* Make sure we've got ourselves a nice fat __gp value.  */
  if (!bfd_link_relocatable (info))
    {
      bfd_vma gp_val;
      struct elf_link_hash_entry *gp;

      /* We assume after gp is set, section size will only decrease. We
	 need to adjust gp for it.  */
      _bfd_set_gp_value (abfd, 0);
      if (! elf32_ia64_choose_gp (abfd, info, true))
	return false;
      gp_val = _bfd_get_gp_value (abfd);

      gp = elf_link_hash_lookup (elf_hash_table (info), "__gp", false,
				 false, false);
      if (gp)
	{
	  gp->root.type = bfd_link_hash_defined;
	  gp->root.u.def.value = gp_val;
	  gp->root.u.def.section = bfd_abs_section_ptr;
	}
    }

  /* If we're producing a final executable, we need to sort the contents
     of the .IA_64.unwind section.  Force this section to be relocated
     into memory rather than written immediately to the output file.  */
  unwind_output_sec = NULL;
  if (!bfd_link_relocatable (info))
    {
      asection *s = bfd_get_section_by_name (abfd, ELF_STRING_ia64_unwind);
      if (s)
	{
	  unwind_output_sec = s->output_section;
	  unwind_output_sec->contents
	    = bfd_malloc (unwind_output_sec->size);
	  if (unwind_output_sec->contents == NULL)
	    return false;
	}
    }

  /* Invoke the regular ELF backend linker to do all the work.  */
  if (!bfd_elf_final_link (abfd, info))
    return false;

  if (unwind_output_sec)
    {
      elf32_ia64_unwind_entry_compare_bfd = abfd;
      qsort (unwind_output_sec->contents,
	     (size_t) (unwind_output_sec->size / 24),
	     24,
	     elf32_ia64_unwind_entry_compare);

      if (! bfd_set_section_contents (abfd, unwind_output_sec,
				      unwind_output_sec->contents, (bfd_vma) 0,
				      unwind_output_sec->size))
	return false;
    }

  return true;
}

static int
elf32_ia64_relocate_section (bfd *output_bfd,
			     struct bfd_link_info *info,
			     bfd *input_bfd,
			     asection *input_section,
			     bfd_byte *contents,
			     Elf_Internal_Rela *relocs,
			     Elf_Internal_Sym *local_syms,
			     asection **local_sections)
{
  struct elf32_ia64_link_hash_table *ia64_info;
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;
  asection *srel;
  bool ret_val = true;	/* for non-fatal errors */
  bfd_vma gp_val;

  symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  ia64_info = elf32_ia64_hash_table (info);
  if (ia64_info == NULL)
    return false;

  /* Infect various flags from the input section to the output section.  */
  if (bfd_link_relocatable (info))
    {
      bfd_vma flags;

      flags = elf_section_data(input_section)->this_hdr.sh_flags;
      flags &= SHF_IA_64_NORECOV;

      elf_section_data(input_section->output_section)
	->this_hdr.sh_flags |= flags;
    }

  gp_val = _bfd_get_gp_value (output_bfd);
  srel = get_reloc_section (input_bfd, ia64_info, input_section, false);

  rel = relocs;
  relend = relocs + input_section->reloc_count;
  for (; rel < relend; ++rel)
    {
      struct elf_link_hash_entry *h;
      struct elf32_ia64_dyn_sym_info *dyn_i;
      bfd_reloc_status_type r;
      reloc_howto_type *howto;
      unsigned long r_symndx;
      Elf_Internal_Sym *sym;
      unsigned int r_type;
      bfd_vma value;
      asection *sym_sec;
      bfd_byte *hit_addr;
      bool dynamic_symbol_p;
      bool undef_weak_ref;

      r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type > R_IA64_MAX_RELOC_CODE)
	{
	  /* xgettext:c-format */
	  _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			      input_bfd, (int) r_type);
	  bfd_set_error (bfd_error_bad_value);
	  ret_val = false;
	  continue;
	}

      howto = ia64_elf_lookup_howto (r_type);
      if (howto == NULL)
	{
	  ret_val = false;
	  continue;
	}

      r_symndx = ELF32_R_SYM (rel->r_info);
      h = NULL;
      sym = NULL;
      sym_sec = NULL;
      undef_weak_ref = false;

      if (r_symndx < symtab_hdr->sh_info)
	{
	  /* Reloc against local symbol.  */
	  asection *msec;
	  sym = local_syms + r_symndx;
	  sym_sec = local_sections[r_symndx];
	  msec = sym_sec;
	  value = _bfd_elf_rela_local_sym (output_bfd, sym, &msec, rel);
	  if (!bfd_link_relocatable (info)
	      && (sym_sec->flags & SEC_MERGE) != 0
	      && ELF_ST_TYPE (sym->st_info) == STT_SECTION
	      && sym_sec->sec_info_type == SEC_INFO_TYPE_MERGE)
	    {
	      struct elf32_ia64_local_hash_entry *loc_h;

	      loc_h = get_local_sym_hash (ia64_info, input_bfd, rel, false);
	      if (loc_h && ! loc_h->sec_merge_done)
		{
		  struct elf32_ia64_dyn_sym_info *dynent;
		  unsigned int count;

		  for (count = loc_h->count, dynent = loc_h->info;
		       count != 0;
		       count--, dynent++)
		    {
		      msec = sym_sec;
		      dynent->addend =
			_bfd_merged_section_offset (output_bfd, &msec,
						    elf_section_data (msec)->
						    sec_info,
						    sym->st_value
						    + dynent->addend);
		      dynent->addend -= sym->st_value;
		      dynent->addend += msec->output_section->vma
					+ msec->output_offset
					- sym_sec->output_section->vma
					- sym_sec->output_offset;
		    }

		  /* We may have introduced duplicated entries. We need
		     to remove them properly.  */
		  count = sort_dyn_sym_info (loc_h->info, loc_h->count);
		  if (count != loc_h->count)
		    {
		      loc_h->count = count;
		      loc_h->sorted_count = count;
		    }

		  loc_h->sec_merge_done = 1;
		}
	    }
	}
      else
	{
	  bool unresolved_reloc;
	  bool warned, ignored;
	  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (input_bfd);

	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sym_sec, value,
				   unresolved_reloc, warned, ignored);

	  if (h->root.type == bfd_link_hash_undefweak)
	    undef_weak_ref = true;
	  else if (warned || (ignored && bfd_link_executable (info)))
	    continue;
	}

      if (sym_sec != NULL && discarded_section (sym_sec))
	RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					 rel, 1, relend, R_IA64_NONE,
					 howto, 0, contents);

      if (bfd_link_relocatable (info))
	continue;

      hit_addr = contents + rel->r_offset;
      value += rel->r_addend;
      dynamic_symbol_p = elf32_ia64_dynamic_symbol_p (h, info, r_type);

      switch (r_type)
	{
	case R_IA64_NONE:
	case R_IA64_LDXMOV:
	  continue;

	case R_IA64_IMM14:
	case R_IA64_IMM22:
	case R_IA64_IMM64:
	case R_IA64_DIR32MSB:
	case R_IA64_DIR32LSB:
	case R_IA64_DIR64MSB:
	case R_IA64_DIR64LSB:
	  /* Install a dynamic relocation for this reloc.  */
	  if ((dynamic_symbol_p || bfd_link_pic (info))
	      && r_symndx != STN_UNDEF
	      && (input_section->flags & SEC_ALLOC) != 0)
	    {
	      unsigned int dyn_r_type;
	      long dynindx;
	      bfd_vma addend;

	      BFD_ASSERT (srel != NULL);

	      switch (r_type)
		{
		case R_IA64_IMM14:
		case R_IA64_IMM22:
		case R_IA64_IMM64:
		  /* ??? People shouldn't be doing non-pic code in
		     shared libraries nor dynamic executables.  */
		  _bfd_error_handler
		    /* xgettext:c-format */
		    (_("%pB: non-pic code with imm relocation against dynamic symbol `%s'"),
		     input_bfd,
		     h ? h->root.root.string
		       : bfd_elf_sym_name (input_bfd, symtab_hdr, sym,
					   sym_sec));
		  ret_val = false;
		  continue;

		default:
		  break;
		}

	      /* If we don't need dynamic symbol lookup, find a
		 matching RELATIVE relocation.  */
	      dyn_r_type = r_type;
	      if (dynamic_symbol_p)
		{
		  dynindx = h->dynindx;
		  addend = rel->r_addend;
		  value = 0;
		}
	      else
		{
		  switch (r_type)
		    {
		    case R_IA64_DIR32MSB:
		      dyn_r_type = R_IA64_REL32MSB;
		      break;
		    case R_IA64_DIR32LSB:
		      dyn_r_type = R_IA64_REL32LSB;
		      break;
		    case R_IA64_DIR64MSB:
		      dyn_r_type = R_IA64_REL64MSB;
		      break;
		    case R_IA64_DIR64LSB:
		      dyn_r_type = R_IA64_REL64LSB;
		      break;

		    default:
		      break;
		    }
		  dynindx = 0;
		  addend = value;
		}

	      elf32_ia64_install_dyn_reloc (output_bfd, info, input_section,
					    srel, rel->r_offset, dyn_r_type,
					    dynindx, addend);
	    }
	  /* Fall through.  */

	case R_IA64_LTV32MSB:
	case R_IA64_LTV32LSB:
	case R_IA64_LTV64MSB:
	case R_IA64_LTV64LSB:
	  r = ia64_elf_install_value (hit_addr, value, r_type);
	  break;

	case R_IA64_GPREL22:
	case R_IA64_GPREL64I:
	case R_IA64_GPREL32MSB:
	case R_IA64_GPREL32LSB:
	case R_IA64_GPREL64MSB:
	case R_IA64_GPREL64LSB:
	  if (dynamic_symbol_p)
	    {
	      _bfd_error_handler
		/* xgettext:c-format */
		(_("%pB: @gprel relocation against dynamic symbol %s"),
		 input_bfd,
		 h ? h->root.root.string
		   : bfd_elf_sym_name (input_bfd, symtab_hdr, sym,
				       sym_sec));
	      ret_val = false;
	      continue;
	    }
	  value -= gp_val;
	  r = ia64_elf_install_value (hit_addr, value, r_type);
	  break;

	case R_IA64_LTOFF22:
	case R_IA64_LTOFF22X:
	case R_IA64_LTOFF64I:
	  dyn_i = get_dyn_sym_info (ia64_info, h, input_bfd, rel, false);
	  value = set_got_entry (input_bfd, info, dyn_i, (h ? h->dynindx : -1),
				 rel->r_addend, value, R_IA64_DIR32LSB);
	  value -= gp_val;
	  r = ia64_elf_install_value (hit_addr, value, r_type);
	  break;

	case R_IA64_PLTOFF22:
	case R_IA64_PLTOFF64I:
	case R_IA64_PLTOFF64MSB:
	case R_IA64_PLTOFF64LSB:
	  dyn_i = get_dyn_sym_info (ia64_info, h, input_bfd, rel, false);
	  value = set_pltoff_entry (output_bfd, info, dyn_i, value, false);
	  value -= gp_val;
	  r = ia64_elf_install_value (hit_addr, value, r_type);
	  break;

	case R_IA64_FPTR64I:
	case R_IA64_FPTR32MSB:
	case R_IA64_FPTR32LSB:
	case R_IA64_FPTR64MSB:
	case R_IA64_FPTR64LSB:
	  dyn_i = get_dyn_sym_info (ia64_info, h, input_bfd, rel, false);
	  if (dyn_i->want_fptr)
	    {
	      if (!undef_weak_ref)
		value = set_fptr_entry (output_bfd, info, dyn_i, value);
	    }
	  if (!dyn_i->want_fptr || bfd_link_pie (info))
	    {
	      long dynindx;
	      unsigned int dyn_r_type = r_type;
	      bfd_vma addend = rel->r_addend;

	      /* Otherwise, we expect the dynamic linker to create
		 the entry.  */

	      if (dyn_i->want_fptr)
		{
		  if (r_type == R_IA64_FPTR64I)
		    {
		      /* We can't represent this without a dynamic symbol.
			 Adjust the relocation to be against an output
			 section symbol, which are always present in the
			 dynamic symbol table.  */
		      /* ??? People shouldn't be doing non-pic code in
			 shared libraries.  Hork.  */
		      _bfd_error_handler
			(_("%pB: linking non-pic code in a position independent executable"),
			 input_bfd);
		      ret_val = false;
		      continue;
		    }
		  dynindx = 0;
		  addend = value;
		  dyn_r_type = r_type + R_IA64_REL32LSB - R_IA64_FPTR32LSB;
		}
	      else if (h)
		{
		  if (h->dynindx != -1)
		    dynindx = h->dynindx;
		  else
		    dynindx = (_bfd_elf_link_lookup_local_dynindx
			       (info, h->root.u.def.section->owner,
				global_sym_index (h)));
		  value = 0;
		}
	      else
		{
		  dynindx = (_bfd_elf_link_lookup_local_dynindx
			     (info, input_bfd, (long) r_symndx));
		  value = 0;
		}

	      elf32_ia64_install_dyn_reloc (output_bfd, info, input_section,
					    srel, rel->r_offset, dyn_r_type,
					    dynindx, addend);
	    }

	  r = ia64_elf_install_value (hit_addr, value, r_type);
	  break;

	case R_IA64_LTOFF_FPTR22:
	case R_IA64_LTOFF_FPTR64I:
	case R_IA64_LTOFF_FPTR32MSB:
	case R_IA64_LTOFF_FPTR32LSB:
	case R_IA64_LTOFF_FPTR64MSB:
	case R_IA64_LTOFF_FPTR64LSB:
	  {
	    long dynindx;

	    dyn_i = get_dyn_sym_info (ia64_info, h, input_bfd, rel, false);
	    if (dyn_i->want_fptr)
	      {
		BFD_ASSERT (h == NULL || h->dynindx == -1);
		if (!undef_weak_ref)
		  value = set_fptr_entry (output_bfd, info, dyn_i, value);
		dynindx = -1;
	      }
	    else
	      {
		/* Otherwise, we expect the dynamic linker to create
		   the entry.  */
		if (h)
		  {
		    if (h->dynindx != -1)
		      dynindx = h->dynindx;
		    else
		      dynindx = (_bfd_elf_link_lookup_local_dynindx
				 (info, h->root.u.def.section->owner,
				  global_sym_index (h)));
		  }
		else
		  dynindx = (_bfd_elf_link_lookup_local_dynindx
			     (info, input_bfd, (long) r_symndx));
		value = 0;
	      }

	    value = set_got_entry (output_bfd, info, dyn_i, dynindx,
				   rel->r_addend, value, R_IA64_FPTR32LSB);
	    value -= gp_val;
	    r = ia64_elf_install_value (hit_addr, value, r_type);
	  }
	  break;

	case R_IA64_PCREL32MSB:
	case R_IA64_PCREL32LSB:
	case R_IA64_PCREL64MSB:
	case R_IA64_PCREL64LSB:
	  /* Install a dynamic relocation for this reloc.  */
	  if (dynamic_symbol_p && r_symndx != STN_UNDEF)
	    {
	      BFD_ASSERT (srel != NULL);

	      elf32_ia64_install_dyn_reloc (output_bfd, info, input_section,
					    srel, rel->r_offset, r_type,
					    h->dynindx, rel->r_addend);
	    }
	  goto finish_pcrel;

	case R_IA64_PCREL21B:
	case R_IA64_PCREL60B:
	  /* We should have created a PLT entry for any dynamic symbol.  */
	  dyn_i = NULL;
	  if (h)
	    dyn_i = get_dyn_sym_info (ia64_info, h, NULL, NULL, false);

	  if (dyn_i && dyn_i->want_plt2)
	    {
	      /* Should have caught this earlier.  */
	      BFD_ASSERT (rel->r_addend == 0);

	      value = (ia64_info->root.splt->output_section->vma
		       + ia64_info->root.splt->output_offset
		       + dyn_i->plt2_offset);
	    }
	  else
	    {
	      /* Since there's no PLT entry, Validate that this is
		 locally defined.  */
	      BFD_ASSERT (undef_weak_ref || sym_sec->output_section != NULL);

	      /* If the symbol is undef_weak, we shouldn't be trying
		 to call it.  There's every chance that we'd wind up
		 with an out-of-range fixup here.  Don't bother setting
		 any value at all.  */
	      if (undef_weak_ref)
		continue;
	    }
	  goto finish_pcrel;

	case R_IA64_PCREL21BI:
	case R_IA64_PCREL21F:
	case R_IA64_PCREL21M:
	case R_IA64_PCREL22:
	case R_IA64_PCREL64I:
	  /* The PCREL21BI reloc is specifically not intended for use with
	     dynamic relocs.  PCREL21F and PCREL21M are used for speculation
	     fixup code, and thus probably ought not be dynamic.  The
	     PCREL22 and PCREL64I relocs aren't emitted as dynamic relocs.  */
	  if (dynamic_symbol_p)
	    {
	      const char *msg;

	      if (r_type == R_IA64_PCREL21BI)
		/* xgettext:c-format */
		msg = _("%pB: @internal branch to dynamic symbol %s");
	      else if (r_type == R_IA64_PCREL21F || r_type == R_IA64_PCREL21M)
		/* xgettext:c-format */
		msg = _("%pB: speculation fixup to dynamic symbol %s");
	      else
		/* xgettext:c-format */
		msg = _("%pB: @pcrel relocation against dynamic symbol %s");
	      _bfd_error_handler (msg, input_bfd,
				  h ? h->root.root.string
				  : bfd_elf_sym_name (input_bfd,
						      symtab_hdr,
						      sym,
						      sym_sec));
	      ret_val = false;
	      continue;
	    }
	  goto finish_pcrel;

	finish_pcrel:
	  /* Make pc-relative.  */
	  value -= (input_section->output_section->vma
		    + input_section->output_offset
		    + rel->r_offset) & ~ (bfd_vma) 0x3;
	  r = ia64_elf_install_value (hit_addr, value, r_type);
	  break;

	case R_IA64_SEGREL32MSB:
	case R_IA64_SEGREL32LSB:
	case R_IA64_SEGREL64MSB:
	case R_IA64_SEGREL64LSB:
	    {
	      /* Find the segment that contains the output_section.  */
	      Elf_Internal_Phdr *p = _bfd_elf_find_segment_containing_section
		(output_bfd, input_section->output_section);

	      if (p == NULL)
		{
		  r = bfd_reloc_notsupported;
		}
	      else
		{
		  /* The VMA of the segment is the vaddr of the associated
		     program header.  */
		  if (value > p->p_vaddr)
		    value -= p->p_vaddr;
		  else
		    value = 0;
		  r = ia64_elf_install_value (hit_addr, value, r_type);
		}
	      break;
	    }

	case R_IA64_SECREL32MSB:
	case R_IA64_SECREL32LSB:
	case R_IA64_SECREL64MSB:
	case R_IA64_SECREL64LSB:
	  /* Make output-section relative to section where the symbol
	     is defined. PR 475  */
	  if (sym_sec)
	    value -= sym_sec->output_section->vma;
	  r = ia64_elf_install_value (hit_addr, value, r_type);
	  break;

	case R_IA64_IPLTMSB:
	case R_IA64_IPLTLSB:
	  /* Install a dynamic relocation for this reloc.  */
	  if ((dynamic_symbol_p || bfd_link_pic (info))
	      && (input_section->flags & SEC_ALLOC) != 0)
	    {
	      BFD_ASSERT (srel != NULL);

	      /* If we don't need dynamic symbol lookup, install two
		 RELATIVE relocations.  */
	      if (!dynamic_symbol_p)
		{
		  unsigned int dyn_r_type;

		  if (r_type == R_IA64_IPLTMSB)
		    dyn_r_type = R_IA64_REL64MSB;
		  else
		    dyn_r_type = R_IA64_REL64LSB;

		  elf32_ia64_install_dyn_reloc (output_bfd, info,
						input_section,
						srel, rel->r_offset,
						dyn_r_type, 0, value);
		  elf32_ia64_install_dyn_reloc (output_bfd, info,
						input_section,
						srel, rel->r_offset + 8,
						dyn_r_type, 0, gp_val);
		}
	      else
		elf32_ia64_install_dyn_reloc (output_bfd, info, input_section,
					      srel, rel->r_offset, r_type,
					      h->dynindx, rel->r_addend);
	    }

	  if (r_type == R_IA64_IPLTMSB)
	    r_type = R_IA64_DIR64MSB;
	  else
	    r_type = R_IA64_DIR64LSB;
	  ia64_elf_install_value (hit_addr, value, r_type);
	  r = ia64_elf_install_value (hit_addr + 8, gp_val, r_type);
	  break;

	case R_IA64_TPREL14:
	case R_IA64_TPREL22:
	case R_IA64_TPREL64I:
	  if (elf_hash_table (info)->tls_sec == NULL)
	    goto missing_tls_sec;
	  value -= elf32_ia64_tprel_base (info);
	  r = ia64_elf_install_value (hit_addr, value, r_type);
	  break;

	case R_IA64_DTPREL14:
	case R_IA64_DTPREL22:
	case R_IA64_DTPREL64I:
	case R_IA64_DTPREL32LSB:
	case R_IA64_DTPREL32MSB:
	case R_IA64_DTPREL64LSB:
	case R_IA64_DTPREL64MSB:
	  if (elf_hash_table (info)->tls_sec == NULL)
	    goto missing_tls_sec;
	  value -= elf32_ia64_dtprel_base (info);
	  r = ia64_elf_install_value (hit_addr, value, r_type);
	  break;

	case R_IA64_LTOFF_TPREL22:
	case R_IA64_LTOFF_DTPMOD22:
	case R_IA64_LTOFF_DTPREL22:
	  {
	    int got_r_type;
	    long dynindx = h ? h->dynindx : -1;
	    bfd_vma r_addend = rel->r_addend;

	    switch (r_type)
	      {
	      default:
	      case R_IA64_LTOFF_TPREL22:
		if (!dynamic_symbol_p)
		  {
		    if (elf_hash_table (info)->tls_sec == NULL)
		      goto missing_tls_sec;
		    if (!bfd_link_pic (info))
		      value -= elf32_ia64_tprel_base (info);
		    else
		      {
			r_addend += value - elf32_ia64_dtprel_base (info);
			dynindx = 0;
		      }
		  }
		got_r_type = R_IA64_TPREL64LSB;
		break;
	      case R_IA64_LTOFF_DTPMOD22:
		if (!dynamic_symbol_p && !bfd_link_pic (info))
		  value = 1;
		got_r_type = R_IA64_DTPMOD64LSB;
		break;
	      case R_IA64_LTOFF_DTPREL22:
		if (!dynamic_symbol_p)
		  {
		    if (elf_hash_table (info)->tls_sec == NULL)
		      goto missing_tls_sec;
		    value -= elf32_ia64_dtprel_base (info);
		  }
		got_r_type = R_IA64_DTPREL32LSB;
		break;
	      }
	    dyn_i = get_dyn_sym_info (ia64_info, h, input_bfd, rel, false);
	    value = set_got_entry (input_bfd, info, dyn_i, dynindx, r_addend,
				   value, got_r_type);
	    value -= gp_val;
	    r = ia64_elf_install_value (hit_addr, value, r_type);
	  }
	  break;

	default:
	  r = bfd_reloc_notsupported;
	  break;
	}

      switch (r)
	{
	case bfd_reloc_ok:
	  break;

	case bfd_reloc_undefined:
	  /* This can happen for global table relative relocs if
	     __gp is undefined.  This is a panic situation so we
	     don't try to continue.  */
	  (*info->callbacks->undefined_symbol)
	    (info, "__gp", input_bfd, input_section, rel->r_offset, 1);
	  return false;

	case bfd_reloc_notsupported:
	  {
	    const char *name;

	    if (h)
	      name = h->root.root.string;
	    else
	      name = bfd_elf_sym_name (input_bfd, symtab_hdr, sym,
				       sym_sec);
	    (*info->callbacks->warning) (info, _("unsupported reloc"),
					 name, input_bfd,
					 input_section, rel->r_offset);
	    ret_val = false;
	  }
	  break;

	case bfd_reloc_dangerous:
	case bfd_reloc_outofrange:
	case bfd_reloc_overflow:
	default:
	missing_tls_sec:
	  {
	    const char *name;

	    if (h)
	      name = h->root.root.string;
	    else
	      name = bfd_elf_sym_name (input_bfd, symtab_hdr, sym,
				       sym_sec);

	    switch (r_type)
	      {
	      case R_IA64_TPREL14:
	      case R_IA64_TPREL22:
	      case R_IA64_TPREL64I:
	      case R_IA64_DTPREL14:
	      case R_IA64_DTPREL22:
	      case R_IA64_DTPREL64I:
	      case R_IA64_DTPREL32LSB:
	      case R_IA64_DTPREL32MSB:
	      case R_IA64_DTPREL64LSB:
	      case R_IA64_DTPREL64MSB:
	      case R_IA64_LTOFF_TPREL22:
	      case R_IA64_LTOFF_DTPMOD22:
	      case R_IA64_LTOFF_DTPREL22:
		_bfd_error_handler
		  /* xgettext:c-format */
		  (_("%pB: missing TLS section for relocation %s against `%s'"
		     " at %#" PRIx64 " in section `%pA'."),
		   input_bfd, howto->name, name,
		   (uint64_t) rel->r_offset, input_section);
		break;

	      case R_IA64_PCREL21B:
	      case R_IA64_PCREL21BI:
	      case R_IA64_PCREL21M:
	      case R_IA64_PCREL21F:
		if (is_elf_hash_table (info->hash))
		  {
		    /* Relaxtion is always performed for ELF output.
		       Overflow failures for those relocations mean
		       that the section is too big to relax.  */
		    _bfd_error_handler
		      /* xgettext:c-format */
		      (_("%pB: Can't relax br (%s) to `%s' at %#" PRIx64
			 " in section `%pA' with size %#" PRIx64
			 " (> 0x1000000)."),
		       input_bfd, howto->name, name, (uint64_t) rel->r_offset,
		       input_section, (uint64_t) input_section->size);
		    break;
		  }
		/* Fall through.  */
	      default:
		(*info->callbacks->reloc_overflow) (info,
						    &h->root,
						    name,
						    howto->name,
						    (bfd_vma) 0,
						    input_bfd,
						    input_section,
						    rel->r_offset);
		break;
	      }

	    ret_val = false;
	  }
	  break;
	}
    }

  return ret_val;
}

static bool
elf32_ia64_finish_dynamic_symbol (bfd *output_bfd,
				  struct bfd_link_info *info,
				  struct elf_link_hash_entry *h,
				  Elf_Internal_Sym *sym)
{
  struct elf32_ia64_link_hash_table *ia64_info;
  struct elf32_ia64_dyn_sym_info *dyn_i;

  ia64_info = elf32_ia64_hash_table (info);

  dyn_i = get_dyn_sym_info (ia64_info, h, NULL, NULL, false);

  /* Fill in the PLT data, if required.  */
  if (dyn_i && dyn_i->want_plt)
    {
      Elf_Internal_Rela outrel;
      bfd_byte *loc;
      asection *plt_sec;
      bfd_vma plt_addr, pltoff_addr, gp_val, plt_index;

      gp_val = _bfd_get_gp_value (output_bfd);

      /* Initialize the minimal PLT entry.  */

      plt_index = (dyn_i->plt_offset - PLT_HEADER_SIZE) / PLT_MIN_ENTRY_SIZE;
      plt_sec = ia64_info->root.splt;
      loc = plt_sec->contents + dyn_i->plt_offset;

      memcpy (loc, plt_min_entry, PLT_MIN_ENTRY_SIZE);
      ia64_elf_install_value (loc, plt_index, R_IA64_IMM22);
      ia64_elf_install_value (loc+2, -dyn_i->plt_offset, R_IA64_PCREL21B);

      plt_addr = (plt_sec->output_section->vma
		  + plt_sec->output_offset
		  + dyn_i->plt_offset);
      pltoff_addr = set_pltoff_entry (output_bfd, info, dyn_i, plt_addr, true);

      /* Initialize the FULL PLT entry, if needed.  */
      if (dyn_i->want_plt2)
	{
	  loc = plt_sec->contents + dyn_i->plt2_offset;

	  memcpy (loc, plt_full_entry, PLT_FULL_ENTRY_SIZE);
	  ia64_elf_install_value (loc, pltoff_addr - gp_val, R_IA64_IMM22);

	  /* Mark the symbol as undefined, rather than as defined in the
	     plt section.  Leave the value alone.  */
	  /* ??? We didn't redefine it in adjust_dynamic_symbol in the
	     first place.  But perhaps elflink.c did some for us.  */
	  if (!h->def_regular)
	    sym->st_shndx = SHN_UNDEF;
	}

      /* Create the dynamic relocation.  */
      outrel.r_offset = pltoff_addr;
      if (bfd_little_endian (output_bfd))
	outrel.r_info = ELF32_R_INFO (h->dynindx, R_IA64_IPLTLSB);
      else
	outrel.r_info = ELF32_R_INFO (h->dynindx, R_IA64_IPLTMSB);
      outrel.r_addend = 0;

      /* This is fun.  In the .IA_64.pltoff section, we've got entries
	 that correspond both to real PLT entries, and those that
	 happened to resolve to local symbols but need to be created
	 to satisfy @pltoff relocations.  The .rela.IA_64.pltoff
	 relocations for the real PLT should come at the end of the
	 section, so that they can be indexed by plt entry at runtime.

	 We emitted all of the relocations for the non-PLT @pltoff
	 entries during relocate_section.  So we can consider the
	 existing sec->reloc_count to be the base of the array of
	 PLT relocations.  */

      loc = ia64_info->rel_pltoff_sec->contents;
      loc += ((ia64_info->rel_pltoff_sec->reloc_count + plt_index)
	      * sizeof (Elf32_External_Rela));
      bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
    }

  /* Mark some specially defined symbols as absolute.  */
  if (h == ia64_info->root.hdynamic
      || h == ia64_info->root.hgot
      || h == ia64_info->root.hplt)
    sym->st_shndx = SHN_ABS;

  return true;
}

static bool
elf32_ia64_finish_dynamic_sections (bfd *abfd,
				    struct bfd_link_info *info)
{
  struct elf32_ia64_link_hash_table *ia64_info;
  bfd *dynobj;

  ia64_info = elf32_ia64_hash_table (info);
  if (ia64_info == NULL)
    return false;

  dynobj = ia64_info->root.dynobj;

  if (ia64_info->root.dynamic_sections_created)
    {
      Elf32_External_Dyn *dyncon, *dynconend;
      asection *sdyn, *sgotplt;
      bfd_vma gp_val;

      sdyn = bfd_get_linker_section (dynobj, ".dynamic");
      sgotplt = ia64_info->root.sgotplt;
      BFD_ASSERT (sdyn != NULL);
      dyncon = (Elf32_External_Dyn *) sdyn->contents;
      dynconend = (Elf32_External_Dyn *) (sdyn->contents + sdyn->size);

      gp_val = _bfd_get_gp_value (abfd);

      for (; dyncon < dynconend; dyncon++)
	{
	  Elf_Internal_Dyn dyn;

	  bfd_elf32_swap_dyn_in (dynobj, dyncon, &dyn);

	  switch (dyn.d_tag)
	    {
	    case DT_PLTGOT:
	      dyn.d_un.d_ptr = gp_val;
	      break;

	    case DT_PLTRELSZ:
	      dyn.d_un.d_val = (ia64_info->minplt_entries
				* sizeof (Elf32_External_Rela));
	      break;

	    case DT_JMPREL:
	      /* See the comment above in finish_dynamic_symbol.  */
	      dyn.d_un.d_ptr = (ia64_info->rel_pltoff_sec->output_section->vma
				+ ia64_info->rel_pltoff_sec->output_offset
				+ (ia64_info->rel_pltoff_sec->reloc_count
				   * sizeof (Elf32_External_Rela)));
	      break;

	    case DT_IA_64_PLT_RESERVE:
	      dyn.d_un.d_ptr = (sgotplt->output_section->vma
				+ sgotplt->output_offset);
	      break;
	    }

	  bfd_elf32_swap_dyn_out (abfd, &dyn, dyncon);
	}

      /* Initialize the PLT0 entry.  */
      if (ia64_info->root.splt)
	{
	  bfd_byte *loc = ia64_info->root.splt->contents;
	  bfd_vma pltres;

	  memcpy (loc, plt_header, PLT_HEADER_SIZE);

	  pltres = (sgotplt->output_section->vma
		    + sgotplt->output_offset
		    - gp_val);

	  ia64_elf_install_value (loc+1, pltres, R_IA64_GPREL22);
	}
    }

  return true;
}

/* ELF file flag handling:  */

/* Function to keep IA-64 specific file flags.  */
static bool
elf32_ia64_set_private_flags (bfd *abfd, flagword flags)
{
  BFD_ASSERT (!elf_flags_init (abfd)
	      || elf_elfheader (abfd)->e_flags == flags);

  elf_elfheader (abfd)->e_flags = flags;
  elf_flags_init (abfd) = true;
  return true;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bool
elf32_ia64_merge_private_bfd_data (bfd *ibfd, struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;
  flagword out_flags;
  flagword in_flags;
  bool ok = true;

  /* FIXME: What should be checked when linking shared libraries?  */
  if ((ibfd->flags & DYNAMIC) != 0)
    return true;

  if (!is_ia64_elf (ibfd) || !is_ia64_elf (obfd))
    return true;

  in_flags  = elf_elfheader (ibfd)->e_flags;
  out_flags = elf_elfheader (obfd)->e_flags;

  if (! elf_flags_init (obfd))
    {
      elf_flags_init (obfd) = true;
      elf_elfheader (obfd)->e_flags = in_flags;

      if (bfd_get_arch (obfd) == bfd_get_arch (ibfd)
	  && bfd_get_arch_info (obfd)->the_default)
	{
	  return bfd_set_arch_mach (obfd, bfd_get_arch (ibfd),
				    bfd_get_mach (ibfd));
	}

      return true;
    }

  /* Check flag compatibility.  */
  if (in_flags == out_flags)
    return true;

  /* Output has EF_IA_64_REDUCEDFP set only if all inputs have it set.  */
  if (!(in_flags & EF_IA_64_REDUCEDFP) && (out_flags & EF_IA_64_REDUCEDFP))
    elf_elfheader (obfd)->e_flags &= ~EF_IA_64_REDUCEDFP;

  if ((in_flags & EF_IA_64_TRAPNIL) != (out_flags & EF_IA_64_TRAPNIL))
    {
      _bfd_error_handler
	(_("%pB: linking trap-on-NULL-dereference with non-trapping files"),
	 ibfd);

      bfd_set_error (bfd_error_bad_value);
      ok = false;
    }
  if ((in_flags & EF_IA_64_BE) != (out_flags & EF_IA_64_BE))
    {
      _bfd_error_handler
	(_("%pB: linking big-endian files with little-endian files"),
	 ibfd);

      bfd_set_error (bfd_error_bad_value);
      ok = false;
    }
  if ((in_flags & EF_IA_64_ABI64) != (out_flags & EF_IA_64_ABI64))
    {
      _bfd_error_handler
	(_("%pB: linking 64-bit files with 32-bit files"),
	 ibfd);

      bfd_set_error (bfd_error_bad_value);
      ok = false;
    }
  if ((in_flags & EF_IA_64_CONS_GP) != (out_flags & EF_IA_64_CONS_GP))
    {
      _bfd_error_handler
	(_("%pB: linking constant-gp files with non-constant-gp files"),
	 ibfd);

      bfd_set_error (bfd_error_bad_value);
      ok = false;
    }
  if ((in_flags & EF_IA_64_NOFUNCDESC_CONS_GP)
      != (out_flags & EF_IA_64_NOFUNCDESC_CONS_GP))
    {
      _bfd_error_handler
	(_("%pB: linking auto-pic files with non-auto-pic files"),
	 ibfd);

      bfd_set_error (bfd_error_bad_value);
      ok = false;
    }

  return ok;
}

static bool
elf32_ia64_print_private_bfd_data (bfd *abfd, void * ptr)
{
  FILE *file = (FILE *) ptr;
  flagword flags = elf_elfheader (abfd)->e_flags;

  BFD_ASSERT (abfd != NULL && ptr != NULL);

  fprintf (file, "private flags = %s%s%s%s%s%s%s%s\n",
	   (flags & EF_IA_64_TRAPNIL) ? "TRAPNIL, " : "",
	   (flags & EF_IA_64_EXT) ? "EXT, " : "",
	   (flags & EF_IA_64_BE) ? "BE, " : "LE, ",
	   (flags & EF_IA_64_REDUCEDFP) ? "REDUCEDFP, " : "",
	   (flags & EF_IA_64_CONS_GP) ? "CONS_GP, " : "",
	   (flags & EF_IA_64_NOFUNCDESC_CONS_GP) ? "NOFUNCDESC_CONS_GP, " : "",
	   (flags & EF_IA_64_ABSOLUTE) ? "ABSOLUTE, " : "",
	   (flags & EF_IA_64_ABI64) ? "ABI64" : "ABI32");

  _bfd_elf_print_private_bfd_data (abfd, ptr);
  return true;
}

static enum elf_reloc_type_class
elf32_ia64_reloc_type_class (const struct bfd_link_info *info ATTRIBUTE_UNUSED,
			     const asection *rel_sec ATTRIBUTE_UNUSED,
			     const Elf_Internal_Rela *rela)
{
  switch ((int) ELF32_R_TYPE (rela->r_info))
    {
    case R_IA64_REL32MSB:
    case R_IA64_REL32LSB:
    case R_IA64_REL64MSB:
    case R_IA64_REL64LSB:
      return reloc_class_relative;
    case R_IA64_IPLTMSB:
    case R_IA64_IPLTLSB:
      return reloc_class_plt;
    case R_IA64_COPY:
      return reloc_class_copy;
    default:
      return reloc_class_normal;
    }
}

static const struct bfd_elf_special_section elf32_ia64_special_sections[] =
{
  { STRING_COMMA_LEN (".sbss"),	 -1, SHT_NOBITS,   SHF_ALLOC + SHF_WRITE + SHF_IA_64_SHORT },
  { STRING_COMMA_LEN (".sdata"), -1, SHT_PROGBITS, SHF_ALLOC + SHF_WRITE + SHF_IA_64_SHORT },
  { NULL,		     0,	  0, 0,		   0 }
};

static bool
elf32_ia64_object_p (bfd *abfd)
{
  asection *sec;
  asection *group, *unwi, *unw;
  flagword flags;
  const char *name;
  char *unwi_name, *unw_name;
  size_t amt;

  if (abfd->flags & DYNAMIC)
    return true;

  /* Flags for fake group section.  */
  flags = (SEC_LINKER_CREATED | SEC_GROUP | SEC_LINK_ONCE
	   | SEC_EXCLUDE);

  /* We add a fake section group for each .gnu.linkonce.t.* section,
     which isn't in a section group, and its unwind sections.  */
  for (sec = abfd->sections; sec != NULL; sec = sec->next)
    {
      if (elf_sec_group (sec) == NULL
	  && ((sec->flags & (SEC_LINK_ONCE | SEC_CODE | SEC_GROUP))
	      == (SEC_LINK_ONCE | SEC_CODE))
	  && startswith (sec->name, ".gnu.linkonce.t."))
	{
	  name = sec->name + 16;

	  amt = strlen (name) + sizeof (".gnu.linkonce.ia64unwi.");
	  unwi_name = bfd_alloc (abfd, amt);
	  if (!unwi_name)
	    return false;

	  strcpy (stpcpy (unwi_name, ".gnu.linkonce.ia64unwi."), name);
	  unwi = bfd_get_section_by_name (abfd, unwi_name);

	  amt = strlen (name) + sizeof (".gnu.linkonce.ia64unw.");
	  unw_name = bfd_alloc (abfd, amt);
	  if (!unw_name)
	    return false;

	  strcpy (stpcpy (unw_name, ".gnu.linkonce.ia64unw."), name);
	  unw = bfd_get_section_by_name (abfd, unw_name);

	  /* We need to create a fake group section for it and its
	     unwind sections.  */
	  group = bfd_make_section_anyway_with_flags (abfd, name,
						      flags);
	  if (group == NULL)
	    return false;

	  /* Move the fake group section to the beginning.  */
	  bfd_section_list_remove (abfd, group);
	  bfd_section_list_prepend (abfd, group);

	  elf_next_in_group (group) = sec;

	  elf_group_name (sec) = name;
	  elf_next_in_group (sec) = sec;
	  elf_sec_group (sec) = group;

	  if (unwi)
	    {
	      elf_group_name (unwi) = name;
	      elf_next_in_group (unwi) = sec;
	      elf_next_in_group (sec) = unwi;
	      elf_sec_group (unwi) = group;
	    }

	   if (unw)
	     {
	       elf_group_name (unw) = name;
	       if (unwi)
		 {
		   elf_next_in_group (unw) = elf_next_in_group (unwi);
		   elf_next_in_group (unwi) = unw;
		 }
	       else
		 {
		   elf_next_in_group (unw) = sec;
		   elf_next_in_group (sec) = unw;
		 }
	       elf_sec_group (unw) = group;
	     }

	   /* Fake SHT_GROUP section header.  */
	  elf_section_data (group)->this_hdr.bfd_section = group;
	  elf_section_data (group)->this_hdr.sh_type = SHT_GROUP;
	}
    }
  return true;
}

static bool
elf32_ia64_hpux_vec (const bfd_target *vec)
{
  extern const bfd_target ia64_elf32_hpux_be_vec;
  return (vec == &ia64_elf32_hpux_be_vec);
}

static bool
elf32_hpux_init_file_header (bfd *abfd, struct bfd_link_info *info)
{
  Elf_Internal_Ehdr *i_ehdrp;

  if (!_bfd_elf_init_file_header (abfd, info))
    return false;

  i_ehdrp = elf_elfheader (abfd);
  i_ehdrp->e_ident[EI_OSABI] = get_elf_backend_data (abfd)->elf_osabi;
  i_ehdrp->e_ident[EI_ABIVERSION] = 1;
  return true;
}

static bool
elf32_hpux_backend_section_from_bfd_section (bfd *abfd ATTRIBUTE_UNUSED,
					     asection *sec, int *retval)
{
  if (bfd_is_com_section (sec))
    {
      *retval = SHN_IA_64_ANSI_COMMON;
      return true;
    }
  return false;
}

static void
elf32_hpux_backend_symbol_processing (bfd *abfd ATTRIBUTE_UNUSED,
				      asymbol *asym)
{
  elf_symbol_type *elfsym = (elf_symbol_type *) asym;

  switch (elfsym->internal_elf_sym.st_shndx)
    {
    case SHN_IA_64_ANSI_COMMON:
      asym->section = bfd_com_section_ptr;
      asym->value = elfsym->internal_elf_sym.st_size;
      asym->flags &= ~BSF_GLOBAL;
      break;
    }
}

static void
ignore_errors (const char *fmt ATTRIBUTE_UNUSED, ...)
{
}

#define TARGET_LITTLE_SYM		ia64_elf32_le_vec
#define TARGET_LITTLE_NAME		"elf32-ia64-little"
#define TARGET_BIG_SYM			ia64_elf32_be_vec
#define TARGET_BIG_NAME			"elf32-ia64-big"
#define ELF_ARCH			bfd_arch_ia64
#define ELF_TARGET_ID			IA64_ELF_DATA
#define ELF_MACHINE_CODE		EM_IA_64
#define ELF_MACHINE_ALT1		1999	/* EAS2.3 */
#define ELF_MACHINE_ALT2		1998	/* EAS2.2 */
#define ELF_MAXPAGESIZE			0x10000	/* 64KB */
#define ELF_COMMONPAGESIZE		0x4000	/* 16KB */

#define elf_backend_section_from_shdr \
	elf32_ia64_section_from_shdr
#define elf_backend_section_flags \
	elf32_ia64_section_flags
#define elf_backend_fake_sections \
	elf32_ia64_fake_sections
#define elf_backend_final_write_processing \
	elf32_ia64_final_write_processing
#define elf_backend_add_symbol_hook \
	elf32_ia64_add_symbol_hook
#define elf_backend_additional_program_headers \
	elf32_ia64_additional_program_headers
#define elf_backend_modify_segment_map \
	elf32_ia64_modify_segment_map
#define elf_backend_modify_headers \
	elf32_ia64_modify_headers
#define elf_info_to_howto \
	elf32_ia64_info_to_howto

#define bfd_elf32_bfd_reloc_type_lookup \
	ia64_elf_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup \
	ia64_elf_reloc_name_lookup
#define bfd_elf32_bfd_is_local_label_name \
	elf32_ia64_is_local_label_name
#define bfd_elf32_bfd_relax_section \
	elf32_ia64_relax_section

#define elf_backend_object_p \
	elf32_ia64_object_p

/* Stuff for the BFD linker: */
#define bfd_elf32_bfd_link_hash_table_create \
	elf32_ia64_hash_table_create
#define elf_backend_create_dynamic_sections \
	elf32_ia64_create_dynamic_sections
#define elf_backend_check_relocs \
	elf32_ia64_check_relocs
#define elf_backend_adjust_dynamic_symbol \
	elf32_ia64_adjust_dynamic_symbol
#define elf_backend_late_size_sections \
	elf32_ia64_late_size_sections
#define elf_backend_omit_section_dynsym \
	_bfd_elf_omit_section_dynsym_all
#define elf_backend_relocate_section \
	elf32_ia64_relocate_section
#define elf_backend_finish_dynamic_symbol \
	elf32_ia64_finish_dynamic_symbol
#define elf_backend_finish_dynamic_sections \
	elf32_ia64_finish_dynamic_sections
#define bfd_elf32_bfd_final_link \
	elf32_ia64_final_link

#define bfd_elf32_bfd_merge_private_bfd_data \
	elf32_ia64_merge_private_bfd_data
#define bfd_elf32_bfd_set_private_flags \
	elf32_ia64_set_private_flags
#define bfd_elf32_bfd_print_private_bfd_data \
	elf32_ia64_print_private_bfd_data

#define elf_backend_plt_readonly	1
#define elf_backend_can_gc_sections	1
#define elf_backend_want_plt_sym	0
#define elf_backend_plt_alignment	5
#define elf_backend_got_header_size	0
#define elf_backend_want_got_plt	1
#define elf_backend_may_use_rel_p	1
#define elf_backend_may_use_rela_p	1
#define elf_backend_default_use_rela_p	1
#define elf_backend_want_dynbss		0
#define elf_backend_copy_indirect_symbol elf32_ia64_hash_copy_indirect
#define elf_backend_hide_symbol		elf32_ia64_hash_hide_symbol
#define elf_backend_fixup_symbol	_bfd_elf_link_hash_fixup_symbol
#define elf_backend_reloc_type_class	elf32_ia64_reloc_type_class
#define elf_backend_rela_normal		1
#define elf_backend_dtrel_excludes_plt	1
#define elf_backend_special_sections	elf32_ia64_special_sections
#define elf_backend_default_execstack	0

/* FIXME: PR 290: The Intel C compiler generates SHT_IA_64_UNWIND with
   SHF_LINK_ORDER. But it doesn't set the sh_link or sh_info fields.
   We don't want to flood users with so many error messages. We turn
   off the warning for now. It will be turned on later when the Intel
   compiler is fixed.   */
#define elf_backend_link_order_error_handler ignore_errors

#include "elf32-target.h"

/* HPUX-specific vectors.  */

#undef  TARGET_LITTLE_SYM
#undef  TARGET_LITTLE_NAME
#undef  TARGET_BIG_SYM
#define TARGET_BIG_SYM			ia64_elf32_hpux_be_vec
#undef	TARGET_BIG_NAME
#define TARGET_BIG_NAME			"elf32-ia64-hpux-big"

/* These are HP-UX specific functions.  */

#undef  elf_backend_init_file_header
#define elf_backend_init_file_header elf32_hpux_init_file_header

#undef  elf_backend_section_from_bfd_section
#define elf_backend_section_from_bfd_section elf32_hpux_backend_section_from_bfd_section

#undef elf_backend_symbol_processing
#define elf_backend_symbol_processing elf32_hpux_backend_symbol_processing

#undef  elf_backend_want_p_paddr_set_to_zero
#define elf_backend_want_p_paddr_set_to_zero 1

#undef ELF_COMMONPAGESIZE
#undef ELF_OSABI
#define ELF_OSABI			ELFOSABI_HPUX

#undef  elf32_bed
#define elf32_bed elf32_ia64_hpux_bed

#include "elf32-target.h"
