#line 1 "../../binutils-gdb/bfd/elfnn-kvx.c"
/* KVX-specific support for 32-bit ELF.
   Copyright (C) 2009-2025 Free Software Foundation, Inc.
   Contributed by Kalray SA.

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

#include "sysdep.h"
#include "bfd.h"
#include "libiberty.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "bfdlink.h"
#include "objalloc.h"
#include "elf/kvx.h"
#include "elfxx-kvx.h"

#define ARCH_SIZE	32

#if ARCH_SIZE == 64
#define LOG_FILE_ALIGN	3
#endif

#if ARCH_SIZE == 32
#define LOG_FILE_ALIGN	2
#endif

#define IS_KVX_TLS_RELOC(R_TYPE)			\
  ((R_TYPE) == BFD_RELOC_KVX_S37_TLS_LE_LO10	\
   || (R_TYPE) == BFD_RELOC_KVX_S37_TLS_LE_UP27	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_LE_LO10	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_LE_UP27	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_LE_EX6	\
   || (R_TYPE) == BFD_RELOC_KVX_S37_TLS_DTPOFF_LO10	\
   || (R_TYPE) == BFD_RELOC_KVX_S37_TLS_DTPOFF_UP27	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_DTPOFF_LO10	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_DTPOFF_UP27	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_DTPOFF_EX6	\
   || (R_TYPE) == BFD_RELOC_KVX_S37_TLS_IE_LO10	\
   || (R_TYPE) == BFD_RELOC_KVX_S37_TLS_IE_UP27	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_IE_LO10	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_IE_UP27	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_IE_EX6	\
   || (R_TYPE) == BFD_RELOC_KVX_S37_TLS_GD_LO10	\
   || (R_TYPE) == BFD_RELOC_KVX_S37_TLS_GD_UP27	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_GD_LO10	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_GD_UP27	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_GD_EX6	\
   || (R_TYPE) == BFD_RELOC_KVX_S37_TLS_LD_LO10	\
   || (R_TYPE) == BFD_RELOC_KVX_S37_TLS_LD_UP27	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_LD_LO10	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_LD_UP27	\
   || (R_TYPE) == BFD_RELOC_KVX_S43_TLS_LD_EX6	\
   )

#define IS_KVX_TLS_RELAX_RELOC(R_TYPE) 0

#define ELIMINATE_COPY_RELOCS 0

/* Return size of a relocation entry.  HTAB is the bfd's
   elf_kvx_link_hash_entry.  */
#define RELOC_SIZE(HTAB) (sizeof (Elf32_External_Rela))

/* GOT Entry size - 8 bytes in ELF64 and 4 bytes in ELF32.  */
#define GOT_ENTRY_SIZE                  (ARCH_SIZE / 8)
#define PLT_ENTRY_SIZE                  (32)

#define PLT_SMALL_ENTRY_SIZE            (4*4)

/* Encoding of the nop instruction */
#define INSN_NOP 0x00f0037f

#define kvx_compute_jump_table_size(htab)		\
  (((htab)->root.srelplt == NULL) ? 0			\
   : (htab)->root.srelplt->reloc_count * GOT_ENTRY_SIZE)

static const bfd_byte elf32_kvx_small_plt0_entry[PLT_ENTRY_SIZE] =
{
 /* FIXME KVX: no first entry, not used yet */
  0
};

/* Per function entry in a procedure linkage table looks like this
   if the distance between the PLTGOT and the PLT is < 4GB use
   these PLT entries.  */
static const bfd_byte elf32_kvx_small_plt_entry[PLT_SMALL_ENTRY_SIZE] =
{
  0x10, 0x00, 0xc4, 0x0f,       /* get $r16 = $pc     ;; */
#if ARCH_SIZE == 32
  0x10, 0x00, 0x40, 0xb0,       /* lwz $r16 = 0[$r16]   ;; */
#else
  0x10, 0x00, 0x40, 0xb8,       /* ld $r16 = 0[$r16] ;; */
#endif
  0x00, 0x00, 0x00, 0x18,       /* upper 27 bits for LSU */
  0x10, 0x00, 0xd8, 0x0f,	/* igoto $r16          ;; */
};

/* Long stub use 43bits format of make. */
static const uint32_t elf32_kvx_long_branch_stub[] =
{
  0xe0400000,      /* make $r16 = LO10<emm43> EX6<imm43> */
  0x00000000,      /* UP27<imm43> ;; */
  0x0fd80010,      /* igoto "r16  ;; */
};

#define elf_info_to_howto               elf32_kvx_info_to_howto
#define elf_info_to_howto_rel           elf32_kvx_info_to_howto

#define KVX_ELF_ABI_VERSION		0

/* In case we're on a 32-bit machine, construct a 64-bit "-1" value.  */
#define ALL_ONES (~ (bfd_vma) 0)

/* Indexed by the bfd interal reloc enumerators.
   Therefore, the table needs to be synced with BFD_RELOC_KVX_*
   in reloc.c.   */

#define KVX_KV3_V1_KV3_V2_KV4_V1
#include "elfxx-kvx-relocs.h"
#undef KVX_KV3_V1_KV3_V2_KV4_V1

/* Given HOWTO, return the bfd internal relocation enumerator.  */

static bfd_reloc_code_real_type
elf32_kvx_bfd_reloc_from_howto (reloc_howto_type *howto)
{
  const int size = (int) ARRAY_SIZE (elf_kvx_howto_table);
  const ptrdiff_t offset = howto - elf_kvx_howto_table;

  if (offset >= 0 && offset < size)
    return BFD_RELOC_KVX_RELOC_START + offset + 1;

  return BFD_RELOC_KVX_RELOC_START + 1;
}

/* Given R_TYPE, return the bfd internal relocation enumerator.  */

static bfd_reloc_code_real_type
elf32_kvx_bfd_reloc_from_type (bfd *abfd ATTRIBUTE_UNUSED, unsigned int r_type)
{
  static bool initialized_p = false;
  /* Indexed by R_TYPE, values are offsets in the howto_table.  */
  static unsigned int offsets[R_KVX_end];

  if (!initialized_p)
    {
      unsigned int i;

      for (i = 0; i < ARRAY_SIZE (elf_kvx_howto_table); ++i)
	offsets[elf_kvx_howto_table[i].type] = i;

      initialized_p = true;
    }

  /* PR 17512: file: b371e70a.  */
  if (r_type >= R_KVX_end)
    {
      bfd_set_error (bfd_error_bad_value);
      return BFD_RELOC_KVX_RELOC_END;
    }

  return (BFD_RELOC_KVX_RELOC_START + 1) + offsets[r_type];
}

struct elf_kvx_reloc_map
{
  bfd_reloc_code_real_type from;
  bfd_reloc_code_real_type to;
};

/* Map bfd generic reloc to KVX-specific reloc.  */
static const struct elf_kvx_reloc_map elf_kvx_reloc_map[] =
{
  {BFD_RELOC_NONE, BFD_RELOC_KVX_NONE},

  /* Basic data relocations.  */
  {BFD_RELOC_CTOR, BFD_RELOC_KVX_32},
  {BFD_RELOC_64, BFD_RELOC_KVX_64},
  {BFD_RELOC_32, BFD_RELOC_KVX_32},
  {BFD_RELOC_16, BFD_RELOC_KVX_16},
  {BFD_RELOC_8,  BFD_RELOC_KVX_8},

  {BFD_RELOC_64_PCREL, BFD_RELOC_KVX_64_PCREL},
  {BFD_RELOC_32_PCREL, BFD_RELOC_KVX_32_PCREL},
};

/* Given the bfd internal relocation enumerator in CODE, return the
   corresponding howto entry.  */

static reloc_howto_type *
elf32_kvx_howto_from_bfd_reloc (bfd_reloc_code_real_type code)
{
  unsigned int i;

  /* Convert bfd generic reloc to KVX-specific reloc.  */
  if (code < BFD_RELOC_KVX_RELOC_START || code > BFD_RELOC_KVX_RELOC_END)
    for (i = 0; i < ARRAY_SIZE (elf_kvx_reloc_map) ; i++)
      if (elf_kvx_reloc_map[i].from == code)
	{
	  code = elf_kvx_reloc_map[i].to;
	  break;
	}

  if (code > BFD_RELOC_KVX_RELOC_START && code < BFD_RELOC_KVX_RELOC_END)
      return &elf_kvx_howto_table[code - (BFD_RELOC_KVX_RELOC_START + 1)];

  return NULL;
}

static reloc_howto_type *
elf32_kvx_howto_from_type (bfd *abfd, unsigned int r_type)
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

  val = elf32_kvx_bfd_reloc_from_type (abfd, r_type);
  howto = elf32_kvx_howto_from_bfd_reloc (val);

  if (howto != NULL)
    return howto;

  bfd_set_error (bfd_error_bad_value);
  return NULL;
}

static bool
elf32_kvx_info_to_howto (bfd *abfd ATTRIBUTE_UNUSED, arelent *bfd_reloc,
			 Elf_Internal_Rela *elf_reloc)
{
  unsigned int r_type;

  r_type = ELF32_R_TYPE (elf_reloc->r_info);
  bfd_reloc->howto = elf32_kvx_howto_from_type (abfd, r_type);

  if (bfd_reloc->howto == NULL)
    {
      /* xgettext:c-format */
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			  abfd, r_type);
      return false;
    }
  return true;
}

static reloc_howto_type *
elf32_kvx_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			     bfd_reloc_code_real_type code)
{
  reloc_howto_type *howto = elf32_kvx_howto_from_bfd_reloc (code);

  if (howto != NULL)
    return howto;

  bfd_set_error (bfd_error_bad_value);
  return NULL;
}

static reloc_howto_type *
elf32_kvx_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			     const char *r_name)
{
  unsigned int i;

  for (i = 0; i < ARRAY_SIZE (elf_kvx_howto_table); ++i)
    if (elf_kvx_howto_table[i].name != NULL
	&& strcasecmp (elf_kvx_howto_table[i].name, r_name) == 0)
      return &elf_kvx_howto_table[i];

  return NULL;
}

#define TARGET_LITTLE_SYM               kvx_elf32_vec
#define TARGET_LITTLE_NAME              "elf32-kvx"

/* The linker script knows the section names for placement.
   The entry_names are used to do simple name mangling on the stubs.
   Given a function name, and its type, the stub can be found. The
   name can be changed. The only requirement is the %s be present.  */
#define STUB_ENTRY_NAME   "__%s_veneer"

/* The name of the dynamic interpreter.  This is put in the .interp
   section.  */
#define ELF_DYNAMIC_INTERPRETER     "/lib/ld.so.1"


/* PCREL 27 is signed-extended and scaled by 4 */
#define KVX_MAX_FWD_CALL_OFFSET \
  (((1 << 26) - 1) << 2)
#define KVX_MAX_BWD_CALL_OFFSET \
  (-((1 << 26) << 2))

/* Check that the destination of the call is within the PCREL27
   range. */
static int
kvx_valid_call_p (bfd_vma value, bfd_vma place)
{
  bfd_signed_vma offset = (bfd_signed_vma) (value - place);
  return (offset <= KVX_MAX_FWD_CALL_OFFSET
	  && offset >= KVX_MAX_BWD_CALL_OFFSET);
}

/* Section name for stubs is the associated section name plus this
   string.  */
#define STUB_SUFFIX ".stub"

enum elf_kvx_stub_type
{
  kvx_stub_none,
  kvx_stub_long_branch,
};

struct elf_kvx_stub_hash_entry
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

  enum elf_kvx_stub_type stub_type;

  /* The symbol table entry, if any, that this was derived from.  */
  struct elf_kvx_link_hash_entry *h;

  /* Destination symbol type */
  unsigned char st_type;

  /* Where this stub is being called from, or, in the case of combined
     stub sections, the first input section in the group.  */
  asection *id_sec;

  /* The name for the local symbol at the start of this stub.  The
     stub name in the hash table has to be unique; this does not, so
     it can be friendlier.  */
  char *output_name;
};

/* Used to build a map of a section.  This is required for mixed-endian
   code/data.  */

typedef struct elf_elf_section_map
{
  bfd_vma vma;
  char type;
}
elf_kvx_section_map;


typedef struct _kvx_elf_section_data
{
  struct bfd_elf_section_data elf;
  unsigned int mapcount;
  unsigned int mapsize;
  elf_kvx_section_map *map;
}
_kvx_elf_section_data;

#define elf_kvx_section_data(sec) \
  ((_kvx_elf_section_data *) elf_section_data (sec))

struct elf_kvx_local_symbol
{
  unsigned int got_type;
  bfd_signed_vma got_refcount;
  bfd_vma got_offset;
};

struct elf_kvx_obj_tdata
{
  struct elf_obj_tdata root;

  /* local symbol descriptors */
  struct elf_kvx_local_symbol *locals;

  /* Zero to warn when linking objects with incompatible enum sizes.  */
  int no_enum_size_warning;

  /* Zero to warn when linking objects with incompatible wchar_t sizes.  */
  int no_wchar_size_warning;
};

#define elf_kvx_tdata(bfd)				\
  ((struct elf_kvx_obj_tdata *) (bfd)->tdata.any)

#define elf_kvx_locals(bfd) (elf_kvx_tdata (bfd)->locals)

#define is_kvx_elf(bfd)				\
  (bfd_get_flavour (bfd) == bfd_target_elf_flavour	\
   && elf_tdata (bfd) != NULL				\
   && elf_object_id (bfd) == KVX_ELF_DATA)

static bool
elf32_kvx_mkobject (bfd *abfd)
{
  return bfd_elf_allocate_object (abfd, sizeof (struct elf_kvx_obj_tdata));
}

#define elf_kvx_hash_entry(ent) \
  ((struct elf_kvx_link_hash_entry *)(ent))

#define GOT_UNKNOWN    0
#define GOT_NORMAL     1

#define GOT_TLS_GD     2
#define GOT_TLS_IE     4
#define GOT_TLS_LD     8

/* KVX ELF linker hash entry.  */
struct elf_kvx_link_hash_entry
{
  struct elf_link_hash_entry root;

  /* Since PLT entries have variable size, we need to record the
     index into .got.plt instead of recomputing it from the PLT
     offset.  */
  bfd_signed_vma plt_got_offset;

  /* Bit mask representing the type of GOT entry(s) if any required by
     this symbol.  */
  unsigned int got_type;

  /* A pointer to the most recently used stub hash entry against this
     symbol.  */
  struct elf_kvx_stub_hash_entry *stub_cache;
};

/* Get the KVX elf linker hash table from a link_info structure.  */
#define elf_kvx_hash_table(info)					\
  ((struct elf_kvx_link_hash_table *) ((info)->hash))

#define kvx_stub_hash_lookup(table, string, create, copy)		\
  ((struct elf_kvx_stub_hash_entry *)				\
   bfd_hash_lookup ((table), (string), (create), (copy)))

/* KVX ELF linker hash table.  */
struct elf_kvx_link_hash_table
{
  /* The main hash table.  */
  struct elf_link_hash_table root;

  /* Nonzero to force PIC branch veneers.  */
  int pic_veneer;

  /* The number of bytes in the initial entry in the PLT.  */
  bfd_size_type plt_header_size;

  /* The number of bytes in the subsequent PLT etries.  */
  bfd_size_type plt_entry_size;

  /* The bytes of the subsequent PLT entry.  */
  const bfd_byte *plt_entry;

  /* Short-cuts to get to dynamic linker sections.  */
  asection *sdynbss;
  asection *srelbss;

  /* Small local sym cache.  */
  struct sym_cache sym_cache;

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

  /* Assorted information used by elf32_kvx_size_stubs.  */
  unsigned int bfd_count;
  unsigned int top_index;
  asection **input_list;
};

/* Create an entry in an KVX ELF linker hash table.  */

static struct bfd_hash_entry *
elf32_kvx_link_hash_newfunc (struct bfd_hash_entry *entry,
			     struct bfd_hash_table *table,
			     const char *string)
{
  struct elf_kvx_link_hash_entry *ret =
    (struct elf_kvx_link_hash_entry *) entry;

  /* Allocate the structure if it has not already been allocated by a
     subclass.  */
  if (ret == NULL)
    ret = bfd_hash_allocate (table,
			     sizeof (struct elf_kvx_link_hash_entry));
  if (ret == NULL)
    return (struct bfd_hash_entry *) ret;

  /* Call the allocation method of the superclass.  */
  ret = ((struct elf_kvx_link_hash_entry *)
	 _bfd_elf_link_hash_newfunc ((struct bfd_hash_entry *) ret,
				     table, string));
  if (ret != NULL)
    {
      ret->got_type = GOT_UNKNOWN;
      ret->plt_got_offset = (bfd_vma) - 1;
      ret->stub_cache = NULL;
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
					 elf_kvx_stub_hash_entry));
      if (entry == NULL)
	return entry;
    }

  /* Call the allocation method of the superclass.  */
  entry = bfd_hash_newfunc (entry, table, string);
  if (entry != NULL)
    {
      struct elf_kvx_stub_hash_entry *eh;

      /* Initialize the local fields.  */
      eh = (struct elf_kvx_stub_hash_entry *) entry;
      eh->stub_sec = NULL;
      eh->stub_offset = 0;
      eh->target_value = 0;
      eh->target_section = NULL;
      eh->stub_type = kvx_stub_none;
      eh->h = NULL;
      eh->id_sec = NULL;
    }

  return entry;
}

/* Copy the extra info we tack onto an elf_link_hash_entry.  */

static void
elf32_kvx_copy_indirect_symbol (struct bfd_link_info *info,
				struct elf_link_hash_entry *dir,
				struct elf_link_hash_entry *ind)
{
  struct elf_kvx_link_hash_entry *edir, *eind;

  edir = (struct elf_kvx_link_hash_entry *) dir;
  eind = (struct elf_kvx_link_hash_entry *) ind;

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

/* Destroy a KVX elf linker hash table.  */

static void
elf32_kvx_link_hash_table_free (bfd *obfd)
{
  struct elf_kvx_link_hash_table *ret
    = (struct elf_kvx_link_hash_table *) obfd->link.hash;

  bfd_hash_table_free (&ret->stub_hash_table);
  _bfd_elf_link_hash_table_free (obfd);
}

/* Create a KVX elf linker hash table.  */

static struct bfd_link_hash_table *
elf32_kvx_link_hash_table_create (bfd *abfd)
{
  struct elf_kvx_link_hash_table *ret;
  bfd_size_type amt = sizeof (struct elf_kvx_link_hash_table);

  ret = bfd_zmalloc (amt);
  if (ret == NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init
      (&ret->root, abfd, elf32_kvx_link_hash_newfunc,
       sizeof (struct elf_kvx_link_hash_entry)))
    {
      free (ret);
      return NULL;
    }

  ret->plt_header_size = PLT_ENTRY_SIZE;
  ret->plt_entry_size = PLT_SMALL_ENTRY_SIZE;
  ret->plt_entry = elf32_kvx_small_plt_entry;

  ret->obfd = abfd;

  if (!bfd_hash_table_init (&ret->stub_hash_table, stub_hash_newfunc,
			    sizeof (struct elf_kvx_stub_hash_entry)))
    {
      _bfd_elf_link_hash_table_free (abfd);
      return NULL;
    }

  ret->root.root.hash_table_free = elf32_kvx_link_hash_table_free;

  return &ret->root.root;
}

static bfd_reloc_status_type
kvx_relocate (unsigned int r_type, bfd *input_bfd, asection *input_section,
	      bfd_vma offset, bfd_vma value)
{
  reloc_howto_type *howto;

  howto = elf32_kvx_howto_from_type (input_bfd, r_type);
  r_type = elf32_kvx_bfd_reloc_from_type (input_bfd, r_type);
  return _bfd_kvx_elf_put_addend (input_bfd,
				  input_section->contents + offset, r_type,
				  howto, value);
}

/* Determine the type of stub needed, if any, for a call.  */

static enum elf_kvx_stub_type
kvx_type_of_stub (asection *input_sec,
		  const Elf_Internal_Rela *rel,
		  asection *sym_sec,
		  unsigned char st_type,
		  bfd_vma destination)
{
  bfd_vma location;
  bfd_signed_vma branch_offset;
  unsigned int r_type;
  enum elf_kvx_stub_type stub_type = kvx_stub_none;

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
     acceptable for the R16 and R17 registers to be clobbered.  */
  if (r_type == R_KVX_PCREL27
      && (branch_offset > KVX_MAX_FWD_CALL_OFFSET
	  || branch_offset < KVX_MAX_BWD_CALL_OFFSET))
    {
      stub_type = kvx_stub_long_branch;
    }

  return stub_type;
}

/* Build a name for an entry in the stub hash table.  */

static char *
elf32_kvx_stub_name (const asection *input_section,
		     const asection *sym_sec,
		     const struct elf_kvx_link_hash_entry *hash,
		     const Elf_Internal_Rela *rel)
{
  char *stub_name;
  bfd_size_type len;

  if (hash)
    {
      len = 8 + 1 + strlen (hash->root.root.root.string) + 1 + 16 + 1;
      stub_name = bfd_malloc (len);
      if (stub_name != NULL)
	snprintf (stub_name, len, "%08x_%s+%" PRIx64 "x",
		  (unsigned int) input_section->id,
		  hash->root.root.root.string,
		  (uint64_t) rel->r_addend);
    }
  else
    {
      len = 8 + 1 + 8 + 1 + 8 + 1 + 16 + 1;
      stub_name = bfd_malloc (len);
      if (stub_name != NULL)
	snprintf (stub_name, len, "%08x_%x:%x+%" PRIx64 "x",
		  (unsigned int) input_section->id,
		  (unsigned int) sym_sec->id,
		  (unsigned int) ELF32_R_SYM (rel->r_info),
		  (uint64_t) rel->r_addend);
    }

  return stub_name;
}

/* Return true if symbol H should be hashed in the `.gnu.hash' section.  For
   executable PLT slots where the executable never takes the address of those
   functions, the function symbols are not added to the hash table.  */

static bool
elf_kvx_hash_symbol (struct elf_link_hash_entry *h)
{
  if (h->plt.offset != (bfd_vma) -1
      && !h->def_regular
      && !h->pointer_equality_needed)
    return false;

  return _bfd_elf_hash_symbol (h);
}


/* Look up an entry in the stub hash.  Stub entries are cached because
   creating the stub name takes a bit of time.  */

static struct elf_kvx_stub_hash_entry *
elf32_kvx_get_stub_entry (const asection *input_section,
			  const asection *sym_sec,
			  struct elf_link_hash_entry *hash,
			  const Elf_Internal_Rela *rel,
			  struct elf_kvx_link_hash_table *htab)
{
  struct elf_kvx_stub_hash_entry *stub_entry;
  struct elf_kvx_link_hash_entry *h =
    (struct elf_kvx_link_hash_entry *) hash;
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

      stub_name = elf32_kvx_stub_name (id_sec, sym_sec, h, rel);
      if (stub_name == NULL)
	return NULL;

      stub_entry = kvx_stub_hash_lookup (&htab->stub_hash_table,
					 stub_name, false, false);
      if (h != NULL)
	h->stub_cache = stub_entry;

      free (stub_name);
    }

  return stub_entry;
}


/* Create a stub section.  */

static asection *
_bfd_kvx_create_stub_section (asection *section,
			      struct elf_kvx_link_hash_table *htab)

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
_bfd_kvx_get_stub_for_link_section (asection *link_section,
				    struct elf_kvx_link_hash_table *htab)
{
  if (htab->stub_group[link_section->id].stub_sec == NULL)
    htab->stub_group[link_section->id].stub_sec
      = _bfd_kvx_create_stub_section (link_section, htab);
  return htab->stub_group[link_section->id].stub_sec;
}


/* Find or create a stub section in the stub group for an input
   section.  */

static asection *
_bfd_kvx_create_or_find_stub_sec (asection *section,
				  struct elf_kvx_link_hash_table *htab)
{
  asection *link_sec = htab->stub_group[section->id].link_sec;
  return _bfd_kvx_get_stub_for_link_section (link_sec, htab);
}


/* Add a new stub entry in the stub group associated with an input
   section to the stub hash.  Not all fields of the new stub entry are
   initialised.  */

static struct elf_kvx_stub_hash_entry *
_bfd_kvx_add_stub_entry_in_group (const char *stub_name,
				  asection *section,
				  struct elf_kvx_link_hash_table *htab)
{
  asection *link_sec;
  asection *stub_sec;
  struct elf_kvx_stub_hash_entry *stub_entry;

  link_sec = htab->stub_group[section->id].link_sec;
  stub_sec = _bfd_kvx_create_or_find_stub_sec (section, htab);

  /* Enter this entry into the linker stub hash table.  */
  stub_entry = kvx_stub_hash_lookup (&htab->stub_hash_table, stub_name,
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

static bool
kvx_build_one_stub (struct bfd_hash_entry *gen_entry,
		    void *in_arg)
{
  struct elf_kvx_stub_hash_entry *stub_entry;
  asection *stub_sec;
  bfd *stub_bfd;
  bfd_byte *loc;
  bfd_vma sym_value;
  unsigned int template_size;
  const uint32_t *template;
  unsigned int i;
  struct bfd_link_info *info;

  /* Massage our args to the form they really have.  */
  stub_entry = (struct elf_kvx_stub_hash_entry *) gen_entry;

  info = (struct bfd_link_info *) in_arg;

  /* Fail if the target section could not be assigned to an output
     section.  The user should fix his linker script.  */
  if (stub_entry->target_section->output_section == NULL
      && info->non_contiguous_regions)
    info->callbacks->fatal (_("%P: Could not assign '%pA' to an output section. "
			      "Retry without "
			      "--enable-non-contiguous-regions.\n"),
			    stub_entry->target_section);

  stub_sec = stub_entry->stub_sec;

  /* Make a note of the offset within the stubs for this entry.  */
  stub_entry->stub_offset = stub_sec->size;
  loc = stub_sec->contents + stub_entry->stub_offset;

  stub_bfd = stub_sec->owner;

  /* This is the address of the stub destination.  */
  sym_value = (stub_entry->target_value
	       + stub_entry->target_section->output_offset
	       + stub_entry->target_section->output_section->vma);

  switch (stub_entry->stub_type)
    {
    case kvx_stub_long_branch:
      template = elf32_kvx_long_branch_stub;
      template_size = sizeof (elf32_kvx_long_branch_stub);
      break;
    default:
      abort ();
    }

  for (i = 0; i < (template_size / sizeof template[0]); i++)
    {
      bfd_putl32 (template[i], loc);
      loc += 4;
    }

  stub_sec->size += template_size;

  switch (stub_entry->stub_type)
    {
    case kvx_stub_long_branch:
      /* The stub uses a make insn with 43bits immediate.
	 We need to apply 3 relocations:
	 BFD_RELOC_KVX_S43_LO10,
	 BFD_RELOC_KVX_S43_UP27,
	 BFD_RELOC_KVX_S43_EX6.  */
      if (kvx_relocate (R_KVX_S43_LO10, stub_bfd, stub_sec,
			stub_entry->stub_offset, sym_value) != bfd_reloc_ok)
	BFD_FAIL ();
      if (kvx_relocate (R_KVX_S43_EX6, stub_bfd, stub_sec,
			stub_entry->stub_offset, sym_value) != bfd_reloc_ok)
	BFD_FAIL ();
      if (kvx_relocate (R_KVX_S43_UP27, stub_bfd, stub_sec,
			stub_entry->stub_offset + 4, sym_value) != bfd_reloc_ok)
	BFD_FAIL ();
      break;
    default:
      abort ();
    }

  return true;
}

/* As above, but don't actually build the stub.  Just bump offset so
   we know stub section sizes.  */

static bool
kvx_size_one_stub (struct bfd_hash_entry *gen_entry,
		   void *in_arg ATTRIBUTE_UNUSED)
{
  struct elf_kvx_stub_hash_entry *stub_entry;
  int size;

  /* Massage our args to the form they really have.  */
  stub_entry = (struct elf_kvx_stub_hash_entry *) gen_entry;

  switch (stub_entry->stub_type)
    {
    case kvx_stub_long_branch:
      size = sizeof (elf32_kvx_long_branch_stub);
      break;
    default:
      abort ();
    }

  stub_entry->stub_sec->size += size;
  return true;
}

/* External entry points for sizing and building linker stubs.  */

/* Set up various things so that we can make a list of input sections
   for each output section included in the link.  Returns -1 on error,
   0 when no stubs will be needed, and 1 on success.  */

int
elf32_kvx_setup_section_lists (bfd *output_bfd,
			       struct bfd_link_info *info)
{
  bfd *input_bfd;
  unsigned int bfd_count;
  unsigned int top_id, top_index;
  asection *section;
  asection **input_list, **list;
  bfd_size_type amt;
  struct elf_kvx_link_hash_table *htab =
    elf_kvx_hash_table (info);

  if (!is_elf_hash_table ((const struct bfd_link_hash_table *)htab))
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

/* Used by elf32_kvx_next_input_section and group_sections.  */
#define PREV_SEC(sec) (htab->stub_group[(sec)->id].link_sec)

/* The linker repeatedly calls this function for each input section,
   in the order that input sections are linked into output sections.
   Build lists of input sections to determine groupings between which
   we may insert linker stubs.  */

void
elf32_kvx_next_input_section (struct bfd_link_info *info, asection *isec)
{
  struct elf_kvx_link_hash_table *htab =
    elf_kvx_hash_table (info);

  if (isec->output_section->index <= htab->top_index)
    {
      asection **list = htab->input_list + isec->output_section->index;

      if (*list != bfd_abs_section_ptr)
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
group_sections (struct elf_kvx_link_hash_table *htab,
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

static void
_bfd_kvx_resize_stubs (struct elf_kvx_link_hash_table *htab)
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
      section->size = 0;
    }

  bfd_hash_traverse (&htab->stub_hash_table, kvx_size_one_stub, htab);
}

/* Satisfy the ELF linker by filling in some fields in our fake bfd.  */

bool
kvx_elf32_init_stub_bfd (struct bfd_link_info *info,
			bfd *stub_bfd)
{
  struct elf_kvx_link_hash_table *htab;

  elf_elfheader (stub_bfd)->e_ident[EI_CLASS] = ELFCLASS32;

/* Always hook our dynamic sections into the first bfd, which is the
   linker created stub bfd.  This ensures that the GOT header is at
   the start of the output TOC section.  */
  htab = elf_kvx_hash_table (info);
  if (htab == NULL)
    return false;

  return true;
}

/* Determine and set the size of the stub section for a final link.

   The basic idea here is to examine all the relocations looking for
   PC-relative calls to a target that is unreachable with a 27bits
   immediate (found in call and goto).  */

bool
elf32_kvx_size_stubs (bfd *output_bfd,
		     bfd *stub_bfd,
		     struct bfd_link_info *info,
		     bfd_signed_vma group_size,
		     asection * (*add_stub_section) (const char *,
						     asection *),
		     void (*layout_sections_again) (void))
{
  bfd_size_type stub_group_size;
  bool stubs_always_before_branch;
  bool stub_changed = false;
  struct elf_kvx_link_hash_table *htab = elf_kvx_hash_table (info);

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
      /* KVX branch range is +-256MB. The value used is 1MB less.  */
      stub_group_size = 255 * 1024 * 1024;
    }

  group_sections (htab, stub_group_size, stubs_always_before_branch);

  (*htab->layout_sections_again) ();

  while (1)
    {
      bfd *input_bfd;

      for (input_bfd = info->input_bfds;
	   input_bfd != NULL; input_bfd = input_bfd->link.next)
	{
	  Elf_Internal_Shdr *symtab_hdr;
	  asection *section;
	  Elf_Internal_Sym *local_syms = NULL;

	  if (!is_kvx_elf (input_bfd)
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

	      /* If there aren't any relocs, then there's nothing more
		 to do.  */
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
		  enum elf_kvx_stub_type stub_type;
		  struct elf_kvx_stub_hash_entry *stub_entry;
		  asection *sym_sec;
		  bfd_vma sym_value;
		  bfd_vma destination;
		  struct elf_kvx_link_hash_entry *hash;
		  const char *sym_name;
		  char *stub_name;
		  const asection *id_sec;
		  unsigned char st_type;
		  bfd_size_type len;

		  r_type = ELF32_R_TYPE (irela->r_info);
		  r_indx = ELF32_R_SYM (irela->r_info);

		  if (r_type >= (unsigned int) R_KVX_end)
		    {
		      bfd_set_error (bfd_error_bad_value);
		    error_ret_free_internal:
		      if (elf_section_data (section)->relocs == NULL)
			free (internal_relocs);
		      goto error_ret_free_local;
		    }

		  /* Only look for stubs on unconditional branch and
		     branch and link instructions.  */
		  /* This catches CALL and GOTO insn */
		  if (r_type != (unsigned int) R_KVX_PCREL27)
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
		      hash = ((struct elf_kvx_link_hash_entry *)
			      elf_sym_hashes (input_bfd)[e_indx]);

		      while (hash->root.root.type == bfd_link_hash_indirect
			     || hash->root.root.type == bfd_link_hash_warning)
			hash = ((struct elf_kvx_link_hash_entry *)
				hash->root.root.u.i.link);

		      if (hash->root.root.type == bfd_link_hash_defined
			  || hash->root.root.type == bfd_link_hash_defweak)
			{
			  struct elf_kvx_link_hash_table *globals =
			    elf_kvx_hash_table (info);
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
			  struct elf_kvx_link_hash_table *globals =
			    elf_kvx_hash_table (info);

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
		  stub_type = kvx_type_of_stub (section, irela, sym_sec,
						st_type, destination);
		  if (stub_type == kvx_stub_none)
		    continue;

		  /* Support for grouping stub sections.  */
		  id_sec = htab->stub_group[section->id].link_sec;

		  /* Get the name of this stub.  */
		  stub_name = elf32_kvx_stub_name (id_sec, sym_sec, hash,
						  irela);
		  if (!stub_name)
		    goto error_ret_free_internal;

		  stub_entry =
		    kvx_stub_hash_lookup (&htab->stub_hash_table,
					 stub_name, false, false);
		  if (stub_entry != NULL)
		    {
		      /* The proper stub has already been created.  */
		      free (stub_name);
		      /* Always update this stub's target since it may have
			 changed after layout.  */
		      stub_entry->target_value = sym_value + irela->r_addend;
		      continue;
		    }

		  stub_entry = _bfd_kvx_add_stub_entry_in_group
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

		  stub_changed = true;
		}

	      /* We're done with the internal relocs, free them.  */
	      if (elf_section_data (section)->relocs == NULL)
		free (internal_relocs);
	    }
	}

      if (!stub_changed)
	break;

      _bfd_kvx_resize_stubs (htab);

      /* Ask the linker to do its stuff.  */
      (*htab->layout_sections_again) ();
      stub_changed = false;
    }

  return true;

error_ret_free_local:
  return false;

}

/* Build all the stubs associated with the current output file.  The
   stubs are kept in a hash table attached to the main linker hash
   table.  We also set up the .plt entries for statically linked PIC
   functions here.  This function is called via kvx_elf_finish in the
   linker.  */

bool
elf32_kvx_build_stubs (struct bfd_link_info *info)
{
  asection *stub_sec;
  struct bfd_hash_table *table;
  struct elf_kvx_link_hash_table *htab;

  htab = elf_kvx_hash_table (info);

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
    }

  /* Build the stubs as directed by the stub hash table.  */
  table = &htab->stub_hash_table;
  bfd_hash_traverse (table, kvx_build_one_stub, info);

  return true;
}

static bfd_vma
kvx_calculate_got_entry_vma (struct elf_link_hash_entry *h,
				 struct elf_kvx_link_hash_table
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
    }

  return off;
}

static unsigned int
kvx_reloc_got_type (bfd_reloc_code_real_type r_type)
{
  switch (r_type)
    {
      /* Extracted with:
	 awk 'match ($0, /HOWTO.*R_(KVX.*_GOT(OFF)?(64)?_.*),/,ary) \
	 {print "case BFD_RELOC_" ary[1] ":";}' elfxx-kvxc.def  */
    case BFD_RELOC_KVX_S37_GOTOFF_LO10:
    case BFD_RELOC_KVX_S37_GOTOFF_UP27:

    case BFD_RELOC_KVX_S37_GOT_LO10:
    case BFD_RELOC_KVX_S37_GOT_UP27:

    case BFD_RELOC_KVX_S43_GOTOFF_LO10:
    case BFD_RELOC_KVX_S43_GOTOFF_UP27:
    case BFD_RELOC_KVX_S43_GOTOFF_EX6:

    case BFD_RELOC_KVX_S43_GOT_LO10:
    case BFD_RELOC_KVX_S43_GOT_UP27:
    case BFD_RELOC_KVX_S43_GOT_EX6:
      return GOT_NORMAL;

    case BFD_RELOC_KVX_S37_TLS_GD_LO10:
    case BFD_RELOC_KVX_S37_TLS_GD_UP27:
    case BFD_RELOC_KVX_S43_TLS_GD_LO10:
    case BFD_RELOC_KVX_S43_TLS_GD_UP27:
    case BFD_RELOC_KVX_S43_TLS_GD_EX6:
      return GOT_TLS_GD;

    case BFD_RELOC_KVX_S37_TLS_LD_LO10:
    case BFD_RELOC_KVX_S37_TLS_LD_UP27:
    case BFD_RELOC_KVX_S43_TLS_LD_LO10:
    case BFD_RELOC_KVX_S43_TLS_LD_UP27:
    case BFD_RELOC_KVX_S43_TLS_LD_EX6:
      return GOT_TLS_LD;

    case BFD_RELOC_KVX_S37_TLS_IE_LO10:
    case BFD_RELOC_KVX_S37_TLS_IE_UP27:
    case BFD_RELOC_KVX_S43_TLS_IE_LO10:
    case BFD_RELOC_KVX_S43_TLS_IE_UP27:
    case BFD_RELOC_KVX_S43_TLS_IE_EX6:
      return GOT_TLS_IE;

    default:
      break;
    }
  return GOT_UNKNOWN;
}

static bool
kvx_can_relax_tls (bfd *input_bfd ATTRIBUTE_UNUSED,
		       struct bfd_link_info *info ATTRIBUTE_UNUSED,
		       bfd_reloc_code_real_type r_type ATTRIBUTE_UNUSED,
		       struct elf_link_hash_entry *h ATTRIBUTE_UNUSED,
		       unsigned long r_symndx ATTRIBUTE_UNUSED)
{
  if (! IS_KVX_TLS_RELAX_RELOC (r_type))
    return false;

  /* Relaxing hook. Disabled on KVX. */
  /* See elfnn-aarch64.c */
  return true;
}

/* Given the relocation code R_TYPE, return the relaxed bfd reloc
   enumerator.  */

static bfd_reloc_code_real_type
kvx_tls_transition (bfd *input_bfd,
			struct bfd_link_info *info,
			unsigned int r_type,
			struct elf_link_hash_entry *h,
			unsigned long r_symndx)
{
  bfd_reloc_code_real_type bfd_r_type
    = elf32_kvx_bfd_reloc_from_type (input_bfd, r_type);

  if (! kvx_can_relax_tls (input_bfd, info, bfd_r_type, h, r_symndx))
    return bfd_r_type;

  return bfd_r_type;
}

/* Return the base VMA address which should be subtracted from real addresses
   when resolving R_KVX_*_TLS_GD_* and R_KVX_*_TLS_LD_* relocation.  */

static bfd_vma
dtpoff_base (struct bfd_link_info *info)
{
  /* If tls_sec is NULL, we should have signalled an error already.  */
  BFD_ASSERT (elf_hash_table (info)->tls_sec != NULL);
  return elf_hash_table (info)->tls_sec->vma;
}

/* Return the base VMA address which should be subtracted from real addresses
   when resolving R_KVX_*_TLS_IE_* and R_KVX_*_TLS_LE_* relocations.  */

static bfd_vma
tpoff_base (struct bfd_link_info *info)
{
  struct elf_link_hash_table *htab = elf_hash_table (info);

  /* If tls_sec is NULL, we should have signalled an error already.  */
  BFD_ASSERT (htab->tls_sec != NULL);

  bfd_vma base = align_power ((bfd_vma) 0,
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
      struct elf_kvx_local_symbol *l;

      l = elf_kvx_locals (input_bfd);
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

/* N_ONES produces N one bits, without overflowing machine arithmetic.  */
#define N_ONES(n) (((((bfd_vma) 1 << ((n) -1)) - 1) << 1) | 1)

/* This is a copy/paste + modification from
   reloc.c:_bfd_relocate_contents. Relocations are applied to 32bits
   words, so all overflow checks will overflow for values above
   32bits.  */
static bfd_reloc_status_type
check_signed_overflow (enum complain_overflow complain_on_overflow,
		       bfd_reloc_code_real_type bfd_r_type, bfd *input_bfd,
		       bfd_vma relocation)
{
  bfd_reloc_status_type flag = bfd_reloc_ok;
  bfd_vma addrmask, fieldmask, signmask, ss;
  bfd_vma a, b, sum;
  bfd_vma x = 0;

  /* These usually come from howto struct. As we don't check for
     values fitting in bitfields or in subpart of words, we set all
     these to values to check as if the field is starting from first
     bit.  */
  unsigned int rightshift = 0;
  unsigned int bitpos = 0;
  unsigned int bitsize = 0;
  bfd_vma src_mask = -1;

  /* Only regular symbol relocations are checked here. Others
     relocations (GOT, TLS) could be checked if the need is
     confirmed. At the moment, we keep previous behavior
     (ie. unchecked) for those. */
  switch (bfd_r_type)
    {
    case BFD_RELOC_KVX_S37_LO10:
    case BFD_RELOC_KVX_S37_UP27:
      bitsize = 37;
      break;

    case BFD_RELOC_KVX_S32_LO5:
    case BFD_RELOC_KVX_S32_UP27:
      bitsize = 32;
      break;

    case BFD_RELOC_KVX_S43_LO10:
    case BFD_RELOC_KVX_S43_UP27:
    case BFD_RELOC_KVX_S43_EX6:
      bitsize = 43;
      break;

    case BFD_RELOC_KVX_S64_LO10:
    case BFD_RELOC_KVX_S64_UP27:
    case BFD_RELOC_KVX_S64_EX27:
      bitsize = 64;
      break;

    default:
      return bfd_reloc_ok;
    }

  /* direct copy/paste from reloc.c below */

  /* Get the values to be added together.  For signed and unsigned
     relocations, we assume that all values should be truncated to
     the size of an address.  For bitfields, all the bits matter.
     See also bfd_check_overflow.  */
  fieldmask = N_ONES (bitsize);
  signmask = ~fieldmask;
  addrmask = (N_ONES (bfd_arch_bits_per_address (input_bfd))
	      | (fieldmask << rightshift));
  a = (relocation & addrmask) >> rightshift;
  b = (x & src_mask & addrmask) >> bitpos;
  addrmask >>= rightshift;

  switch (complain_on_overflow)
    {
    case complain_overflow_signed:
      /* If any sign bits are set, all sign bits must be set.
	 That is, A must be a valid negative address after
	 shifting.  */
      signmask = ~(fieldmask >> 1);
      /* Fall thru */

    case complain_overflow_bitfield:
      /* Much like the signed check, but for a field one bit
	 wider.  We allow a bitfield to represent numbers in the
	 range -2**n to 2**n-1, where n is the number of bits in the
	 field.  Note that when bfd_vma is 32 bits, a 32-bit reloc
	 can't overflow, which is exactly what we want.  */
      ss = a & signmask;
      if (ss != 0 && ss != (addrmask & signmask))
	flag = bfd_reloc_overflow;

      /* We only need this next bit of code if the sign bit of B
	 is below the sign bit of A.  This would only happen if
	 SRC_MASK had fewer bits than BITSIZE.  Note that if
	 SRC_MASK has more bits than BITSIZE, we can get into
	 trouble; we would need to verify that B is in range, as
	 we do for A above.  */
      ss = ((~src_mask) >> 1) & src_mask;
      ss >>= bitpos;

      /* Set all the bits above the sign bit.  */
      b = (b ^ ss) - ss;

      /* Now we can do the addition.  */
      sum = a + b;

      /* See if the result has the correct sign.  Bits above the
	 sign bit are junk now; ignore them.  If the sum is
	 positive, make sure we did not have all negative inputs;
	 if the sum is negative, make sure we did not have all
	 positive inputs.  The test below looks only at the sign
	 bits, and it really just
	 SIGN (A) == SIGN (B) && SIGN (A) != SIGN (SUM)

	 We mask with addrmask here to explicitly allow an address
	 wrap-around.  The Linux kernel relies on it, and it is
	 the only way to write assembler code which can run when
	 loaded at a location 0x80000000 away from the location at
	 which it is linked.  */
      if (((~(a ^ b)) & (a ^ sum)) & signmask & addrmask)
	flag = bfd_reloc_overflow;
      break;

    case complain_overflow_unsigned:
      /* Checking for an unsigned overflow is relatively easy:
	 trim the addresses and add, and trim the result as well.
	 Overflow is normally indicated when the result does not
	 fit in the field.  However, we also need to consider the
	 case when, e.g., fieldmask is 0x7fffffff or smaller, an
	 input is 0x80000000, and bfd_vma is only 32 bits; then we
	 will get sum == 0, but there is an overflow, since the
	 inputs did not fit in the field.  Instead of doing a
	 separate test, we can check for this by or-ing in the
	 operands when testing for the sum overflowing its final
	 field.  */
      sum = (a + b) & addrmask;
      if ((a | b | sum) & signmask)
	flag = bfd_reloc_overflow;
      break;

    default:
      abort ();
    }
  return flag;
}

/* Perform a relocation as part of a final link.  */
static bfd_reloc_status_type
elf32_kvx_final_link_relocate (reloc_howto_type *howto,
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
    = elf32_kvx_bfd_reloc_from_howto (howto);
  bfd_reloc_code_real_type new_bfd_r_type;
  unsigned long r_symndx;
  bfd_byte *hit_data = contents + rel->r_offset;
  bfd_vma place, off;
  bfd_vma addend;
  struct elf_kvx_link_hash_table *globals;
  bool weak_undef_p;
  asection *base_got;
  bfd_reloc_status_type rret = bfd_reloc_ok;
  bool resolved_to_zero;
  globals = elf_kvx_hash_table (info);

  symtab_hdr = &elf_symtab_hdr (input_bfd);

  BFD_ASSERT (is_kvx_elf (input_bfd));

  r_symndx = ELF32_R_SYM (rel->r_info);

  /* It is possible to have linker relaxations on some TLS access
     models.  Update our information here.  */
  new_bfd_r_type = kvx_tls_transition (input_bfd, info, r_type, h, r_symndx);
  if (new_bfd_r_type != bfd_r_type)
    {
      bfd_r_type = new_bfd_r_type;
      howto = elf32_kvx_howto_from_bfd_reloc (bfd_r_type);
      BFD_ASSERT (howto != NULL);
      r_type = howto->type;
    }

  place = input_section->output_section->vma
    + input_section->output_offset + rel->r_offset;

  /* Get addend, accumulating the addend for consecutive relocs
     which refer to the same offset.  */
  addend = saved_addend ? *saved_addend : 0;
  addend += rel->r_addend;

  weak_undef_p = (h ? h->root.type == bfd_link_hash_undefweak
		  : bfd_is_und_section (sym_sec));
  resolved_to_zero = (h != NULL
		      && UNDEFWEAK_NO_DYNAMIC_RELOC (info, h));

  switch (bfd_r_type)
    {
    case BFD_RELOC_KVX_32:
#if ARCH_SIZE == 64
    case BFD_RELOC_KVX_32:
#endif
    case BFD_RELOC_KVX_S37_LO10:
    case BFD_RELOC_KVX_S37_UP27:

    case BFD_RELOC_KVX_S32_LO5:
    case BFD_RELOC_KVX_S32_UP27:

    case BFD_RELOC_KVX_S43_LO10:
    case BFD_RELOC_KVX_S43_UP27:
    case BFD_RELOC_KVX_S43_EX6:

    case BFD_RELOC_KVX_S64_LO10:
    case BFD_RELOC_KVX_S64_UP27:
    case BFD_RELOC_KVX_S64_EX27:
      /* When generating a shared library or PIE, these relocations
	 are copied into the output file to be resolved at run time.  */
      if (bfd_link_pic (info)
	  && (input_section->flags & SEC_ALLOC)
	  && (h == NULL
	      || (ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
		  && !resolved_to_zero)
	      || h->root.type != bfd_link_hash_undefweak))
	{
	  Elf_Internal_Rela outrel;
	  bfd_byte *loc;
	  bool skip, relocate;
	  asection *sreloc;

	  *unresolved_reloc_p = false;

	  skip = false;
	  relocate = false;

	  outrel.r_addend = addend;
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

	  outrel.r_offset += (input_section->output_section->vma
			      + input_section->output_offset);

	  if (skip)
	    memset (&outrel, 0, sizeof outrel);
	  else if (h != NULL
		   && h->dynindx != -1
		   && (!bfd_link_pic (info) || !info->symbolic
		       || !h->def_regular))
	    outrel.r_info = ELF32_R_INFO (h->dynindx, r_type);
	  else if (bfd_r_type == BFD_RELOC_KVX_32
		   || bfd_r_type == BFD_RELOC_KVX_64)
	    {
	      int symbol;

	      /* On SVR4-ish systems, the dynamic loader cannot
		 relocate the text and data segments independently,
		 so the symbol does not matter.  */
	      symbol = 0;
	      outrel.r_info = ELF32_R_INFO (symbol, R_KVX_RELATIVE);
	      outrel.r_addend += value;
	    }
	  else if (bfd_link_pic (info) && info->symbolic)
	    {
	      goto skip_because_pic;
	    }
	  else
	    {
	      /* We may endup here from bad input code trying to
		 insert relocation on symbols within code.  We do not
		 want that currently, and such code should use GOT +
		 KVX_32/64 reloc that translate in KVX_RELATIVE.  */
	      const char *name;
	      if (h && h->root.root.string)
		name = h->root.root.string;
	      else
		name = bfd_elf_sym_name (input_bfd, symtab_hdr, sym,
					 NULL);

	      (*_bfd_error_handler)
		/* xgettext:c-format */
		(_("%pB(%pA+%#" PRIx64 "): "
		   "unresolvable %s relocation in section `%s'"),
		 input_bfd, input_section, (uint64_t) rel->r_offset, howto->name,
		 name);
	      return bfd_reloc_notsupported;
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

	  rret = check_signed_overflow (complain_overflow_signed, bfd_r_type,
					input_bfd, value + addend);
	  if (rret != bfd_reloc_ok)
	    return rret;

	  return _bfd_final_link_relocate (howto, input_bfd, input_section,
					   contents, rel->r_offset, value,
					   addend);
	}

    skip_because_pic:
      rret = check_signed_overflow (complain_overflow_signed, bfd_r_type,
				    input_bfd, value + addend);
      if (rret != bfd_reloc_ok)
	return rret;

      return _bfd_final_link_relocate (howto, input_bfd, input_section,
				       contents, rel->r_offset, value,
				       addend);
      break;

    case BFD_RELOC_KVX_PCREL17:
    case BFD_RELOC_KVX_PCREL27:
      {
	/* BCU insn are always first in a bundle, so there is no need
	   to correct the address using offset within bundle.  */

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
	struct elf_kvx_stub_hash_entry *stub_entry = NULL;

	/* If the target symbol is global and marked as a function the
	   relocation applies a function call or a tail call.  In this
	   situation we can veneer out of range branches.  The veneers
	   use R16 and R17 hence cannot be used arbitrary out of range
	   branches that occur within the body of a function.  */

	/* Check if a stub has to be inserted because the destination
	   is too far away.  */
	if (! kvx_valid_call_p (value, place))
	  {
	    /* The target is out of reach, so redirect the branch to
	       the local stub for this function.  */
	    stub_entry = elf32_kvx_get_stub_entry (input_section,
						   sym_sec, h,
						   rel, globals);
	    if (stub_entry != NULL)
	      value = (stub_entry->stub_offset
		       + stub_entry->stub_sec->output_offset
		       + stub_entry->stub_sec->output_section->vma);
	    /* We have redirected the destination to stub entry address,
	       so ignore any addend record in the original rela entry.  */
	    addend = 0;
	  }
      }
      *unresolved_reloc_p = false;

      /* FALLTHROUGH */

      /* PCREL 32 are used in dwarf2 table for exception handling */
    case BFD_RELOC_KVX_32_PCREL:
    case BFD_RELOC_KVX_S64_PCREL_LO10:
    case BFD_RELOC_KVX_S64_PCREL_UP27:
    case BFD_RELOC_KVX_S64_PCREL_EX27:
    case BFD_RELOC_KVX_S37_PCREL_LO10:
    case BFD_RELOC_KVX_S37_PCREL_UP27:
    case BFD_RELOC_KVX_S43_PCREL_LO10:
    case BFD_RELOC_KVX_S43_PCREL_UP27:
    case BFD_RELOC_KVX_S43_PCREL_EX6:
      return _bfd_final_link_relocate (howto, input_bfd, input_section,
				       contents, rel->r_offset, value,
				       addend);
      break;

    case BFD_RELOC_KVX_S37_TLS_LE_LO10:
    case BFD_RELOC_KVX_S37_TLS_LE_UP27:

    case BFD_RELOC_KVX_S43_TLS_LE_LO10:
    case BFD_RELOC_KVX_S43_TLS_LE_UP27:
    case BFD_RELOC_KVX_S43_TLS_LE_EX6:
      return _bfd_final_link_relocate (howto, input_bfd, input_section,
				       contents, rel->r_offset,
				       value - tpoff_base (info), addend);
      break;

    case BFD_RELOC_KVX_S37_TLS_DTPOFF_LO10:
    case BFD_RELOC_KVX_S37_TLS_DTPOFF_UP27:

    case BFD_RELOC_KVX_S43_TLS_DTPOFF_LO10:
    case BFD_RELOC_KVX_S43_TLS_DTPOFF_UP27:
    case BFD_RELOC_KVX_S43_TLS_DTPOFF_EX6:
      return _bfd_final_link_relocate (howto, input_bfd, input_section,
				       contents, rel->r_offset,
				       value - dtpoff_base (info), addend);

    case BFD_RELOC_KVX_S37_TLS_GD_UP27:
    case BFD_RELOC_KVX_S37_TLS_GD_LO10:

    case BFD_RELOC_KVX_S43_TLS_GD_UP27:
    case BFD_RELOC_KVX_S43_TLS_GD_EX6:
    case BFD_RELOC_KVX_S43_TLS_GD_LO10:

    case BFD_RELOC_KVX_S37_TLS_IE_UP27:
    case BFD_RELOC_KVX_S37_TLS_IE_LO10:

    case BFD_RELOC_KVX_S43_TLS_IE_UP27:
    case BFD_RELOC_KVX_S43_TLS_IE_EX6:
    case BFD_RELOC_KVX_S43_TLS_IE_LO10:

    case BFD_RELOC_KVX_S37_TLS_LD_UP27:
    case BFD_RELOC_KVX_S37_TLS_LD_LO10:

    case BFD_RELOC_KVX_S43_TLS_LD_UP27:
    case BFD_RELOC_KVX_S43_TLS_LD_EX6:
    case BFD_RELOC_KVX_S43_TLS_LD_LO10:

      if (globals->root.sgot == NULL)
	return bfd_reloc_notsupported;
      value = symbol_got_offset (input_bfd, h, r_symndx);

      _bfd_final_link_relocate (howto, input_bfd, input_section,
				contents, rel->r_offset, value, addend);
      *unresolved_reloc_p = false;
      break;

    case BFD_RELOC_KVX_S37_GOTADDR_UP27:
    case BFD_RELOC_KVX_S37_GOTADDR_LO10:

    case BFD_RELOC_KVX_S43_GOTADDR_UP27:
    case BFD_RELOC_KVX_S43_GOTADDR_EX6:
    case BFD_RELOC_KVX_S43_GOTADDR_LO10:

    case BFD_RELOC_KVX_S64_GOTADDR_UP27:
    case BFD_RELOC_KVX_S64_GOTADDR_EX27:
    case BFD_RELOC_KVX_S64_GOTADDR_LO10:
      {
	if (globals->root.sgot == NULL)
	  BFD_ASSERT (h != NULL);

	value = globals->root.sgot->output_section->vma
	  + globals->root.sgot->output_offset;

	return _bfd_final_link_relocate (howto, input_bfd, input_section,
					 contents, rel->r_offset, value,
					 addend);
      }
      break;

    case BFD_RELOC_KVX_S37_GOTOFF_LO10:
    case BFD_RELOC_KVX_S37_GOTOFF_UP27:

    case BFD_RELOC_KVX_32_GOTOFF:
    case BFD_RELOC_KVX_64_GOTOFF:

    case BFD_RELOC_KVX_S43_GOTOFF_LO10:
    case BFD_RELOC_KVX_S43_GOTOFF_UP27:
    case BFD_RELOC_KVX_S43_GOTOFF_EX6:

      {
	asection *basegot = globals->root.sgot;
	/* BFD_ASSERT(h == NULL); */
	BFD_ASSERT(globals->root.sgot != NULL);
	value -= basegot->output_section->vma + basegot->output_offset;
	return _bfd_final_link_relocate (howto, input_bfd, input_section,
					 contents, rel->r_offset, value,
					 addend);
      }
      break;

    case BFD_RELOC_KVX_S37_GOT_LO10:
    case BFD_RELOC_KVX_S37_GOT_UP27:

    case BFD_RELOC_KVX_32_GOT:
    case BFD_RELOC_KVX_64_GOT:

    case BFD_RELOC_KVX_S43_GOT_LO10:
    case BFD_RELOC_KVX_S43_GOT_UP27:
    case BFD_RELOC_KVX_S43_GOT_EX6:

      if (globals->root.sgot == NULL)
	BFD_ASSERT (h != NULL);

      if (h != NULL)
	{
	  value = kvx_calculate_got_entry_vma (h, globals, info, value,
					       output_bfd,
					       unresolved_reloc_p);
#ifdef UGLY_DEBUG
	  printf("GOT_LO/HI for %s, value %x\n", h->root.root.string, value);
#endif

	  return _bfd_final_link_relocate (howto, input_bfd, input_section,
					   contents, rel->r_offset, value,
					   addend);
	}
      else
	{
#ifdef UGLY_DEBUG
	  printf("GOT_LO/HI with h NULL, initial value %x\n", value);
#endif
	  struct elf_kvx_local_symbol *locals = elf_kvx_locals (input_bfd);

	  if (locals == NULL)
	    {
	      int howto_index = bfd_r_type - BFD_RELOC_KVX_RELOC_START;
	      _bfd_error_handler
		/* xgettext:c-format */
		(_("%pB: local symbol descriptor table be NULL when applying "
		   "relocation %s against local symbol"),
		 input_bfd, elf_kvx_howto_table[howto_index].name);
	      abort ();
	    }

	  off = symbol_got_offset (input_bfd, h, r_symndx);
	  base_got = globals->root.sgot;
	  bfd_vma got_entry_addr = (base_got->output_section->vma
				    + base_got->output_offset + off);

	  if (!symbol_got_offset_mark_p (input_bfd, h, r_symndx))
	    {
	      bfd_put_64 (output_bfd, value, base_got->contents + off);

	      if (bfd_link_pic (info))
		{
		  asection *s;
		  Elf_Internal_Rela outrel;

		  /* For PIC executables and shared libraries we need
		     to relocate the GOT entry at run time.  */
		  s = globals->root.srelgot;
		  if (s == NULL)
		    abort ();

		  outrel.r_offset = got_entry_addr;
		  outrel.r_info = ELF32_R_INFO (0, R_KVX_RELATIVE);
		  outrel.r_addend = value;
		  elf_append_rela (output_bfd, s, &outrel);
		}

	      symbol_got_offset_mark (input_bfd, h, r_symndx);
	    }

	  /* Update the relocation value to GOT entry addr as we have
	     transformed the direct data access into an indirect data
	     access through GOT.  */
	  value = got_entry_addr;

	  return _bfd_final_link_relocate (howto, input_bfd, input_section,
					   contents, rel->r_offset, off, 0);
	}
      break;

    default:
      return bfd_reloc_notsupported;
    }

  if (saved_addend)
    *saved_addend = value;

  /* Only apply the final relocation in a sequence.  */
  if (save_addend)
    return bfd_reloc_continue;

  return _bfd_kvx_elf_put_addend (input_bfd, hit_data, bfd_r_type,
				  howto, value);
}



/* Relocate a KVX ELF section.  */

static int
elf32_kvx_relocate_section (bfd *output_bfd,
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
  struct elf_kvx_link_hash_table *globals;
  bool save_addend = false;
  bfd_vma addend = 0;

  globals = elf_kvx_hash_table (info);

  symtab_hdr = &elf_symtab_hdr (input_bfd);
  sym_hashes = elf_sym_hashes (input_bfd);

  rel = relocs;
  relend = relocs + input_section->reloc_count;
  for (; rel < relend; rel++)
    {
      unsigned int r_type;
      bfd_reloc_code_real_type bfd_r_type;
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

      bfd_reloc.howto = elf32_kvx_howto_from_type (input_bfd, r_type);
      howto = bfd_reloc.howto;

      if (howto == NULL)
	return _bfd_unrecognized_reloc (input_bfd, input_section, r_type);

      bfd_r_type = elf32_kvx_bfd_reloc_from_howto (howto);

      h = NULL;
      sym = NULL;
      sec = NULL;

      if (r_symndx < symtab_hdr->sh_info) /* A local symbol. */
	{
	  sym = local_syms + r_symndx;
	  sym_type = ELF32_ST_TYPE (sym->st_info);
	  sec = local_sections[r_symndx];

	  /* An object file might have a reference to a local
	     undefined symbol.  This is a draft object file, but we
	     should at least do something about it.  */
	  if (r_type != R_KVX_NONE
	      && r_type != R_KVX_S37_GOTADDR_LO10
	      && r_type != R_KVX_S37_GOTADDR_UP27
	      && r_type != R_KVX_S64_GOTADDR_LO10
	      && r_type != R_KVX_S64_GOTADDR_UP27
	      && r_type != R_KVX_S64_GOTADDR_EX27
	      && r_type != R_KVX_S43_GOTADDR_LO10
	      && r_type != R_KVX_S43_GOTADDR_UP27
	      && r_type != R_KVX_S43_GOTADDR_EX6
	      && bfd_is_und_section (sec)
	      && ELF_ST_BIND (sym->st_info) != STB_WEAK)
	    (*info->callbacks->undefined_symbol)
	      (info, bfd_elf_string_from_elf_section
	       (input_bfd, symtab_hdr->sh_link, sym->st_name),
	       input_bfd, input_section, rel->r_offset, true);

	  relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
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
					 rel, 1, relend, R_KVX_NONE,
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
	  && r_type != R_KVX_NONE
	  && (h == NULL
	      || h->root.type == bfd_link_hash_defined
	      || h->root.type == bfd_link_hash_defweak)
	  && IS_KVX_TLS_RELOC (bfd_r_type) != (sym_type == STT_TLS))
	{
	  (*_bfd_error_handler)
	    ((sym_type == STT_TLS
	      /* xgettext:c-format */
	      ? _("%pB(%pA+%#" PRIx64 "): %s used with TLS symbol %s")
	      /* xgettext:c-format */
	      : _("%pB(%pA+%#" PRIx64 "): %s used with non-TLS symbol %s")),
	     input_bfd,
	     input_section, (uint64_t) rel->r_offset, howto->name, name);
	}

      /* Original aarch64 has relaxation handling for TLS here. */
      r = bfd_reloc_continue;

      /* There may be multiple consecutive relocations for the
	 same offset.  In that case we are supposed to treat the
	 output of each relocation as the addend for the next.  */
      if (rel + 1 < relend
	  && rel->r_offset == rel[1].r_offset
	  && ELF32_R_TYPE (rel[1].r_info) != R_KVX_NONE)

	save_addend = true;
      else
	save_addend = false;

      if (r == bfd_reloc_continue)
	r = elf32_kvx_final_link_relocate (howto, input_bfd, output_bfd,
					   input_section, contents, rel,
					   relocation, info, sec,
					   h, &unresolved_reloc,
					   save_addend, &addend, sym);

      switch (elf32_kvx_bfd_reloc_from_type (input_bfd, r_type))
	{
	case BFD_RELOC_KVX_S37_TLS_GD_LO10:
	case BFD_RELOC_KVX_S37_TLS_GD_UP27:

	case BFD_RELOC_KVX_S43_TLS_GD_LO10:
	case BFD_RELOC_KVX_S43_TLS_GD_UP27:
	case BFD_RELOC_KVX_S43_TLS_GD_EX6:

	case BFD_RELOC_KVX_S37_TLS_LD_LO10:
	case BFD_RELOC_KVX_S37_TLS_LD_UP27:

	case BFD_RELOC_KVX_S43_TLS_LD_LO10:
	case BFD_RELOC_KVX_S43_TLS_LD_UP27:
	case BFD_RELOC_KVX_S43_TLS_LD_EX6:

	  if (! symbol_got_offset_mark_p (input_bfd, h, r_symndx))
	    {
	      bool need_relocs = false;
	      bfd_byte *loc;
	      int indx;
	      bfd_vma off;

	      off = symbol_got_offset (input_bfd, h, r_symndx);
	      indx = h && h->dynindx != -1 ? h->dynindx : 0;

	      need_relocs =
		(bfd_link_pic (info) || indx != 0) &&
		(h == NULL
		 || ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
		 || h->root.type != bfd_link_hash_undefweak);

	      BFD_ASSERT (globals->root.srelgot != NULL);

	      if (need_relocs)
		{
		  Elf_Internal_Rela rela;
		  rela.r_info = ELF32_R_INFO (indx, R_KVX_64_DTPMOD);
		  rela.r_addend = 0;
		  rela.r_offset = globals->root.sgot->output_section->vma +
		    globals->root.sgot->output_offset + off;

		  loc = globals->root.srelgot->contents;
		  loc += globals->root.srelgot->reloc_count++
		    * RELOC_SIZE (htab);
		  bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);

		  bfd_reloc_code_real_type real_type =
		    elf32_kvx_bfd_reloc_from_type (input_bfd, r_type);

		  if (real_type == BFD_RELOC_KVX_S37_TLS_LD_LO10
		      || real_type == BFD_RELOC_KVX_S37_TLS_LD_UP27
		      || real_type == BFD_RELOC_KVX_S43_TLS_LD_LO10
		      || real_type == BFD_RELOC_KVX_S43_TLS_LD_UP27
		      || real_type == BFD_RELOC_KVX_S43_TLS_LD_EX6)
		    {
		      /* For local dynamic, don't generate DTPOFF in any case.
			 Initialize the DTPOFF slot into zero, so we get module
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
			ELF32_R_INFO (indx, R_KVX_64_DTPOFF);
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

	case BFD_RELOC_KVX_S37_TLS_IE_LO10:
	case BFD_RELOC_KVX_S37_TLS_IE_UP27:

	case BFD_RELOC_KVX_S43_TLS_IE_LO10:
	case BFD_RELOC_KVX_S43_TLS_IE_UP27:
	case BFD_RELOC_KVX_S43_TLS_IE_EX6:
	  if (! symbol_got_offset_mark_p (input_bfd, h, r_symndx))
	    {
	      bool need_relocs = false;
	      bfd_byte *loc;
	      int indx;
	      bfd_vma off;

	      off = symbol_got_offset (input_bfd, h, r_symndx);

	      indx = h && h->dynindx != -1 ? h->dynindx : 0;

	      need_relocs =
		(bfd_link_pic (info) || indx != 0) &&
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

		  rela.r_info = ELF32_R_INFO (indx, R_KVX_64_TPOFF);
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
	  (*_bfd_error_handler)
	    /* xgettext:c-format */
	    (_("%pB(%pA+%#" PRIx64 "): "
	       "unresolvable %s relocation against symbol `%s'"),
	     input_bfd, input_section, (uint64_t) rel->r_offset, howto->name,
	     h->root.root.string);
	  return false;
	}

      if (r != bfd_reloc_ok && r != bfd_reloc_continue)
	{
	  switch (r)
	    {
	    case bfd_reloc_overflow:
	      (*info->callbacks->reloc_overflow)
		(info, (h ? &h->root : NULL), name, howto->name, (bfd_vma) 0,
		 input_bfd, input_section, rel->r_offset);

	      /* Original aarch64 code had a check for alignement correctness */
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
elf32_kvx_object_p (bfd *abfd)
{
  /* must be coherent with default arch in cpu-kvx.c */
  int e_set = bfd_mach_kv3_1;

  if (elf_elfheader (abfd)->e_machine == EM_KVX)
    {
      int e_core = elf_elfheader (abfd)->e_flags & ELF_KVX_CORE_MASK;
      switch(e_core)
	{
#if ARCH_SIZE == 64
	case ELF_KVX_CORE_KV3_1 : e_set = bfd_mach_kv3_1_64; break;
	case ELF_KVX_CORE_KV3_2 : e_set = bfd_mach_kv3_2_64; break;
	case ELF_KVX_CORE_KV4_1 : e_set = bfd_mach_kv4_1_64; break;
#else
	case ELF_KVX_CORE_KV3_1 : e_set = bfd_mach_kv3_1; break;
	case ELF_KVX_CORE_KV3_2 : e_set = bfd_mach_kv3_2; break;
	case ELF_KVX_CORE_KV4_1 : e_set = bfd_mach_kv4_1; break;
#endif
	default:
	  (*_bfd_error_handler)(_("%s: Bad ELF id: `%d'"),
				abfd->filename, e_core);
	}
    }
  return bfd_default_set_arch_mach (abfd, bfd_arch_kvx, e_set);
}

/* Function to keep KVX specific flags in the ELF header.  */

static bool
elf32_kvx_set_private_flags (bfd *abfd, flagword flags)
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
elf32_kvx_merge_private_bfd_data (bfd *ibfd, struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;
  flagword out_flags;
  flagword in_flags;
  bool flags_compatible = true;
  asection *sec;

  /* Check if we have the same endianess.  */
  if (!_bfd_generic_verify_endian_match (ibfd, info))
    return false;

  if (!is_kvx_elf (ibfd) || !is_kvx_elf (obfd))
    return true;

  /* The input BFD must have had its flags initialised.  */
  /* The following seems bogus to me -- The flags are initialized in
     the assembler but I don't think an elf_flags_init field is
     written into the object.  */
  /* BFD_ASSERT (elf_flags_init (ibfd)); */

  if (bfd_get_arch_size (ibfd) != bfd_get_arch_size (obfd))
    {
      const char *msg;

      if (bfd_get_arch_size (ibfd) == 32
	  && bfd_get_arch_size (obfd) == 64)
	msg = _("%s: compiled as 32-bit object and %s is 64-bit");
      else if (bfd_get_arch_size (ibfd) == 64
	       && bfd_get_arch_size (obfd) == 32)
	msg = _("%s: compiled as 64-bit object and %s is 32-bit");
      else
	msg = _("%s: object size does not match that of target %s");

      (*_bfd_error_handler) (msg, bfd_get_filename (ibfd),
			     bfd_get_filename (obfd));
      bfd_set_error (bfd_error_wrong_format);
      return false;
    }

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
elf32_kvx_print_private_bfd_data (bfd *abfd, void *ptr)
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
  fprintf (file, _("Private flags = 0x%lx : "), elf_elfheader (abfd)->e_flags);
  if((flags & ELF_KVX_ABI_64B_ADDR_BIT) == ELF_KVX_ABI_64B_ADDR_BIT)
    {
      if (ELF_KVX_CHECK_CORE(flags,ELF_KVX_CORE_KV3_1))
	fprintf (file, _("Coolidge (kv3) V1 64 bits"));
      else if (ELF_KVX_CHECK_CORE(flags,ELF_KVX_CORE_KV3_2))
	fprintf (file, _("Coolidge (kv3) V2 64 bits"));
      else if (ELF_KVX_CHECK_CORE(flags,ELF_KVX_CORE_KV4_1))
	fprintf (file, _("Coolidge (kv4) V1 64 bits"));
    }
  else
    {
      if (ELF_KVX_CHECK_CORE(flags,ELF_KVX_CORE_KV3_1))
	fprintf (file, _("Coolidge (kv3) V1 32 bits"));
      else if (ELF_KVX_CHECK_CORE(flags,ELF_KVX_CORE_KV3_2))
	fprintf (file, _("Coolidge (kv3) V2 32 bits"));
      else if (ELF_KVX_CHECK_CORE(flags,ELF_KVX_CORE_KV4_1))
	fprintf (file, _("Coolidge (kv4) V1 32 bits"));
    }

  fputc ('\n', file);

  return true;
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.	*/

static bool
elf32_kvx_adjust_dynamic_symbol (struct bfd_link_info *info,
				 struct elf_link_hash_entry *h)
{
  struct elf_kvx_link_hash_table *htab;
  asection *s;

  /* If this is a function, put it in the procedure linkage table.  We
     will fill in the contents of the procedure linkage table later,
     when we know the address of the .got section.  */
  if (h->type == STT_FUNC || h->needs_plt)
    {
      if (h->plt.refcount <= 0
	  || ((SYMBOL_CALLS_LOCAL (info, h)
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

  /* We must allocate the symbol in our .dynbss section, which will
     become part of the .bss section of the executable.  There will be
     an entry for this symbol in the .dynsym section.  The dynamic
     object will contain position independent code, so all references
     from the dynamic object to this symbol will go through the global
     offset table.  The dynamic linker will use the .dynsym entry to
     determine the address it must put in the global offset table, so
     both the dynamic object and the regular object will refer to the
     same memory location for the variable.  */

  htab = elf_kvx_hash_table (info);

  /* We must generate a R_KVX_COPY reloc to tell the dynamic linker
     to copy the initial value out of the dynamic object and into the
     runtime process image.  */
  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0)
    {
      htab->srelbss->size += RELOC_SIZE (htab);
      h->needs_copy = 1;
    }

  s = htab->sdynbss;

  return _bfd_elf_adjust_dynamic_copy (info, h, s);
}

static bool
elf32_kvx_allocate_local_symbols (bfd *abfd, unsigned number)
{
  struct elf_kvx_local_symbol *locals;
  locals = elf_kvx_locals (abfd);
  if (locals == NULL)
    {
      locals = (struct elf_kvx_local_symbol *)
	bfd_zalloc (abfd, number * sizeof (struct elf_kvx_local_symbol));
      if (locals == NULL)
	return false;
      elf_kvx_locals (abfd) = locals;
    }
  return true;
}

/* Create the .got section to hold the global offset table.  */

static bool
kvx_elf_create_got_section (bfd *abfd, struct bfd_link_info *info)
{
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  flagword flags;
  asection *s;
  struct elf_link_hash_entry *h;
  struct elf_link_hash_table *htab = elf_hash_table (info);

  /* This function may be called more than once.  */
  s = bfd_get_linker_section (abfd, ".got");
  if (s != NULL)
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
	  || !bfd_set_section_alignment (s,
					 bed->s->log_file_align))
	return false;
      htab->sgotplt = s;
    }

  /* The first bit of the global offset table is the header.  */
  s->size += bed->got_header_size;

  /* we still need to handle got content when doing static link with PIC */
  if (bfd_link_executable (info) && !bfd_link_pic (info)) {
    htab->dynobj = abfd;
  }

  return true;
}

/* Look through the relocs for a section during the first phase.  */

static bool
elf32_kvx_check_relocs (bfd *abfd, struct bfd_link_info *info,
			    asection *sec, const Elf_Internal_Rela *relocs)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  asection *sreloc;

  struct elf_kvx_link_hash_table *htab;

  if (bfd_link_relocatable (info))
    return true;

  BFD_ASSERT (is_kvx_elf (abfd));

  htab = elf_kvx_hash_table (info);
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
	  isym = bfd_sym_from_r_symndx (&htab->sym_cache,
					abfd, r_symndx);
	  if (isym == NULL)
	    return false;

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
      bfd_r_type = kvx_tls_transition (abfd, info, r_type, h, r_symndx);

      if (h != NULL)
	{
	  /* Create the ifunc sections for static executables.  If we
	     never see an indirect function symbol nor we are building
	     a static executable, those sections will be empty and
	     won't appear in output.  */
	  switch (bfd_r_type)
	    {
	    default:
	      break;
	    }

	  /* It is referenced by a non-shared object. */
	  h->ref_regular = 1;
	}

      switch (bfd_r_type)
	{

	case BFD_RELOC_KVX_S43_LO10:
	case BFD_RELOC_KVX_S43_UP27:
	case BFD_RELOC_KVX_S43_EX6:

	case BFD_RELOC_KVX_S37_LO10:
	case BFD_RELOC_KVX_S37_UP27:

	case BFD_RELOC_KVX_S64_LO10:
	case BFD_RELOC_KVX_S64_UP27:
	case BFD_RELOC_KVX_S64_EX27:

	case BFD_RELOC_KVX_32:
	case BFD_RELOC_KVX_64:

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
	  if (! bfd_link_pic (info))
	    break;

	  {
	    struct elf_dyn_relocs *p;
	    struct elf_dyn_relocs **head;

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

		isym = bfd_sym_from_r_symndx (&htab->sym_cache,
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
		bfd_size_type amt = sizeof *p;
		p = ((struct elf_dyn_relocs *)
		     bfd_zalloc (htab->root.dynobj, amt));
		if (p == NULL)
		  return false;
		p->next = *head;
		*head = p;
		p->sec = sec;
	      }

	    p->count += 1;

	  }
	  break;

	case BFD_RELOC_KVX_S37_GOT_LO10:
	case BFD_RELOC_KVX_S37_GOT_UP27:

	case BFD_RELOC_KVX_S37_GOTOFF_LO10:
	case BFD_RELOC_KVX_S37_GOTOFF_UP27:

	case BFD_RELOC_KVX_S43_GOT_LO10:
	case BFD_RELOC_KVX_S43_GOT_UP27:
	case BFD_RELOC_KVX_S43_GOT_EX6:

	case BFD_RELOC_KVX_S43_GOTOFF_LO10:
	case BFD_RELOC_KVX_S43_GOTOFF_UP27:
	case BFD_RELOC_KVX_S43_GOTOFF_EX6:

	case BFD_RELOC_KVX_S37_TLS_GD_LO10:
	case BFD_RELOC_KVX_S37_TLS_GD_UP27:

	case BFD_RELOC_KVX_S43_TLS_GD_LO10:
	case BFD_RELOC_KVX_S43_TLS_GD_UP27:
	case BFD_RELOC_KVX_S43_TLS_GD_EX6:

	case BFD_RELOC_KVX_S37_TLS_IE_LO10:
	case BFD_RELOC_KVX_S37_TLS_IE_UP27:

	case BFD_RELOC_KVX_S43_TLS_IE_LO10:
	case BFD_RELOC_KVX_S43_TLS_IE_UP27:
	case BFD_RELOC_KVX_S43_TLS_IE_EX6:

	case BFD_RELOC_KVX_S37_TLS_LD_LO10:
	case BFD_RELOC_KVX_S37_TLS_LD_UP27:

	case BFD_RELOC_KVX_S43_TLS_LD_LO10:
	case BFD_RELOC_KVX_S43_TLS_LD_UP27:
	case BFD_RELOC_KVX_S43_TLS_LD_EX6:
	  {
	    unsigned got_type;
	    unsigned old_got_type;

	    got_type = kvx_reloc_got_type (bfd_r_type);

	    if (h)
	      {
		h->got.refcount += 1;
		old_got_type = elf_kvx_hash_entry (h)->got_type;
	      }
	    else
	      {
		struct elf_kvx_local_symbol *locals;

		if (!elf32_kvx_allocate_local_symbols
		    (abfd, symtab_hdr->sh_info))
		  return false;

		locals = elf_kvx_locals (abfd);
		BFD_ASSERT (r_symndx < symtab_hdr->sh_info);
		locals[r_symndx].got_refcount += 1;
		old_got_type = locals[r_symndx].got_type;
	      }

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
	    /* Disabled untested and unused TLS */
	    /* if ((got_type & GOT_TLS_IE) && GOT_TLS_GD_ANY_P (got_type)) */
	    /*   got_type &= ~ (GOT_TLSDESC_GD | GOT_TLS_GD); */

	    if (old_got_type != got_type)
	      {
		if (h != NULL)
		  elf_kvx_hash_entry (h)->got_type = got_type;
		else
		  {
		    struct elf_kvx_local_symbol *locals;
		    locals = elf_kvx_locals (abfd);
		    BFD_ASSERT (r_symndx < symtab_hdr->sh_info);
		    locals[r_symndx].got_type = got_type;
		  }
	      }

	    if (htab->root.dynobj == NULL)
	      htab->root.dynobj = abfd;
	    if (! kvx_elf_create_got_section (htab->root.dynobj, info))
	      return false;
	    break;
	  }

	case BFD_RELOC_KVX_S64_GOTADDR_LO10:
	case BFD_RELOC_KVX_S64_GOTADDR_UP27:
	case BFD_RELOC_KVX_S64_GOTADDR_EX27:

	case BFD_RELOC_KVX_S43_GOTADDR_LO10:
	case BFD_RELOC_KVX_S43_GOTADDR_UP27:
	case BFD_RELOC_KVX_S43_GOTADDR_EX6:

	case BFD_RELOC_KVX_S37_GOTADDR_LO10:
	case BFD_RELOC_KVX_S37_GOTADDR_UP27:

	  if (htab->root.dynobj == NULL)
	    htab->root.dynobj = abfd;
	  if (! kvx_elf_create_got_section (htab->root.dynobj, info))
	    return false;
	  break;

	case BFD_RELOC_KVX_PCREL27:
	case BFD_RELOC_KVX_PCREL17:
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

static bool
elf32_kvx_init_file_header (bfd *abfd, struct bfd_link_info *link_info)
{
  Elf_Internal_Ehdr *i_ehdrp;	/* ELF file header, internal form.  */

  if (!_bfd_elf_init_file_header (abfd, link_info))
    return false;

  i_ehdrp = elf_elfheader (abfd);
  i_ehdrp->e_ident[EI_ABIVERSION] = KVX_ELF_ABI_VERSION;
  return true;
}

static enum elf_reloc_type_class
elf32_kvx_reloc_type_class (const struct bfd_link_info *info ATTRIBUTE_UNUSED,
				const asection *rel_sec ATTRIBUTE_UNUSED,
				const Elf_Internal_Rela *rela)
{
  switch ((int) ELF32_R_TYPE (rela->r_info))
    {
    case R_KVX_RELATIVE:
      return reloc_class_relative;
    case R_KVX_JMP_SLOT:
      return reloc_class_plt;
    case R_KVX_COPY:
      return reloc_class_copy;
    default:
      return reloc_class_normal;
    }
}

/* A structure used to record a list of sections, independently
   of the next and prev fields in the asection structure.  */
typedef struct section_list
{
  asection *sec;
  struct section_list *next;
  struct section_list *prev;
}
section_list;

typedef struct
{
  void *finfo;
  struct bfd_link_info *info;
  asection *sec;
  int sec_shndx;
  int (*func) (void *, const char *, Elf_Internal_Sym *,
	       asection *, struct elf_link_hash_entry *);
} output_arch_syminfo;

/* Output a single local symbol for a generated stub.  */

static bool
elf32_kvx_output_stub_sym (output_arch_syminfo *osi, const char *name,
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
kvx_map_one_stub (struct bfd_hash_entry *gen_entry, void *in_arg)
{
  struct elf_kvx_stub_hash_entry *stub_entry;
  asection *stub_sec;
  bfd_vma addr;
  char *stub_name;
  output_arch_syminfo *osi;

  /* Massage our args to the form they really have.  */
  stub_entry = (struct elf_kvx_stub_hash_entry *) gen_entry;
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
    case kvx_stub_long_branch:
      if (!elf32_kvx_output_stub_sym
	  (osi, stub_name, addr, sizeof (elf32_kvx_long_branch_stub)))
	return false;
      break;

    default:
      abort ();
    }

  return true;
}

/* Output mapping symbols for linker generated sections.  */

static bool
elf32_kvx_output_arch_local_syms (bfd *output_bfd,
				  struct bfd_link_info *info,
				  void *finfo,
				  int (*func) (void *, const char *,
					       Elf_Internal_Sym *,
					       asection *,
					       struct elf_link_hash_entry *))
{
  output_arch_syminfo osi;
  struct elf_kvx_link_hash_table *htab;

  htab = elf_kvx_hash_table (info);

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

	  bfd_hash_traverse (&htab->stub_hash_table, kvx_map_one_stub,
			     &osi);
	}
    }

  /* Finally, output mapping symbols for the PLT.  */
  if (!htab->root.splt || htab->root.splt->size == 0)
    return true;

  osi.sec_shndx = _bfd_elf_section_from_bfd_section
    (output_bfd, htab->root.splt->output_section);
  osi.sec = htab->root.splt;

  return true;

}

/* Allocate target specific section data.  */

static bool
elf32_kvx_new_section_hook (bfd *abfd, asection *sec)
{
  _kvx_elf_section_data *sdata;

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
elf32_kvx_create_dynamic_sections (bfd *dynobj,
				   struct bfd_link_info *info)
{
  struct elf_kvx_link_hash_table *htab;

  /* We need to create .got section.  */
  if (!kvx_elf_create_got_section (dynobj, info))
    return false;

  if (!_bfd_elf_create_dynamic_sections (dynobj, info))
    return false;

  htab = elf_kvx_hash_table (info);
  htab->sdynbss = bfd_get_linker_section (dynobj, ".dynbss");
  if (!bfd_link_pic (info))
    htab->srelbss = bfd_get_linker_section (dynobj, ".rela.bss");

  if (!htab->sdynbss || (!bfd_link_pic (info) && !htab->srelbss))
    abort ();

  return true;
}


/* Allocate space in .plt, .got and associated reloc sections for
   dynamic relocs.  */

static bool
elf32_kvx_allocate_dynrelocs (struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info;
  struct elf_kvx_link_hash_table *htab;
  struct elf_dyn_relocs *p;

  /* An example of a bfd_link_hash_indirect symbol is versioned
     symbol. For example: __gxx_personality_v0(bfd_link_hash_indirect)
     -> __gxx_personality_v0(bfd_link_hash_defined)

     There is no need to process bfd_link_hash_indirect symbols here
     because we will also be presented with the concrete instance of
     the symbol and elf32_kvx_copy_indirect_symbol () will have been
     called to copy all relevant data from the generic to the concrete
     symbol instance.  */
  if (h->root.type == bfd_link_hash_indirect)
    return true;

  if (h->root.type == bfd_link_hash_warning)
    h = (struct elf_link_hash_entry *) h->root.u.i.link;

  info = (struct bfd_link_info *) inf;
  htab = elf_kvx_hash_table (info);

  if (htab->root.dynamic_sections_created && h->plt.refcount > 0)
    {
      /* Make sure this symbol is output as a dynamic symbol.
	 Undefined weak syms won't yet be marked as dynamic.  */
      if (h->dynindx == -1 && !h->forced_local)
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
	  s->size += PLT_SMALL_ENTRY_SIZE;

	  /* We also need to make an entry in the .got.plt section, which
	     will be placed in the .got section by the linker script.  */
	  htab->root.sgotplt->size += GOT_ENTRY_SIZE;

	  /* We also need to make an entry in the .rela.plt section.  */
	  htab->root.srelplt->size += RELOC_SIZE (htab);

	  /* We need to ensure that all GOT entries that serve the PLT
	     are consecutive with the special GOT slots [0] [1] and
	     [2]. Any addtional relocations must be placed after the
	     PLT related entries.  We abuse the reloc_count such that
	     during sizing we adjust reloc_count to indicate the
	     number of PLT related reserved entries.  In subsequent
	     phases when filling in the contents of the reloc entries,
	     PLT related entries are placed by computing their PLT
	     index (0 .. reloc_count). While other none PLT relocs are
	     placed at the slot indicated by reloc_count and
	     reloc_count is updated.  */

	  htab->root.srelplt->reloc_count++;
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

  if (h->got.refcount > 0)
    {
      bool dyn;
      unsigned got_type = elf_kvx_hash_entry (h)->got_type;

      h->got.offset = (bfd_vma) - 1;

      dyn = htab->root.dynamic_sections_created;

      /* Make sure this symbol is output as a dynamic symbol.
	 Undefined weak syms won't yet be marked as dynamic.  */
      if (dyn && h->dynindx == -1 && !h->forced_local)
	{
	  if (!bfd_elf_link_record_dynamic_symbol (info, h))
	    return false;
	}

      if (got_type == GOT_UNKNOWN)
	{
	  (*_bfd_error_handler)
	    (_("relocation against `%s' has faulty GOT type "),
	     (h) ? h->root.root.string : "a local symbol");
	  bfd_set_error (bfd_error_bad_value);
	  return false;
	}
      else if (got_type == GOT_NORMAL)
	{
	  h->got.offset = htab->root.sgot->size;
	  htab->root.sgot->size += GOT_ENTRY_SIZE;
	  if ((ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
	       || h->root.type != bfd_link_hash_undefweak)
	      && (bfd_link_pic (info)
		  || WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, 0, h)))
	    {
	      htab->root.srelgot->size += RELOC_SIZE (htab);
	    }
	}
      else
	{
	  int indx;

	  /* Any of these will require 2 GOT slots because
	   * they use __tls_get_addr() */
	  if (got_type & (GOT_TLS_GD | GOT_TLS_LD))
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
	      && (bfd_link_pic (info)
		  || indx != 0
		  || WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, 0, h)))
	    {
	      /* Only the GD case requires 2 relocations. */
	      if (got_type & GOT_TLS_GD)
		htab->root.srelgot->size += RELOC_SIZE (htab) * 2;

	      /* LD needs a DTPMOD reloc, IE needs a DTPOFF. */
	      if (got_type & (GOT_TLS_LD | GOT_TLS_IE))
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

/* Find any dynamic relocs that apply to read-only sections.  */

static bool
kvx_readonly_dynrelocs (struct elf_link_hash_entry * h, void * inf)
{
  struct elf_dyn_relocs * p;

  for (p = h->dyn_relocs; p != NULL; p = p->next)
    {
      asection *s = p->sec;

      if (s != NULL && (s->flags & SEC_READONLY) != 0)
	{
	  struct bfd_link_info *info = (struct bfd_link_info *) inf;

	  info->flags |= DF_TEXTREL;
	  info->callbacks->minfo (_("%pB: dynamic relocation against `%pT' in "
				    "read-only section `%pA'\n"),
				  s->owner, h->root.root.string, s);

	  /* Not an error, just cut short the traversal.  */
	  return false;
	}
    }
  return true;
}

/* This is the most important function of all . Innocuosly named
   though !  */
static bool
elf32_kvx_late_size_sections (bfd *output_bfd ATTRIBUTE_UNUSED,
			      struct bfd_link_info *info)
{
  struct elf_kvx_link_hash_table *htab;
  bfd *dynobj;
  asection *s;
  bool relocs;
  bfd *ibfd;

  htab = elf_kvx_hash_table ((info));
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
      struct elf_kvx_local_symbol *locals = NULL;
      Elf_Internal_Shdr *symtab_hdr;
      asection *srel;
      unsigned int i;

      if (!is_kvx_elf (ibfd))
	continue;

      for (s = ibfd->sections; s != NULL; s = s->next)
	{
	  struct elf_dyn_relocs *p;

	  for (p = (struct elf_dyn_relocs *)
		 (elf_section_data (s)->local_dynrel); p != NULL; p = p->next)
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
		  srel->size += p->count * RELOC_SIZE (htab);
		  if ((p->sec->output_section->flags & SEC_READONLY) != 0)
		    info->flags |= DF_TEXTREL;
		}
	    }
	}

      locals = elf_kvx_locals (ibfd);
      if (!locals)
	continue;

      symtab_hdr = &elf_symtab_hdr (ibfd);
      srel = htab->root.srelgot;
      for (i = 0; i < symtab_hdr->sh_info; i++)
	{
	  locals[i].got_offset = (bfd_vma) - 1;
	  if (locals[i].got_refcount > 0)
	    {
	      unsigned got_type = locals[i].got_type;
	      if (got_type & (GOT_TLS_GD | GOT_TLS_LD))
		{
		  locals[i].got_offset = htab->root.sgot->size;
		  htab->root.sgot->size += GOT_ENTRY_SIZE * 2;
		}

	      if (got_type & (GOT_NORMAL | GOT_TLS_IE ))
		{
		  locals[i].got_offset = htab->root.sgot->size;
		  htab->root.sgot->size += GOT_ENTRY_SIZE;
		}

	      if (got_type == GOT_UNKNOWN)
		{
		}

	      if (bfd_link_pic (info))
		{
		  if (got_type & GOT_TLS_GD)
		    htab->root.srelgot->size += RELOC_SIZE (htab) * 2;

		  if (got_type & GOT_TLS_IE
		      || got_type & GOT_TLS_LD
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
  elf_link_hash_traverse (&htab->root, elf32_kvx_allocate_dynrelocs,
			  info);

  /* For every jump slot reserved in the sgotplt, reloc_count is
     incremented.  However, when we reserve space for TLS descriptors,
     it's not incremented, so in order to compute the space reserved
     for them, it suffices to multiply the reloc count by the jump
     slot size.  */

  if (htab->root.srelplt)
    htab->sgotplt_jump_table_size = kvx_compute_jump_table_size (htab);

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
	  || s == htab->root.igotplt || s == htab->sdynbss)
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
	 but this way if it does, we get a R_KVX_NONE reloc instead
	 of garbage.  */
      s->contents = (bfd_byte *) bfd_zalloc (dynobj, s->size);
      if (s->contents == NULL)
	return false;
      s->alloced = 1;
    }

  if (htab->root.dynamic_sections_created)
    {
      /* Add some entries to the .dynamic section.  We fill in the
	 values later, in elf32_kvx_finish_dynamic_sections, but we
	 must add the entries now so that we get the correct size for
	 the .dynamic section.  The DT_DEBUG entry is filled in by the
	 dynamic linker and used by the debugger.  */
#define add_dynamic_entry(TAG, VAL)			\
      _bfd_elf_add_dynamic_entry (info, TAG, VAL)

      if (bfd_link_executable (info))
	{
	  if (!add_dynamic_entry (DT_DEBUG, 0))
	    return false;
	}

      if (htab->root.splt->size != 0)
	{
	  if (!add_dynamic_entry (DT_PLTGOT, 0)
	      || !add_dynamic_entry (DT_PLTRELSZ, 0)
	      || !add_dynamic_entry (DT_PLTREL, DT_RELA)
	      || !add_dynamic_entry (DT_JMPREL, 0))
	    return false;
	}

      if (relocs)
	{
	  if (!add_dynamic_entry (DT_RELA, 0)
	      || !add_dynamic_entry (DT_RELASZ, 0)
	      || !add_dynamic_entry (DT_RELAENT, RELOC_SIZE (htab)))
	    return false;

	  /* If any dynamic relocs apply to a read-only section,
	     then we need a DT_TEXTREL entry.  */
	  if ((info->flags & DF_TEXTREL) == 0)
	    elf_link_hash_traverse (&htab->root, kvx_readonly_dynrelocs,
				    info);

	  if ((info->flags & DF_TEXTREL) != 0)
	    {
	      if (!add_dynamic_entry (DT_TEXTREL, 0))
		return false;
	    }
	}
    }
#undef add_dynamic_entry

  return true;
}

static inline void
elf_kvx_update_plt_entry (bfd *output_bfd,
			  bfd_reloc_code_real_type r_type,
			  bfd_byte *plt_entry, bfd_vma value)
{
  reloc_howto_type *howto = elf32_kvx_howto_from_bfd_reloc (r_type);
  BFD_ASSERT(howto != NULL);
  _bfd_kvx_elf_put_addend (output_bfd, plt_entry, r_type, howto, value);
}

static void
elf32_kvx_create_small_pltn_entry (struct elf_link_hash_entry *h,
				   struct elf_kvx_link_hash_table *htab,
				   bfd *output_bfd)
{
  bfd_byte *plt_entry;
  bfd_vma plt_index;
  bfd_vma got_offset;
  bfd_vma gotplt_entry_address;
  bfd_vma plt_entry_address;
  Elf_Internal_Rela rela;
  bfd_byte *loc;
  asection *plt, *gotplt, *relplt;

  plt = htab->root.splt;
  gotplt = htab->root.sgotplt;
  relplt = htab->root.srelplt;

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
  memcpy (plt_entry, elf32_kvx_small_plt_entry, PLT_SMALL_ENTRY_SIZE);

  /* Patch the loading of the GOT entry, relative to the PLT entry
     address. */

  /* Use 37bits offset for both 32 and 64bits mode.
     Fill the LO10 of of lw $r9 = 0[$r14].  */
  elf_kvx_update_plt_entry(output_bfd, BFD_RELOC_KVX_S37_LO10,
			   plt_entry+4,
			   gotplt_entry_address - plt_entry_address);

  /* Fill the UP27 of of lw $r9 = 0[$r14].  */
  elf_kvx_update_plt_entry(output_bfd, BFD_RELOC_KVX_S37_UP27,
			   plt_entry+8,
			   gotplt_entry_address - plt_entry_address);

  rela.r_offset = gotplt_entry_address;

  /* Fill in the entry in the .rela.plt section.  */
  rela.r_info = ELF32_R_INFO (h->dynindx, R_KVX_JMP_SLOT);
  rela.r_addend = 0;

  /* Compute the relocation entry to used based on PLT index and do
     not adjust reloc_count. The reloc_count has already been adjusted
     to account for this entry.  */
  loc = relplt->contents + plt_index * RELOC_SIZE (htab);
  bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
}

/* Size sections even though they're not dynamic.  We use it to setup
   _TLS_MODULE_BASE_, if needed.  */

static bool
elf32_kvx_early_size_sections (bfd *output_bfd, struct bfd_link_info *info)
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
elf32_kvx_finish_dynamic_symbol (bfd *output_bfd,
				 struct bfd_link_info *info,
				 struct elf_link_hash_entry *h,
				 Elf_Internal_Sym *sym)
{
  struct elf_kvx_link_hash_table *htab;
  htab = elf_kvx_hash_table (info);

  if (h->plt.offset != (bfd_vma) - 1)
    {
      asection *plt = NULL, *gotplt = NULL, *relplt = NULL;

      /* This symbol has an entry in the procedure linkage table.  Set
	 it up.  */

      if (htab->root.splt != NULL)
	{
	  plt = htab->root.splt;
	  gotplt = htab->root.sgotplt;
	  relplt = htab->root.srelplt;
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

      elf32_kvx_create_small_pltn_entry (h, htab, output_bfd);
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
      && elf_kvx_hash_entry (h)->got_type == GOT_NORMAL)
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

#ifdef UGLY_DEBUG
      printf("setting rela at offset 0x%x(0x%x + 0x%x + 0x%x) for %s\n",
	     rela.r_offset,
	     htab->root.sgot->output_section->vma,
	     htab->root.sgot->output_offset,
	     h->got.offset,
	     h->root.root.string);
#endif

      if (bfd_link_pic (info) && SYMBOL_REFERENCES_LOCAL (info, h))
	{
	  if (!h->def_regular)
	    return false;

	  /* in case of PLT related GOT entry, it is not clear who is
	     supposed to set the LSB of GOT entry...
	     kvx_calculate_got_entry_vma() would be a good candidate,
	     but it is not called currently
	     So we are commenting it ATM.  */
	  // BFD_ASSERT ((h->got.offset & 1) != 0);
	  rela.r_info = ELF32_R_INFO (0, R_KVX_RELATIVE);
	  rela.r_addend = (h->root.u.def.value
			   + h->root.u.def.section->output_section->vma
			   + h->root.u.def.section->output_offset);
	}
      else
	{
	  BFD_ASSERT ((h->got.offset & 1) == 0);
	  bfd_put_32 (output_bfd, (bfd_vma) 0,
		      htab->root.sgot->contents + h->got.offset);
	  rela.r_info = ELF32_R_INFO (h->dynindx, R_KVX_GLOB_DAT);
	  rela.r_addend = 0;
	}

      loc = htab->root.srelgot->contents;
      loc += htab->root.srelgot->reloc_count++ * RELOC_SIZE (htab);
      bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
    }

  if (h->needs_copy)
    {
      Elf_Internal_Rela rela;
      bfd_byte *loc;

      /* This symbol needs a copy reloc.  Set it up.  */

      if (h->dynindx == -1
	  || (h->root.type != bfd_link_hash_defined
	      && h->root.type != bfd_link_hash_defweak)
	  || htab->srelbss == NULL)
	abort ();

      rela.r_offset = (h->root.u.def.value
		       + h->root.u.def.section->output_section->vma
		       + h->root.u.def.section->output_offset);
      rela.r_info = ELF32_R_INFO (h->dynindx, R_KVX_COPY);
      rela.r_addend = 0;
      loc = htab->srelbss->contents;
      loc += htab->srelbss->reloc_count++ * RELOC_SIZE (htab);
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

static void
elf32_kvx_init_small_plt0_entry (bfd *output_bfd ATTRIBUTE_UNUSED,
				 struct elf_kvx_link_hash_table *htab)
{
  memcpy (htab->root.splt->contents, elf32_kvx_small_plt0_entry,
	  PLT_ENTRY_SIZE);
  elf_section_data (htab->root.splt->output_section)->this_hdr.sh_entsize =
    PLT_ENTRY_SIZE;
}

static bool
elf32_kvx_finish_dynamic_sections (bfd *output_bfd,
				   struct bfd_link_info *info)
{
  struct elf_kvx_link_hash_table *htab;
  bfd *dynobj;
  asection *sdyn;

  htab = elf_kvx_hash_table (info);
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

	    case DT_RELASZ:
	      /* The procedure linkage table relocs (DT_JMPREL) should
		 not be included in the overall relocs (DT_RELA).
		 Therefore, we override the DT_RELASZ entry here to
		 make it not include the JMPREL relocs.  Since the
		 linker script arranges for .rela.plt to follow all
		 other relocation sections, we don't have to worry
		 about changing the DT_RELA entry.  */
	      if (htab->root.srelplt != NULL)
		{
		  s = htab->root.srelplt;
		  dyn.d_un.d_val -= s->size;
		}
	      break;
	    }

	  bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
	}

    }

  /* Fill in the special first entry in the procedure linkage table.  */
  if (htab->root.splt && htab->root.splt->size > 0)
    {
      elf32_kvx_init_small_plt0_entry (output_bfd, htab);

      elf_section_data (htab->root.splt->output_section)->
	this_hdr.sh_entsize = htab->plt_entry_size;
    }

  if (htab->root.sgotplt)
    {
      if (bfd_is_abs_section (htab->root.sgotplt->output_section))
	{
	  (*_bfd_error_handler)
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

  return true;
}

/* Return address for Ith PLT stub in section PLT, for relocation REL
   or (bfd_vma) -1 if it should not be included.  */

static bfd_vma
elf32_kvx_plt_sym_val (bfd_vma i, const asection *plt,
		       const arelent *rel ATTRIBUTE_UNUSED)
{
  return plt->vma + PLT_ENTRY_SIZE + i * PLT_SMALL_ENTRY_SIZE;
}

#define ELF_ARCH			bfd_arch_kvx
#define ELF_TARGET_ID			KVX_ELF_DATA
#define ELF_MACHINE_CODE		EM_KVX
#define ELF_MAXPAGESIZE			0x10000
#define ELF_MINPAGESIZE			0x1000
#define ELF_COMMONPAGESIZE		0x1000

#define bfd_elf32_bfd_link_hash_table_create    \
  elf32_kvx_link_hash_table_create

#define bfd_elf32_bfd_merge_private_bfd_data	\
  elf32_kvx_merge_private_bfd_data

#define bfd_elf32_bfd_print_private_bfd_data	\
  elf32_kvx_print_private_bfd_data

#define bfd_elf32_bfd_reloc_type_lookup		\
  elf32_kvx_reloc_type_lookup

#define bfd_elf32_bfd_reloc_name_lookup		\
  elf32_kvx_reloc_name_lookup

#define bfd_elf32_bfd_set_private_flags		\
  elf32_kvx_set_private_flags

#define bfd_elf32_mkobject			\
  elf32_kvx_mkobject

#define bfd_elf32_new_section_hook		\
  elf32_kvx_new_section_hook

#define elf_backend_adjust_dynamic_symbol	\
  elf32_kvx_adjust_dynamic_symbol

#define elf_backend_early_size_sections		\
  elf32_kvx_early_size_sections

#define elf_backend_check_relocs		\
  elf32_kvx_check_relocs

#define elf_backend_copy_indirect_symbol	\
  elf32_kvx_copy_indirect_symbol

/* Create .dynbss, and .rela.bss sections in DYNOBJ, and set up shortcuts
   to them in our hash.  */
#define elf_backend_create_dynamic_sections	\
  elf32_kvx_create_dynamic_sections

#define elf_backend_init_index_section		\
  _bfd_elf_init_2_index_sections

#define elf_backend_finish_dynamic_sections	\
  elf32_kvx_finish_dynamic_sections

#define elf_backend_finish_dynamic_symbol	\
  elf32_kvx_finish_dynamic_symbol

#define elf_backend_object_p			\
  elf32_kvx_object_p

#define elf_backend_output_arch_local_syms      \
  elf32_kvx_output_arch_local_syms

#define elf_backend_plt_sym_val			\
  elf32_kvx_plt_sym_val

#define elf_backend_init_file_header		\
  elf32_kvx_init_file_header

#define elf_backend_init_process_headers	\
  elf32_kvx_init_process_headers

#define elf_backend_relocate_section		\
  elf32_kvx_relocate_section

#define elf_backend_reloc_type_class		\
  elf32_kvx_reloc_type_class

#define elf_backend_late_size_sections	\
  elf32_kvx_late_size_sections

#define elf_backend_can_refcount       1
#define elf_backend_can_gc_sections    1
#define elf_backend_plt_readonly       1
#define elf_backend_want_got_plt       1
#define elf_backend_want_plt_sym       0
#define elf_backend_may_use_rel_p      0
#define elf_backend_may_use_rela_p     1
#define elf_backend_default_use_rela_p 1
#define elf_backend_rela_normal        1
#define elf_backend_got_header_size (GOT_ENTRY_SIZE * 3)
#define elf_backend_default_execstack  0
#define elf_backend_extern_protected_data 1
#define elf_backend_hash_symbol elf_kvx_hash_symbol

#include "elf32-target.h"
