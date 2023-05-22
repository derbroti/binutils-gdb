/* Maschinenkern-specific support for 32-bit ELF
   Copyright (C) 1999-2021 Free Software Foundation, Inc.
   (Heavily copied from the S12Z port by Sergey Belyashov (sergey.belyashov@gmail.com))

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
#include "bfdlink.h"
#include "libbfd.h"
#include "elf-bfd.h"

#include "elf/mk.h"

/* All users of this file have bfd_octets_per_byte (abfd, sec) == 2.  */
#define OCTETS_PER_BYTE(ABFD, SEC) 2

#define USE_REL 1

typedef const struct {
  bfd_reloc_code_real_type r_type;
  reloc_howto_type howto;
} bfd_howto_type;

#define BFD_EMPTY_HOWTO(rt,x) {rt, EMPTY_HOWTO(x)}
#define BFD_HOWTO(rt,a,b,c,d,e,f,g,h,i,j,k,l,m) {rt, HOWTO(a,b,c,d,e,f,g,h,i,j,k,l,m)}


static const
bfd_howto_type elf_mk_howto_table[] =
{
  /* This reloc does nothing.  */
  BFD_HOWTO (BFD_RELOC_NONE,
	 R_MK_NONE,		/* type 0 */
	 0,			/* rightshift */
	 3,			/* size 3 = null */
	 0,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,/*  */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_NONE",		/* name */
	 FALSE,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /*  direct 24 bit  */
  BFD_HOWTO (BFD_RELOC_MK_24,
   R_MK_24,   /* type 1 */
   0,     /* rightshift */
   2,     /* size = 32 bit */
   24,     /* bitsize */
   FALSE,     /* pc_relative */
   0,     /* bitpos */
   complain_overflow_bitfield, /*  */
   bfd_elf_generic_reloc, /* special_function */
   "R_MK_24",    /* name */
   FALSE,     /* partial_inplace */
   0xFFFFFF,     /* src_mask */
   0xFFFFFF,     /* dst_mask */
   FALSE),   /* pcrel_offset */

  /*  direct 23 bit -  call+variants and goto  */
  BFD_HOWTO (BFD_RELOC_MK_23,
   R_MK_23,   /* type 2 */
   1,     /* rightshift */
   2,     /* size = 32 bit */
   23,     /* bitsize */
   FALSE,     /* pc_relative */
   0,     /* bitpos */
   complain_overflow_unsigned,/*  */
   bfd_elf_generic_reloc, /* special_function */
   "R_MK_23",    /* name */
   FALSE,     /* partial_inplace */
   0x7FFFFF,     /* src_mask */
   0x7FFFFF,     /* dst_mask */
   FALSE),   /* pcrel_offset */


  /*  direct 16 bit  */
  BFD_HOWTO (BFD_RELOC_MK_16,
   R_MK_16,   /* type 3 */
   0,     /* rightshift */
   2,     /* size = 32 bit */
   16,     /* bitsize */
   FALSE,     /* pc_relative */
   0,     /* bitpos */
   complain_overflow_unsigned,/*  */
   bfd_elf_generic_reloc, /* special_function */
   "R_MK_16",    /* name */
   FALSE,     /* partial_inplace */
   0xFFFF,     /* src_mask */
   0xFFFF,     /* dst_mask */
   FALSE),   /* pcrel_offset */

  /*  direct lowest 16 bit  */
  BFD_HOWTO (BFD_RELOC_MK_16LO,
   R_MK_16LO,   /* type 4 */
   0,     /* rightshift */
   2,     /* size = 32 bit */
   16,     /* bitsize */
   FALSE,     /* pc_relative */
   0,     /* bitpos */
   complain_overflow_dont,/*  */
   bfd_elf_generic_reloc, /* special_function */
   "R_MK_16lO",    /* name */
   FALSE,     /* partial_inplace */
   0xFFFF,     /* src_mask */
   0xFFFF,     /* dst_mask */
   FALSE),   /* pcrel_offset */

    /*  direct uppeer 8 bit  */
  BFD_HOWTO (BFD_RELOC_MK_16UP,
   R_MK_16UP,   /* type 5 */
   16,     /* rightshift */
   2,     /* size = 32 bit */
   8,     /* bitsize */
   FALSE,     /* pc_relative */
   0,     /* bitpos */
   complain_overflow_dont,/*  */
   bfd_elf_generic_reloc, /* special_function */
   "R_MK_16UP",    /* name */
   FALSE,     /* partial_inplace */
   0xFF,     /* src_mask */
   0xFF,     /* dst_mask */
   FALSE),   /* pcrel_offset */

    /* Direct lowest  8 bit  */
  BFD_HOWTO (BFD_RELOC_MK_8LO,
   R_MK_8LO,   /* type 6 */
   0,     /* rightshift */
   2,     /* size = 32 bit */
   8,     /* bitsize */
   FALSE,     /* pc_relative */
   0,     /* bitpos */
   complain_overflow_dont, //do not complain as we have to chop of bits...
   // complain_overflow_unsigned,
   bfd_elf_generic_reloc, /* special_function */
   "R_MK_8LO",    /* name */
   FALSE,     /* partial_inplace */
   0xFF,     /* src_mask */
   0xFF,     /* dst_mask */
   FALSE),   /* pcrel_offset */

  /* Direct lowest  4 bit  */
  BFD_HOWTO (BFD_RELOC_MK_4LO,
   R_MK_4LO,   /* type 7 */
   0,     /* rightshift */
   2,     /* size = 32 bit */
   4,     /* bitsize */
   FALSE,     /* pc_relative */
   16,     /* bitpos */
   complain_overflow_dont, //do not complain as we have to chop of bits...
   // complain_overflow_unsigned,
   bfd_elf_generic_reloc, /* special_function */
   "R_MK_4LO",    /* name */
   FALSE,     /* partial_inplace */
   0xF0000,     /* src_mask */
   0xF0000,     /* dst_mask */
   FALSE),   /* pcrel_offset */

    /* Direct upper  8 bit  */
  BFD_HOWTO (BFD_RELOC_MK_8UP,
   R_MK_8UP,   /* type 8 */
   16,     /* rightshift */
   2,     /* size = 32 bit */
   8,     /* bitsize */
   FALSE,     /* pc_relative */
   16,     /* bitpos */
   complain_overflow_unsigned,/*  */
   bfd_elf_generic_reloc, /* special_function */
   "R_MK_8UP",    /* name */
   FALSE,     /* partial_inplace */
   0xFF0000,     /* src_mask */
   0xFF0000,     /* dst_mask */
   FALSE),   /* pcrel_offset */

    /* PC relative effectvie 25 bit jump */
  BFD_HOWTO (BFD_RELOC_MK_J_PC24,
   R_MK_J_PC24,   /* type 9 */
   1,     /* rightshift */
   2,     /* size = 32 bit */
   24,     /* bitsize */
   TRUE,     /* pc_relative */
   0,     /* bitpos */
   complain_overflow_signed,/*  */
   bfd_elf_generic_reloc, /* special_function */
   "R_MK_J_PC24",    /* name */
   FALSE,     /* partial_inplace */
   0xFFFFFF,     /* src_mask */
   0xFFFFFF,     /* dst_mask */
   TRUE),   /* pcrel_offset */


    /* PC relative 24 bit  */
  BFD_HOWTO (BFD_RELOC_MK_PC24,
   R_MK_PC24,   /* type 10 */
   0,     /* rightshift */
   2,     /* size = 32 bit */
   24,     /* bitsize */
   FALSE,     /* pc_relative */
   0,     /* bitpos */
   complain_overflow_unsigned,/*  */
   bfd_elf_generic_reloc, /* special_function */
   "R_MK_PC24",    /* name */
   FALSE,     /* partial_inplace */
   0xFFFFFF,     /* src_mask */
   0xFFFFFF,     /* dst_mask */
   TRUE),   /* pcrel_offset */


    /* PC relative low 16 bit  */
  BFD_HOWTO (BFD_RELOC_MK_PC16,
   R_MK_PC16,   /* type 11 */
   0,     /* rightshift */
   2,     /* size = 32 bit */
   16,     /* bitsize */
   TRUE,     /* pc_relative */
   0,     /* bitpos */
   complain_overflow_signed,/*  */
   bfd_elf_generic_reloc, /* special_function */
   "R_MK_PC16",    /* name */
   FALSE,     /* partial_inplace */
   0xFFFF,     /* src_mask */
   0xFFFF,     /* dst_mask */
   TRUE),   /* pcrel_offset */


    /* PC relative effectvie 17 bit jump */
  BFD_HOWTO (BFD_RELOC_MK_J_PC16,
   R_MK_J_PC16,   /* type 12 */
   1,     /* rightshift */
   2,     /* size = 32 bit */
   16,     /* bitsize */
   TRUE,     /* pc_relative */
   0,     /* bitpos */
   complain_overflow_signed,/*  */
   bfd_elf_generic_reloc, /* special_function */
   "R_MK_J_PC16",    /* name */
   FALSE,     /* partial_inplace */
   0xFFFF,     /* src_mask */
   0xFFFF,     /* dst_mask */
   TRUE)   /* pcrel_offset */


//RELOC_NUMBER (R_MK_PC12,      13) // PC relative low 12 bit

};

static reloc_howto_type *
mk_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
		       bfd_reloc_code_real_type code)
{
  enum
    {
      table_size = sizeof (elf_mk_howto_table) / sizeof (elf_mk_howto_table[0])
    };
  unsigned int i;

  for (i = 0; i < table_size; i++)
    {
      if (elf_mk_howto_table[i].r_type == code)
	  return &elf_mk_howto_table[i].howto;
    }

  printf ("%s:%d Not found BFD reloc type %d\n", __FILE__, __LINE__, code);

  return NULL;
}

static reloc_howto_type *
mk_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED, const char *r_name)
{
  enum
    {
      table_size = sizeof (elf_mk_howto_table) / sizeof (elf_mk_howto_table[0])
    };
  unsigned int i;

  for (i = 0; i < table_size; i++)
    {
      if (elf_mk_howto_table[i].howto.name != NULL
	  && strcasecmp (elf_mk_howto_table[i].howto.name, r_name) == 0)
	return &elf_mk_howto_table[i].howto;
    }

  printf ("%s:%d Not found ELF reloc name `%s'\n", __FILE__, __LINE__, r_name);

  return NULL;
}

static reloc_howto_type *
mk_rtype_to_howto (bfd *abfd, unsigned r_type)
{
  enum
    {
      table_size = sizeof (elf_mk_howto_table) / sizeof (elf_mk_howto_table[0])
    };
  unsigned int i;

  for (i = 0; i < table_size; i++)
    {
      if (elf_mk_howto_table[i].howto.type == r_type) {
	  return &elf_mk_howto_table[i].howto;
    }
    }

  /* xgettext:c-format */
  _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
		      abfd, r_type);
  return NULL;
} 

/* Set the howto pointer for an mk ELF reloc.  */

static bfd_boolean
mk_info_to_howto_rel (bfd *abfd, arelent *cache_ptr, Elf_Internal_Rela *dst)
{
  unsigned int  r_type = ELF32_R_TYPE (dst->r_info);
  reloc_howto_type *howto = mk_rtype_to_howto (abfd, r_type);
  if (howto != NULL)
    {
      cache_ptr->howto = howto;
      return TRUE;
    }
  bfd_set_error (bfd_error_bad_value);
  return FALSE;
}


static bfd_boolean
mk_elf_relocate_section (bfd *output_bfd,
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
  Elf_Internal_Rela *rel, *relend;
  reloc_howto_type *howto;

  symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (input_bfd);

  rel = relocs;
  relend = relocs + input_section->reloc_count;
  for (; rel < relend; rel++)
    {
      unsigned int r_type;
      unsigned long r_symndx;
      Elf_Internal_Sym *sym;
      asection *sec;
      struct elf_link_hash_entry *h;
      bfd_vma relocation;

      /* This is a final link.  */
      r_symndx = ELF32_R_SYM (rel->r_info);
      r_type = ELF32_R_TYPE (rel->r_info);
      h = NULL;
      sym = NULL;
      sec = NULL;
      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];
	  relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
	}
      else
	{
	  bfd_boolean unresolved_reloc, warned, ignored;

	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation,
				   unresolved_reloc, warned, ignored);
	}

  howto = mk_rtype_to_howto (input_bfd, r_type);
  if (howto == NULL)
        return FALSE;

      if (sec != NULL && discarded_section (sec))
	{
	  /* For relocs against symbols from removed linkonce sections,
	     or sections discarded by a linker script, we just want the
	     section contents cleared.  Avoid any special processing.  */
	  RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					   rel, 1, relend, howto, 0, contents);
	}

      if (bfd_link_relocatable (info)) 
	      continue;


  if (howto->complain_on_overflow != complain_overflow_dont) {
    if (bfd_check_overflow (howto->complain_on_overflow,
             howto->bitsize,
             howto->rightshift,
             16 * 2, //bfd_arch_bits_per_address (abfd) * 2, //misleadding... instructions are 2 addresses wide
             relocation) != bfd_reloc_ok) {
      _bfd_error_handler (_("%pB: %s overflow in '%s' @ 0x%lx value: %lx"), input_bfd, howto->name, input_section->name, rel->r_offset, relocation);
      return FALSE;
    }
  }
    
    if (_bfd_final_link_relocate (howto, input_bfd, input_section, contents,
        rel->r_offset, relocation, 0/*addend*/) != bfd_reloc_ok) {
          _bfd_error_handler (_("%pB: final_link_relocate failed."), input_bfd);
          return FALSE;
        }
    }

  return TRUE;
}

/* The final processing done just before writing out a MK ELF object
   file.  This gets the MK architecture right based on the machine
   number.  */

static bfd_boolean
mk_elf_final_write_processing (bfd *abfd)
{
  //unsigned long val = bfd_get_mach (abfd);

  elf_elfheader (abfd)->e_machine = EM_MK;
  elf_elfheader (abfd)->e_flags = 0;
  return _bfd_elf_final_write_processing (abfd);
}

/* Set the right machine number.  */
static bfd_boolean
mk_elf_object_p (bfd *abfd)
{
  if (elf_elfheader (abfd)->e_machine != EM_MK)
    {
      _bfd_error_handler (_("%pB: unsupported arch %#x"),
			  abfd, elf_elfheader (abfd)->e_machine);
    }
  return bfd_default_set_arch_mach (abfd, bfd_arch_mk, 0);
}

static int
mk_is_local_label_name (bfd *	abfd ATTRIBUTE_UNUSED,
			 const char * name)
{
  return (name[0] != '_') ||
	 _bfd_elf_is_local_label_name (abfd, name);
}



#define ELF_ARCH		bfd_arch_mk
#define ELF_MACHINE_CODE	EM_MK
#define ELF_MINPAGESIZE    0x10
#define ELF_COMMONPAGESIZE 0x10
#define ELF_MAXPAGESIZE		 0x10

#define TARGET_BIG_SYM		mk_elf32_vec
#define TARGET_BIG_NAME		"elf32-mk"

//#define elf_backend_can_refcount		1
//#define elf_backend_can_gc_sections		1
//#define elf_backend_stack_align			1
#define elf_backend_default_use_rela_p 0

#define elf_info_to_howto					mk_info_to_howto_rel
#define elf_info_to_howto_rel				mk_info_to_howto_rel

#define elf_backend_final_write_processing	mk_elf_final_write_processing
#define elf_backend_object_p				mk_elf_object_p
#define elf_backend_relocate_section		mk_elf_relocate_section

#define bfd_elf32_bfd_reloc_type_lookup		mk_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup		mk_reloc_name_lookup
#define bfd_elf32_bfd_is_local_label_name	mk_is_local_label_name

#include "elf32-target.h"
