/* BFD library support routines for the MK architecture.
   Copyright (C) 2005-2021 Free Software Foundation, Inc.
   Contributed by Arnold Metselaar <arnold_m@operamail.com>

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

const bfd_arch_info_type bfd_mk_arch;

/* This routine is provided two arch_infos and
   returns whether they'd be compatible.  */

static const bfd_arch_info_type *
compatible (const bfd_arch_info_type *a, const bfd_arch_info_type *b)
{
  if (a->arch != b->arch || a->arch != bfd_arch_mk)
    return NULL;

  if (a->mach == b->mach)
    return a;

  return NULL;
}

const bfd_arch_info_type bfd_mk_arch =
{
  16,       /* There's 16 bits_per_word.  */
  16,       /* There's 16 bits_per_address.  */
  16,       /* There's 16 bits_per_byte.  */
  bfd_arch_mk,    /* One of enum bfd_architecture, defined
           in archures.c and provided in
           generated header files.  */
  0,   /* Random BFD-internal number for this
           machine, similarly listed in
           archures.c.  Not emitted in output.  */
  "mk",     /* The arch_name.  */
  "mk",     /* The printable name is the same.  */
  2,        /* Section alignment power; each section
           is aligned to (only) 2^2 bytes.  */
  TRUE,       /* This is the default "machine".  */
  compatible,   /* A function for testing
           "machine" compatibility of two
           bfd_arch_info_type.  */
  bfd_default_scan,   /* Check if a bfd_arch_info_type is a
           match.  */
  bfd_arch_default_fill,  /* Default fill.  */
  NULL,   /* Pointer to next bfd_arch_info_type in
           the same family.  */
  0 /* Maximum offset of a reloc from the start of an insn.  */
};
