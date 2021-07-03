/* Maschinenkern ELF support for BFD.

*/

#ifndef _ELF_MK_H
#define _ELF_MK_H

#include "elf/reloc-macros.h"

START_RELOC_NUMBERS (elf_mk_reloc_type)
     RELOC_NUMBER (R_MK_NONE,      0)	// No reloc
     RELOC_NUMBER (R_MK_24,        1)	// Direct 24 bit
     RELOC_NUMBER (R_MK_23,        2) // Direct 23 bit
     RELOC_NUMBER (R_MK_16,        3)	// Direct 16 bit
     RELOC_NUMBER (R_MK_8LO,       4) // Direct lowest 8 bit
     RELOC_NUMBER (R_MK_4LO,       5) // Direct lowest 4 bit // kinda useless but unless assembler prevents it, it would be possible
     RELOC_NUMBER (R_MK_8UP,       6) // Direct upper  8 bit
     RELOC_NUMBER (R_MK_PC16,      7) // PC relative low 16 bit
     RELOC_NUMBER (R_MK_PC12,      8) // PC relative low 12 bit
END_RELOC_NUMBERS (R_MK_max)

#endif
