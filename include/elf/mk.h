/* Maschinenkern ELF support for BFD.

*/

#ifndef _ELF_MK_H
#define _ELF_MK_H

#include "elf/reloc-macros.h"

START_RELOC_NUMBERS (elf_mk_reloc_type)
     RELOC_NUMBER (R_MK_NONE,      0) // No reloc
     RELOC_NUMBER (R_MK_24,        1) // Direct 24 bit
     RELOC_NUMBER (R_MK_23,        2) // Direct 23 bit
     RELOC_NUMBER (R_MK_16,        3) // Direct 16 bit
     RELOC_NUMBER (R_MK_16LO,      4) // Direct lowest 16 bit
     RELOC_NUMBER (R_MK_16UP,      5) // Direct upper  8 bit 
     RELOC_NUMBER (R_MK_8LO,       6) // Direct lowest 8 bit
     RELOC_NUMBER (R_MK_4LO,       7) // Direct lowest 4 bit // kinda useless but unless assembler prevents it, it would be possible
     RELOC_NUMBER (R_MK_8UP,       8) // Direct upper  8 bit
     RELOC_NUMBER (R_MK_J_PC24,    9) // PC relative     effective 25 bit signed jump
     RELOC_NUMBER (R_MK_PC24,     10) // PC relative     24 bit
     RELOC_NUMBER (R_MK_PC16,     11) // PC relative low 16 bit
     RELOC_NUMBER (R_MK_J_PC16,   12) // PC relative     effective 17 bit signed jump
     RELOC_NUMBER (R_MK_PC12,     13) // PC relative low 12 bit
END_RELOC_NUMBERS (R_MK_max)

#endif
