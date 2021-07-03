# Copyright (C) 2014-2021 Free Software Foundation, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.

cat << EOF
/* Copyright (C) 2014-2021 Free Software Foundation, Inc.

   Copying and distribution of this script, with or without modification,
   are permitted in any medium without royalty provided the copyright
   notice and this notice are preserved.  */

OUTPUT_FORMAT("${OUTPUT_FORMAT}")
OUTPUT_ARCH("${ARCH}")
ENTRY("_start")

SECTIONS
{
.vector_table 0x0: { *(.vector_table) *(vector_table) }
.config     0x530: { *(.config) *(config) }
.rodata     0x580: { *(.rodata) *(rodata) }

.text      0x1000: { *(.text) *(text) }
.data            : { *(.data) *(data) }
.bss             : { *(.bss) *(bss) }
.stack   0xff0000: { *(.stack) *(stack) }
.boot    0xffff00: { *(.boot) *(boot) }
}
EOF