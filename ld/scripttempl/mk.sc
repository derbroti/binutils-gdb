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
.vtab       0x0: { *(.vtab) *(vtab) }
.conf     0x530: { *(.conf) *(conf) }
.rdat     0x600: { *(.rdat) *(rdat) }
.bot      0xE00: { *(.bot)    *(bot)    }

.text    0x1000: { *(.text) *(text) }
.data          : { *(.data) *(data) }
.bss           : { *(.bss) *(bss) }
.stack 0xff0000: { *(.stack) *(stack) }
.boot  0xffff00: { *(.boot) *(boot) }
}
EOF
