// AUTO-GENERATED DO -NOT- EDIT

#include "sysdep.h"
#include "disassemble.h"
#include "elf-bfd.h"
#include <stdio.h>

const char* registers[32] = {"%r0", "%r1", "%r2", "%r3", "%r4", "%r5", "%r6", "%r7", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15", "%x0", "%x1", "%x2", "%x3", "%x4", "%x5", "", "", "", "", "", "", "", "%x13", "%x14", "%x15"};


struct objdump_disasm_info
{
  bfd *              abfd;
/*  asection *         sec;
  bfd_boolean        require_sec;
  arelent **         dynrelbuf;
  long               dynrelcount;
  disassembler_ftype disassemble_fn;
  arelent *          reloc;*/
};

struct closest_sec_t {
    char name[100];
    bfd_vma addr;
    bfd_vma sec_start;
};

static void
find_closest_section (bfd *abfd ATTRIBUTE_UNUSED, asection *section, void *data) {
    struct closest_sec_t* cs = (struct closest_sec_t*) data;

    //if (! process_section_p (section))
    //  return;

    if ((section->flags & SEC_HAS_CONTENTS) == 0)
        return;

    if (bfd_section_size (section) == 0)
        return;

    if (cs->addr < bfd_section_vma(section))
        return;

    if (cs->addr - bfd_section_vma(section) < cs->addr - cs->sec_start) {
        strcpy(cs->name, bfd_section_name(section));
        cs->sec_start = bfd_section_vma(section);

    }
}

static void print_symbol(bfd_vma pc, bfd_vma addr, disassemble_info * info) {
    if (bfd_get_flavour (((struct objdump_disasm_info *) info->application_data)->abfd) != bfd_target_elf_flavour)
        return;

    struct objdump_disasm_info *aux;
    bfd *abfd;
    aux = (struct objdump_disasm_info *) info->application_data;
    abfd = aux->abfd;
    bfd_boolean is_relocatable = ((abfd->flags & (HAS_RELOC | EXEC_P | DYNAMIC)) == HAS_RELOC);

    if (!is_relocatable) {
        if (info->symbol_at_address_func (pc + addr, info)) {
            for (int n = 0; n < info->symtab_size; ++n) {
                if (pc + addr == bfd_asymbol_value (info->symtab[n])) {
                    info->fprintf_func (info->stream, " # <%s>", bfd_asymbol_name (info->symtab[n]));
                }
            }
        } else {
            struct closest_sec_t closest_sec;
            closest_sec.addr = addr;
            strcpy(closest_sec.name, bfd_section_name(info->section));
            closest_sec.sec_start = bfd_section_vma(info->section);
            bfd_map_over_sections (abfd, find_closest_section, &closest_sec);

            info->fprintf_func (info->stream, " # <%s+0x%x>", closest_sec.name, addr - closest_sec.sec_start);
        }
    } else {
        info->fprintf_func (info->stream, " # <TBC>");
    }
}

char* p2_inst_0a1[26];
char* p2_inst_0a2[26];
char* p2_inst_0b1[26];
char* p2_inst_0b2[26];
char* p2_inst_0b3[26];
char* p2_inst_0b4[26];
char* p2_inst_0c1[26];
char* p2_inst_0c2[26];
char* p2_inst_0d1[26];
char* p2_inst_0d2[26];
char* p2_inst_0d3[26];
char* p2_inst_0e[26];
char* p2_inst_0f1[26];
char* p2_inst_0g1[26];
char* p2_inst_2a[26];
char* p2_inst_2b[26];
char* p2_inst_3[26];
char* p2_inst_4[26];
char* p2_inst_5[26];
char* p2_inst_5x[26];
char* p2_inst_6[26];
char* p2_inst_7a1[26];
char* p2_inst_7b1[26];
char* p2_inst_7b2[26];
char* p2_inst_7c1[26];
char* p2_inst_7c2[26];
char* p2_inst_8a1[26];
char* p2_inst_8a2[26];
char* p2_inst_8a3[26];
char* p2_inst_131[26];
char* p2_inst_132[26];
char* p2_inst_91[26];
char* p2_inst_92[26];
char* p2_inst_101[26];
char* p1_inst_0f2[31];
char* p1_inst_0f3[31];
char* p1_inst_0g2[31];
char* p1_inst_0g3[31];
char* p1_inst_1[31];
char* p1_inst_7a2[31];
char* p1_inst_7a3[31];
char* p1_inst_7c3[31];
char* p1_inst_7c4[31];
char* p1_inst_7c5[31];
char* p1_inst_7c6[31];
char* p1_inst_8a4[31];
char* p1_inst_8a5[31];
char* p1_inst_8b1[31];
char* p1_inst_8b2[31];
char* p1_inst_93[31];
char* p1_inst_94[31];
char* p1_inst_102[31];
char* p1_inst_11[31];
char* p0_inst_12a[33];
char* p0_inst_12b[33];
char* p0_inst_12c[33];
void (*fcnPtr[256])(uint32_t, bfd_vma pc, disassemble_info*);

void (*fcnPtr_EA[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_EB[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_EC[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_ED[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_EE[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_EF[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_F0[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_F1[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_F1_8[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_F1_8_C[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_F1_8_D[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_F2[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_F3[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_F4[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_F5[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_F6[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_F7[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_F8[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_F9[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FA[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FB[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FC[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FD[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_6[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_7[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_8[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_9[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_A[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_B[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_C[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_C_0[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_C_1[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_C_2[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_C_3[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_C_4[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_C_5[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_C_6[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_C_6_4[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_C_6_4_0[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_C_6_4_0_0[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FE_C_6_4_0_1[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FF[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FF_F[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FF_F_F[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FF_F_F_F[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FF_F_F_F_F[16])(uint32_t, bfd_vma pc, disassemble_info*);
void (*fcnPtr_FF_F_F_F_F_F[16])(uint32_t, bfd_vma pc, disassemble_info*);


#define p0_12a_OFFSET 0x00
#define p0_12b_OFFSET 0xFE
#define p0_12c_OFFSET 0xFF
#define p1_0f2_OFFSET 0xDE
#define p1_0f3_OFFSET 0xE0
#define p1_0g2_OFFSET 0xE5
#define p1_0g3_OFFSET 0xE6
#define p1_1_OFFSET 0xA0
#define p1_102_OFFSET 0x38
#define p1_11_OFFSET 0x51
#define p1_7a2_OFFSET 0x44
#define p1_7a3_OFFSET 0x52
#define p1_7c3_OFFSET 0xA8
#define p1_7c4_OFFSET 0xBF
#define p1_7c5_OFFSET 0xD6
#define p1_7c6_OFFSET 0xDE
#define p1_8a4_OFFSET 0x8A
#define p1_8a5_OFFSET 0xA1
#define p1_8b1_OFFSET 0xA9
#define p1_8b2_OFFSET 0xB5
#define p1_93_OFFSET 0x0A
#define p1_94_OFFSET 0x16
#define p2_0a1_OFFSET 0x0
#define p2_0a2_OFFSET 0xE
#define p2_0b1_OFFSET 0x1C
#define p2_0b2_OFFSET 0x34
#define p2_0b3_OFFSET 0x42
#define p2_0b4_OFFSET 0x5A
#define p2_0c1_OFFSET 0x68
#define p2_0c2_OFFSET 0x80
#define p2_0d1_OFFSET 0x8E
#define p2_0d2_OFFSET 0x9C
#define p2_0d3_OFFSET 0xB4
#define p2_0e_OFFSET 0xC2
#define p2_0f1_OFFSET 0xD0
#define p2_0g1_OFFSET 0xE4
#define p2_101_OFFSET 0x1E
#define p2_131_OFFSET 0xBD
#define p2_132_OFFSET 0xBE
#define p2_2a_OFFSET 0x00
#define p2_2b_OFFSET 0x0C
#define p2_3_OFFSET 0x0
#define p2_4_OFFSET 0xC0
#define p2_5_OFFSET 0xCC
#define p2_6_OFFSET 0x1A
#define p2_7a1_OFFSET 0x36
#define p2_7b1_OFFSET 0x5A
#define p2_7b2_OFFSET 0x74
#define p2_7c1_OFFSET 0x82
#define p2_7c2_OFFSET 0x9A
#define p2_8a1_OFFSET 0x60
#define p2_8a2_OFFSET 0x7A
#define p2_8a3_OFFSET 0x88
#define p2_91_OFFSET 0x00
#define p2_92_OFFSET 0x02
#include "opcode/mk-dis.h"
static int is_init = 0;
static void init_inst() {
p2_inst_0a1[0] = "mov";
p2_inst_0a1[1] = "add";
p2_inst_0a1[2] = "adc";
p2_inst_0a1[3] = "sub";
p2_inst_0a1[4] = "sbb";
p2_inst_0a1[5] = "mul";
p2_inst_0a1[6] = "div";
p2_inst_0a1[7] = "muls";
p2_inst_0a1[8] = "divs";
p2_inst_0a1[9] = "cmp";
p2_inst_0a1[10] = "test";
p2_inst_0a1[11] = "and";
p2_inst_0a1[12] = "or";
p2_inst_0a1[13] = "xor";
p2_inst_0a2[0] = "mov";
p2_inst_0a2[1] = "add";
p2_inst_0a2[2] = "adc";
p2_inst_0a2[3] = "sub";
p2_inst_0a2[4] = "sbb";
p2_inst_0a2[5] = "mul";
p2_inst_0a2[6] = "div";
p2_inst_0a2[7] = "muls";
p2_inst_0a2[8] = "divs";
p2_inst_0a2[9] = "cmp";
p2_inst_0a2[10] = "test";
p2_inst_0a2[11] = "and";
p2_inst_0a2[12] = "or";
p2_inst_0a2[13] = "xor";
p2_inst_0b1[0] = "mov";
p2_inst_0b1[1] = "add";
p2_inst_0b1[2] = "adc";
p2_inst_0b1[3] = "sub";
p2_inst_0b1[4] = "sbb";
p2_inst_0b1[5] = "mul";
p2_inst_0b1[6] = "div";
p2_inst_0b1[7] = "muls";
p2_inst_0b1[8] = "divs";
p2_inst_0b1[9] = "cmp";
p2_inst_0b1[10] = "test";
p2_inst_0b1[11] = "and";
p2_inst_0b1[12] = "or";
p2_inst_0b1[13] = "xor";
p2_inst_0b1[14] = "rol";
p2_inst_0b1[15] = "ror";
p2_inst_0b1[16] = "rcl";
p2_inst_0b1[17] = "rcr";
p2_inst_0b1[18] = "shl";
p2_inst_0b1[19] = "shr";
p2_inst_0b1[20] = "sar";
p2_inst_0b1[21] = "bitc";
p2_inst_0b1[22] = "bits";
p2_inst_0b1[23] = "bitn";
p2_inst_0b2[0] = "mov";
p2_inst_0b2[1] = "add";
p2_inst_0b2[2] = "adc";
p2_inst_0b2[3] = "sub";
p2_inst_0b2[4] = "sbb";
p2_inst_0b2[5] = "mul";
p2_inst_0b2[6] = "div";
p2_inst_0b2[7] = "muls";
p2_inst_0b2[8] = "divs";
p2_inst_0b2[9] = "cmp";
p2_inst_0b2[10] = "test";
p2_inst_0b2[11] = "and";
p2_inst_0b2[12] = "or";
p2_inst_0b2[13] = "xor";
p2_inst_0b3[0] = "mov";
p2_inst_0b3[1] = "add";
p2_inst_0b3[2] = "adc";
p2_inst_0b3[3] = "sub";
p2_inst_0b3[4] = "sbb";
p2_inst_0b3[5] = "mul";
p2_inst_0b3[6] = "div";
p2_inst_0b3[7] = "muls";
p2_inst_0b3[8] = "divs";
p2_inst_0b3[9] = "cmp";
p2_inst_0b3[10] = "test";
p2_inst_0b3[11] = "and";
p2_inst_0b3[12] = "or";
p2_inst_0b3[13] = "xor";
p2_inst_0b3[14] = "rol";
p2_inst_0b3[15] = "ror";
p2_inst_0b3[16] = "rcl";
p2_inst_0b3[17] = "rcr";
p2_inst_0b3[18] = "shl";
p2_inst_0b3[19] = "shr";
p2_inst_0b3[20] = "sar";
p2_inst_0b3[21] = "bitc";
p2_inst_0b3[22] = "bits";
p2_inst_0b3[23] = "bitn";
p2_inst_0b4[0] = "mov";
p2_inst_0b4[1] = "add";
p2_inst_0b4[2] = "adc";
p2_inst_0b4[3] = "sub";
p2_inst_0b4[4] = "sbb";
p2_inst_0b4[5] = "mul";
p2_inst_0b4[6] = "div";
p2_inst_0b4[7] = "muls";
p2_inst_0b4[8] = "divs";
p2_inst_0b4[9] = "cmp";
p2_inst_0b4[10] = "test";
p2_inst_0b4[11] = "and";
p2_inst_0b4[12] = "or";
p2_inst_0b4[13] = "xor";
p2_inst_0c1[0] = "mov";
p2_inst_0c1[1] = "add";
p2_inst_0c1[2] = "adc";
p2_inst_0c1[3] = "sub";
p2_inst_0c1[4] = "sbb";
p2_inst_0c1[5] = "mul";
p2_inst_0c1[6] = "div";
p2_inst_0c1[7] = "muls";
p2_inst_0c1[8] = "divs";
p2_inst_0c1[9] = "cmp";
p2_inst_0c1[10] = "test";
p2_inst_0c1[11] = "and";
p2_inst_0c1[12] = "or";
p2_inst_0c1[13] = "xor";
p2_inst_0c1[14] = "rol";
p2_inst_0c1[15] = "ror";
p2_inst_0c1[16] = "rcl";
p2_inst_0c1[17] = "rcr";
p2_inst_0c1[18] = "shl";
p2_inst_0c1[19] = "shr";
p2_inst_0c1[20] = "sar";
p2_inst_0c1[21] = "bitc";
p2_inst_0c1[22] = "bits";
p2_inst_0c1[23] = "bitn";
p2_inst_0c2[0] = "mov";
p2_inst_0c2[1] = "add";
p2_inst_0c2[2] = "adc";
p2_inst_0c2[3] = "sub";
p2_inst_0c2[4] = "sbb";
p2_inst_0c2[5] = "mul";
p2_inst_0c2[6] = "div";
p2_inst_0c2[7] = "muls";
p2_inst_0c2[8] = "divs";
p2_inst_0c2[9] = "cmp";
p2_inst_0c2[10] = "test";
p2_inst_0c2[11] = "and";
p2_inst_0c2[12] = "or";
p2_inst_0c2[13] = "xor";
p2_inst_0d1[0] = "mov";
p2_inst_0d1[1] = "add";
p2_inst_0d1[2] = "adc";
p2_inst_0d1[3] = "sub";
p2_inst_0d1[4] = "sbb";
p2_inst_0d1[5] = "mul";
p2_inst_0d1[6] = "div";
p2_inst_0d1[7] = "muls";
p2_inst_0d1[8] = "divs";
p2_inst_0d1[9] = "cmp";
p2_inst_0d1[10] = "test";
p2_inst_0d1[11] = "and";
p2_inst_0d1[12] = "or";
p2_inst_0d1[13] = "xor";
p2_inst_0d2[0] = "mov";
p2_inst_0d2[1] = "add";
p2_inst_0d2[2] = "adc";
p2_inst_0d2[3] = "sub";
p2_inst_0d2[4] = "sbb";
p2_inst_0d2[5] = "mul";
p2_inst_0d2[6] = "div";
p2_inst_0d2[7] = "muls";
p2_inst_0d2[8] = "divs";
p2_inst_0d2[9] = "cmp";
p2_inst_0d2[10] = "test";
p2_inst_0d2[11] = "and";
p2_inst_0d2[12] = "or";
p2_inst_0d2[13] = "xor";
p2_inst_0d2[14] = "rol";
p2_inst_0d2[15] = "ror";
p2_inst_0d2[16] = "rcl";
p2_inst_0d2[17] = "rcr";
p2_inst_0d2[18] = "shl";
p2_inst_0d2[19] = "shr";
p2_inst_0d2[20] = "sar";
p2_inst_0d2[21] = "bitc";
p2_inst_0d2[22] = "bits";
p2_inst_0d2[23] = "bitn";
p2_inst_0d3[0] = "mov";
p2_inst_0d3[1] = "add";
p2_inst_0d3[2] = "adc";
p2_inst_0d3[3] = "sub";
p2_inst_0d3[4] = "sbb";
p2_inst_0d3[5] = "mul";
p2_inst_0d3[6] = "div";
p2_inst_0d3[7] = "muls";
p2_inst_0d3[8] = "divs";
p2_inst_0d3[9] = "cmp";
p2_inst_0d3[10] = "test";
p2_inst_0d3[11] = "and";
p2_inst_0d3[12] = "or";
p2_inst_0d3[13] = "xor";
p2_inst_0e[0] = "mov";
p2_inst_0e[1] = "add";
p2_inst_0e[2] = "adc";
p2_inst_0e[3] = "sub";
p2_inst_0e[4] = "sbb";
p2_inst_0e[5] = "mul";
p2_inst_0e[6] = "div";
p2_inst_0e[7] = "muls";
p2_inst_0e[8] = "divs";
p2_inst_0e[9] = "cmp";
p2_inst_0e[10] = "test";
p2_inst_0e[11] = "and";
p2_inst_0e[12] = "or";
p2_inst_0e[13] = "xor";
p2_inst_0f1[0] = "mov";
p2_inst_0f1[1] = "add";
p2_inst_0f1[2] = "adc";
p2_inst_0f1[3] = "sub";
p2_inst_0f1[4] = "sbb";
p2_inst_0f1[5] = "mul";
p2_inst_0f1[6] = "div";
p2_inst_0f1[7] = "muls";
p2_inst_0f1[8] = "divs";
p2_inst_0f1[9] = "cmp";
p2_inst_0f1[10] = "test";
p2_inst_0f1[11] = "and";
p2_inst_0f1[12] = "or";
p2_inst_0f1[13] = "xor";
p1_inst_0f2[0] = "call";
p1_inst_0f2[1] = "goto";
p1_inst_0f3[0] = "inc";
p1_inst_0f3[1] = "dec";
p1_inst_0f3[2] = "push";
p1_inst_0f3[3] = "pop";
p2_inst_0g1[0] = "mov";
p1_inst_0g2[0] = "jmp";
p1_inst_0g3[0] = "inc";
p1_inst_0g3[1] = "dec";
p1_inst_0g3[2] = "push";
p1_inst_0g3[3] = "pop";
p1_inst_1[0] = "call";
p1_inst_1[1] = "goto";
p1_inst_1[2] = "cle";
p1_inst_1[3] = "clne";
p1_inst_1[4] = "clge";
p1_inst_1[5] = "clg";
p1_inst_1[6] = "clle";
p1_inst_1[7] = "cll";
p1_inst_1[8] = "clbe";
p1_inst_1[9] = "clb";
p1_inst_1[10] = "clae";
p1_inst_1[11] = "cla";
p2_inst_101[0] = "mov";
p2_inst_101[1] = "add";
p2_inst_101[2] = "adc";
p2_inst_101[3] = "sub";
p2_inst_101[4] = "sbb";
p2_inst_101[5] = "mul";
p2_inst_101[6] = "div";
p2_inst_101[7] = "muls";
p2_inst_101[8] = "divs";
p2_inst_101[9] = "cmp";
p2_inst_101[10] = "test";
p2_inst_101[11] = "and";
p2_inst_101[12] = "or";
p2_inst_101[13] = "xor";
p2_inst_101[14] = "rol";
p2_inst_101[15] = "ror";
p2_inst_101[16] = "rcl";
p2_inst_101[17] = "rcr";
p2_inst_101[18] = "shl";
p2_inst_101[19] = "shr";
p2_inst_101[20] = "sar";
p2_inst_101[21] = "bitc";
p2_inst_101[22] = "bits";
p2_inst_101[23] = "bitn";
p2_inst_101[24] = "btsc";
p2_inst_101[25] = "btss";
p1_inst_102[0] = "inc";
p1_inst_102[1] = "dec";
p1_inst_102[2] = "call";
p1_inst_102[3] = "jmp";
p1_inst_102[4] = "goto";
p1_inst_102[5] = "je";
p1_inst_102[6] = "jne";
p1_inst_102[7] = "jge";
p1_inst_102[8] = "jg";
p1_inst_102[9] = "jle";
p1_inst_102[10] = "jl";
p1_inst_102[11] = "jbe";
p1_inst_102[12] = "jb";
p1_inst_102[13] = "jae";
p1_inst_102[14] = "ja";
p1_inst_102[15] = "cle";
p1_inst_102[16] = "clne";
p1_inst_102[17] = "clge";
p1_inst_102[18] = "clg";
p1_inst_102[19] = "clle";
p1_inst_102[20] = "cll";
p1_inst_102[21] = "clbe";
p1_inst_102[22] = "clb";
p1_inst_102[23] = "clae";
p1_inst_102[24] = "cla";
p1_inst_11[0] = "inc";
p1_inst_11[1] = "dec";
p1_inst_11[2] = "jmp";
p1_inst_11[3] = "not";
p1_inst_11[4] = "xchg";
p1_inst_11[5] = "push";
p1_inst_11[6] = "pop";
p1_inst_11[7] = "int";
p1_inst_11[8] = "neg";
p1_inst_11[9] = "je";
p1_inst_11[10] = "jne";
p1_inst_11[11] = "jge";
p1_inst_11[12] = "jg";
p1_inst_11[13] = "jle";
p1_inst_11[14] = "jl";
p1_inst_11[15] = "jbe";
p1_inst_11[16] = "jb";
p1_inst_11[17] = "jae";
p1_inst_11[18] = "ja";
p0_inst_12a[0] = "ret";
p0_inst_12a[1] = "gine";
p0_inst_12a[2] = "gie";
p0_inst_12a[3] = "slep";
p0_inst_12a[4] = "hlt";
p0_inst_12a[5] = "rst";
p0_inst_12a[6] = "rtfi";
p0_inst_12a[7] = "rtif";
p0_inst_12a[8] = "rte";
p0_inst_12a[9] = "rtne";
p0_inst_12a[10] = "rtge";
p0_inst_12a[11] = "rtg";
p0_inst_12a[12] = "rtle";
p0_inst_12a[13] = "rtl";
p0_inst_12a[14] = "rtbe";
p0_inst_12a[15] = "rtb";
p0_inst_12a[16] = "rtae";
p0_inst_12a[17] = "rta";
p0_inst_12a[18] = "rtno";
p0_inst_12a[19] = "rto";
p0_inst_12a[20] = "rtns";
p0_inst_12a[21] = "rts";
p0_inst_12a[22] = "rtnc";
p0_inst_12a[23] = "rtc";
p0_inst_12a[24] = "rtnz";
p0_inst_12a[25] = "rtz";
p0_inst_12a[26] = "rtnd";
p0_inst_12a[27] = "rtd";
p0_inst_12a[28] = "rtnh";
p0_inst_12a[29] = "rth";
p0_inst_12a[30] = "rtnp";
p0_inst_12a[31] = "rtp";
p0_inst_12b[0] = "nop";
p0_inst_12c[0] = "nop";
p2_inst_131[0] = "mov";
p2_inst_132[0] = "mov";
p2_inst_2a[0] = "rol";
p2_inst_2a[1] = "ror";
p2_inst_2a[2] = "rcl";
p2_inst_2a[3] = "rcr";
p2_inst_2a[4] = "shl";
p2_inst_2a[5] = "shr";
p2_inst_2a[6] = "sar";
p2_inst_2a[7] = "bitc";
p2_inst_2a[8] = "bits";
p2_inst_2a[9] = "bitn";
p2_inst_2a[10] = "btsc";
p2_inst_2a[11] = "btss";
p2_inst_2b[0] = "rol";
p2_inst_2b[1] = "ror";
p2_inst_2b[2] = "rcl";
p2_inst_2b[3] = "rcr";
p2_inst_2b[4] = "shl";
p2_inst_2b[5] = "shr";
p2_inst_2b[6] = "sar";
p2_inst_2b[7] = "bitc";
p2_inst_2b[8] = "bits";
p2_inst_2b[9] = "bitn";
p2_inst_2b[10] = "btsc";
p2_inst_2b[11] = "btss";
p2_inst_3[0] = "rol";
p2_inst_3[1] = "ror";
p2_inst_3[2] = "rcl";
p2_inst_3[3] = "rcr";
p2_inst_3[4] = "shl";
p2_inst_3[5] = "shr";
p2_inst_3[6] = "sar";
p2_inst_3[7] = "bitc";
p2_inst_3[8] = "bits";
p2_inst_3[9] = "bitn";
p2_inst_3[10] = "btsc";
p2_inst_3[11] = "btss";
p2_inst_4[0] = "rol";
p2_inst_4[1] = "ror";
p2_inst_4[2] = "rcl";
p2_inst_4[3] = "rcr";
p2_inst_4[4] = "shl";
p2_inst_4[5] = "shr";
p2_inst_4[6] = "sar";
p2_inst_4[7] = "bitc";
p2_inst_4[8] = "bits";
p2_inst_4[9] = "bitn";
p2_inst_4[10] = "btsc";
p2_inst_4[11] = "btss";
p2_inst_5[0] = "rol";
p2_inst_5[1] = "ror";
p2_inst_5[2] = "rcl";
p2_inst_5[3] = "rcr";
p2_inst_5[4] = "shl";
p2_inst_5[5] = "shr";
p2_inst_5[6] = "sar";
p2_inst_5[7] = "bitc";
p2_inst_5[8] = "bits";
p2_inst_5[9] = "bitn";
p2_inst_5[10] = "btsc";
p2_inst_5[11] = "btss";
p2_inst_6[0] = "mov";
p2_inst_6[1] = "add";
p2_inst_6[2] = "adc";
p2_inst_6[3] = "sub";
p2_inst_6[4] = "sbb";
p2_inst_6[5] = "mul";
p2_inst_6[6] = "div";
p2_inst_6[7] = "muls";
p2_inst_6[8] = "divs";
p2_inst_6[9] = "cmp";
p2_inst_6[10] = "test";
p2_inst_6[11] = "and";
p2_inst_6[12] = "or";
p2_inst_6[13] = "xor";
p2_inst_7a1[0] = "mov";
p2_inst_7a1[1] = "add";
p2_inst_7a1[2] = "adc";
p2_inst_7a1[3] = "sub";
p2_inst_7a1[4] = "sbb";
p2_inst_7a1[5] = "mul";
p2_inst_7a1[6] = "div";
p2_inst_7a1[7] = "muls";
p2_inst_7a1[8] = "divs";
p2_inst_7a1[9] = "cmp";
p2_inst_7a1[10] = "test";
p2_inst_7a1[11] = "and";
p2_inst_7a1[12] = "or";
p2_inst_7a1[13] = "xor";
p1_inst_7a2[0] = "jmp";
p1_inst_7a2[1] = "push";
p1_inst_7a2[2] = "pop";
p1_inst_7a2[3] = "int";
p1_inst_7a2[4] = "je";
p1_inst_7a2[5] = "jne";
p1_inst_7a2[6] = "jge";
p1_inst_7a2[7] = "jg";
p1_inst_7a2[8] = "jle";
p1_inst_7a2[9] = "jl";
p1_inst_7a2[10] = "jbe";
p1_inst_7a2[11] = "jb";
p1_inst_7a2[12] = "jae";
p1_inst_7a2[13] = "ja";
p1_inst_7a3[0] = "inc";
p1_inst_7a3[1] = "dec";
p1_inst_7a3[2] = "not";
p1_inst_7a3[3] = "xchg";
p1_inst_7a3[4] = "push";
p1_inst_7a3[5] = "pop";
p1_inst_7a3[6] = "int";
p1_inst_7a3[7] = "neg";
p2_inst_7b1[0] = "mov";
p2_inst_7b1[1] = "add";
p2_inst_7b1[2] = "adc";
p2_inst_7b1[3] = "sub";
p2_inst_7b1[4] = "sbb";
p2_inst_7b1[5] = "mul";
p2_inst_7b1[6] = "div";
p2_inst_7b1[7] = "muls";
p2_inst_7b1[8] = "divs";
p2_inst_7b1[9] = "cmp";
p2_inst_7b1[10] = "test";
p2_inst_7b1[11] = "and";
p2_inst_7b1[12] = "or";
p2_inst_7b1[13] = "xor";
p2_inst_7b1[14] = "rol";
p2_inst_7b1[15] = "ror";
p2_inst_7b1[16] = "rcl";
p2_inst_7b1[17] = "rcr";
p2_inst_7b1[18] = "shl";
p2_inst_7b1[19] = "shr";
p2_inst_7b1[20] = "sar";
p2_inst_7b1[21] = "bitc";
p2_inst_7b1[22] = "bits";
p2_inst_7b1[23] = "bitn";
p2_inst_7b1[24] = "btsc";
p2_inst_7b1[25] = "btss";
p2_inst_7b2[0] = "mov";
p2_inst_7b2[1] = "add";
p2_inst_7b2[2] = "adc";
p2_inst_7b2[3] = "sub";
p2_inst_7b2[4] = "sbb";
p2_inst_7b2[5] = "mul";
p2_inst_7b2[6] = "div";
p2_inst_7b2[7] = "muls";
p2_inst_7b2[8] = "divs";
p2_inst_7b2[9] = "cmp";
p2_inst_7b2[10] = "test";
p2_inst_7b2[11] = "and";
p2_inst_7b2[12] = "or";
p2_inst_7b2[13] = "xor";
p2_inst_7c1[0] = "mov";
p2_inst_7c1[1] = "add";
p2_inst_7c1[2] = "adc";
p2_inst_7c1[3] = "sub";
p2_inst_7c1[4] = "sbb";
p2_inst_7c1[5] = "mul";
p2_inst_7c1[6] = "div";
p2_inst_7c1[7] = "muls";
p2_inst_7c1[8] = "divs";
p2_inst_7c1[9] = "cmp";
p2_inst_7c1[10] = "test";
p2_inst_7c1[11] = "and";
p2_inst_7c1[12] = "or";
p2_inst_7c1[13] = "xor";
p2_inst_7c1[14] = "rol";
p2_inst_7c1[15] = "ror";
p2_inst_7c1[16] = "rcl";
p2_inst_7c1[17] = "rcr";
p2_inst_7c1[18] = "shl";
p2_inst_7c1[19] = "shr";
p2_inst_7c1[20] = "sar";
p2_inst_7c1[21] = "bitc";
p2_inst_7c1[22] = "bits";
p2_inst_7c1[23] = "bitn";
p2_inst_7c2[0] = "mov";
p2_inst_7c2[1] = "add";
p2_inst_7c2[2] = "adc";
p2_inst_7c2[3] = "sub";
p2_inst_7c2[4] = "sbb";
p2_inst_7c2[5] = "mul";
p2_inst_7c2[6] = "div";
p2_inst_7c2[7] = "muls";
p2_inst_7c2[8] = "divs";
p2_inst_7c2[9] = "cmp";
p2_inst_7c2[10] = "test";
p2_inst_7c2[11] = "and";
p2_inst_7c2[12] = "or";
p2_inst_7c2[13] = "xor";
p1_inst_7c3[0] = "call";
p1_inst_7c3[1] = "jmp";
p1_inst_7c3[2] = "goto";
p1_inst_7c3[3] = "je";
p1_inst_7c3[4] = "jne";
p1_inst_7c3[5] = "jge";
p1_inst_7c3[6] = "jg";
p1_inst_7c3[7] = "jle";
p1_inst_7c3[8] = "jl";
p1_inst_7c3[9] = "jbe";
p1_inst_7c3[10] = "jb";
p1_inst_7c3[11] = "jae";
p1_inst_7c3[12] = "ja";
p1_inst_7c3[13] = "cle";
p1_inst_7c3[14] = "clne";
p1_inst_7c3[15] = "clge";
p1_inst_7c3[16] = "clg";
p1_inst_7c3[17] = "clle";
p1_inst_7c3[18] = "cll";
p1_inst_7c3[19] = "clbe";
p1_inst_7c3[20] = "clb";
p1_inst_7c3[21] = "clae";
p1_inst_7c3[22] = "cla";
p1_inst_7c4[0] = "call";
p1_inst_7c4[1] = "jmp";
p1_inst_7c4[2] = "goto";
p1_inst_7c4[3] = "je";
p1_inst_7c4[4] = "jne";
p1_inst_7c4[5] = "jge";
p1_inst_7c4[6] = "jg";
p1_inst_7c4[7] = "jle";
p1_inst_7c4[8] = "jl";
p1_inst_7c4[9] = "jbe";
p1_inst_7c4[10] = "jb";
p1_inst_7c4[11] = "jae";
p1_inst_7c4[12] = "ja";
p1_inst_7c4[13] = "cle";
p1_inst_7c4[14] = "clne";
p1_inst_7c4[15] = "clge";
p1_inst_7c4[16] = "clg";
p1_inst_7c4[17] = "clle";
p1_inst_7c4[18] = "cll";
p1_inst_7c4[19] = "clbe";
p1_inst_7c4[20] = "clb";
p1_inst_7c4[21] = "clae";
p1_inst_7c4[22] = "cla";
p1_inst_7c5[0] = "inc";
p1_inst_7c5[1] = "dec";
p1_inst_7c5[2] = "not";
p1_inst_7c5[3] = "xchg";
p1_inst_7c5[4] = "push";
p1_inst_7c5[5] = "pop";
p1_inst_7c5[6] = "int";
p1_inst_7c5[7] = "neg";
p1_inst_7c6[0] = "inc";
p1_inst_7c6[1] = "dec";
p1_inst_7c6[2] = "not";
p1_inst_7c6[3] = "xchg";
p1_inst_7c6[4] = "push";
p1_inst_7c6[5] = "pop";
p1_inst_7c6[6] = "int";
p1_inst_7c6[7] = "neg";
p2_inst_8a1[0] = "mov";
p2_inst_8a1[1] = "add";
p2_inst_8a1[2] = "adc";
p2_inst_8a1[3] = "sub";
p2_inst_8a1[4] = "sbb";
p2_inst_8a1[5] = "mul";
p2_inst_8a1[6] = "div";
p2_inst_8a1[7] = "muls";
p2_inst_8a1[8] = "divs";
p2_inst_8a1[9] = "cmp";
p2_inst_8a1[10] = "test";
p2_inst_8a1[11] = "and";
p2_inst_8a1[12] = "or";
p2_inst_8a1[13] = "xor";
p2_inst_8a1[14] = "rol";
p2_inst_8a1[15] = "ror";
p2_inst_8a1[16] = "rcl";
p2_inst_8a1[17] = "rcr";
p2_inst_8a1[18] = "shl";
p2_inst_8a1[19] = "shr";
p2_inst_8a1[20] = "sar";
p2_inst_8a1[21] = "bitc";
p2_inst_8a1[22] = "bits";
p2_inst_8a1[23] = "bitn";
p2_inst_8a1[24] = "btsc";
p2_inst_8a1[25] = "btss";
p2_inst_8a2[0] = "mov";
p2_inst_8a2[1] = "add";
p2_inst_8a2[2] = "adc";
p2_inst_8a2[3] = "sub";
p2_inst_8a2[4] = "sbb";
p2_inst_8a2[5] = "mul";
p2_inst_8a2[6] = "div";
p2_inst_8a2[7] = "muls";
p2_inst_8a2[8] = "divs";
p2_inst_8a2[9] = "cmp";
p2_inst_8a2[10] = "test";
p2_inst_8a2[11] = "and";
p2_inst_8a2[12] = "or";
p2_inst_8a2[13] = "xor";
p2_inst_8a3[0] = "div";
p2_inst_8a3[1] = "divs";
p1_inst_8a4[0] = "call";
p1_inst_8a4[1] = "jmp";
p1_inst_8a4[2] = "goto";
p1_inst_8a4[3] = "je";
p1_inst_8a4[4] = "jne";
p1_inst_8a4[5] = "jge";
p1_inst_8a4[6] = "jg";
p1_inst_8a4[7] = "jle";
p1_inst_8a4[8] = "jl";
p1_inst_8a4[9] = "jbe";
p1_inst_8a4[10] = "jb";
p1_inst_8a4[11] = "jae";
p1_inst_8a4[12] = "ja";
p1_inst_8a4[13] = "cle";
p1_inst_8a4[14] = "clne";
p1_inst_8a4[15] = "clge";
p1_inst_8a4[16] = "clg";
p1_inst_8a4[17] = "clle";
p1_inst_8a4[18] = "cll";
p1_inst_8a4[19] = "clbe";
p1_inst_8a4[20] = "clb";
p1_inst_8a4[21] = "clae";
p1_inst_8a4[22] = "cla";
p1_inst_8a5[0] = "inc";
p1_inst_8a5[1] = "dec";
p1_inst_8a5[2] = "not";
p1_inst_8a5[3] = "xchg";
p1_inst_8a5[4] = "push";
p1_inst_8a5[5] = "pop";
p1_inst_8a5[6] = "int";
p1_inst_8a5[7] = "neg";
p1_inst_8b1[0] = "call";
p1_inst_8b1[1] = "goto";
p1_inst_8b1[2] = "cle";
p1_inst_8b1[3] = "clne";
p1_inst_8b1[4] = "clge";
p1_inst_8b1[5] = "clg";
p1_inst_8b1[6] = "clle";
p1_inst_8b1[7] = "cll";
p1_inst_8b1[8] = "clbe";
p1_inst_8b1[9] = "clb";
p1_inst_8b1[10] = "clae";
p1_inst_8b1[11] = "cla";
p1_inst_8b2[0] = "inc";
p1_inst_8b2[1] = "dec";
p1_inst_8b2[2] = "not";
p1_inst_8b2[3] = "xchg";
p1_inst_8b2[4] = "push";
p1_inst_8b2[5] = "pop";
p1_inst_8b2[6] = "int";
p1_inst_8b2[7] = "neg";
p2_inst_91[0] = "div";
p2_inst_91[1] = "divs";
p2_inst_92[0] = "add";
p2_inst_92[1] = "adc";
p2_inst_92[2] = "sub";
p2_inst_92[3] = "sbb";
p2_inst_92[4] = "mul";
p2_inst_92[5] = "div";
p2_inst_92[6] = "muls";
p2_inst_92[7] = "divs";
p1_inst_93[0] = "call";
p1_inst_93[1] = "goto";
p1_inst_93[2] = "cle";
p1_inst_93[3] = "clne";
p1_inst_93[4] = "clge";
p1_inst_93[5] = "clg";
p1_inst_93[6] = "clle";
p1_inst_93[7] = "cll";
p1_inst_93[8] = "clbe";
p1_inst_93[9] = "clb";
p1_inst_93[10] = "clae";
p1_inst_93[11] = "cla";
p1_inst_94[0] = "inc";
p1_inst_94[1] = "dec";
p1_inst_94[2] = "not";
p1_inst_94[3] = "xchg";
p1_inst_94[4] = "push";
p1_inst_94[5] = "pop";
p1_inst_94[6] = "int";
p1_inst_94[7] = "neg";
}
static void p2_0a1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_0a1_exec(mne, pc, info);
}

static void p2_0a2 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_0a2_exec(mne, pc, info);
}

static void p2_0b1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_0b1_exec(mne, pc, info);
}

static void p2_0b2 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_0b2_exec(mne, pc, info);
}

static void p2_0b3 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_0b3_exec(mne, pc, info);
}

static void p2_0b4 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_0b4_exec(mne, pc, info);
}

static void p2_0c1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_0c1_exec(mne, pc, info);
}

static void p2_0c2 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_0c2_exec(mne, pc, info);
}

static void p2_0d1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_0d1_exec(mne, pc, info);
}

static void p2_0d2 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_0d2_exec(mne, pc, info);
}

static void p2_0d3 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_0d3_exec(mne, pc, info);
}

static void p2_0e (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_0e_exec(mne, pc, info);
}

static void p2_0f1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_0f1_exec(mne, pc, info);
}

static void p1_0f2 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_0f2_exec(mne, pc, info);
}

static void p1_0f3 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_0f3_exec(mne, pc, info);
}

static void p2_0g1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_0g1_exec(mne, pc, info);
}

static void p1_0g2 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_0g2_exec(mne, pc, info);
}

static void p1_0g3 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_0g3_exec(mne, pc, info);
}

static void p1_1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_1_exec(mne, pc, info);
}

static void pX__EA (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_EA[mne >> 20 & 0x8](mne, pc, info);
}

static void pX__EB (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_EB[mne >> 20 & 0x8](mne, pc, info);
}

static void pX__EC (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_EC[mne >> 20 & 0x8](mne, pc, info);
}

static void pX__ED (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_ED[mne >> 20 & 0x8](mne, pc, info);
}

static void pX__EE (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_EE[mne >> 20 & 0x8](mne, pc, info);
}

static void pX__EF (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_EF[mne >> 20 & 0x8](mne, pc, info);
}

static void p2_2a (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_2a_exec(mne, pc, info);
}

static void pX__F0 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_F0[mne >> 20 & 0xF](mne, pc, info);
}

static void p2_2b (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_2b_exec(mne, pc, info);
}

static void pX__F1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_F1[mne >> 20 & 0xF](mne, pc, info);
}

static void p2_3 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_3_exec(mne, pc, info);
}

static void pX__F1_8 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_F1_8[mne >> 12 & 0xF](mne, pc, info);
}

static void p2_4 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_4_exec(mne, pc, info);
}

static void pX__F1_8_C (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_F1_8_C[mne >> 8 & 0xF](mne, pc, info);
}

static void p2_5 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_5_exec(mne, pc, info);
}

static void pX__F1_8_D (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_F1_8_D[mne >> 8 & 0xF](mne, pc, info);
}

static void p2_6 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_6_exec(mne, pc, info);
}

static void pX__F2 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_F2[mne >> 20 & 0xe](mne, pc, info);
}

static void pX__F3 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_F3[mne >> 20 & 0xe](mne, pc, info);
}

static void p2_7a1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_7a1_exec(mne, pc, info);
}

static void pX__F4 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_F4[mne >> 20 & 0xF](mne, pc, info);
}

static void p1_7a2 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_7a2_exec(mne, pc, info);
}

static void p2_7b1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_7b1_exec(mne, pc, info);
}

static void pX__F5 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_F5[mne >> 20 & 0xF](mne, pc, info);
}

static void p1_7a3 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_7a3_exec(mne, pc, info);
}

static void pX__F6 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_F6[mne >> 20 & 0xF](mne, pc, info);
}

static void pX__F7 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_F7[mne >> 20 & 0xF](mne, pc, info);
}

static void p2_7b2 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_7b2_exec(mne, pc, info);
}

static void pX__F8 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_F8[mne >> 20 & 0xF](mne, pc, info);
}

static void p2_7c1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_7c1_exec(mne, pc, info);
}

static void pX__F9 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_F9[mne >> 20 & 0xF](mne, pc, info);
}

static void p2_7c2 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_7c2_exec(mne, pc, info);
}

static void pX__FA (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FA[mne >> 20 & 0xF](mne, pc, info);
}

static void p1_7c3 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_7c3_exec(mne, pc, info);
}

static void pX__FB (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FB[mne >> 20 & 0xF](mne, pc, info);
}

static void p1_7c4 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_7c4_exec(mne, pc, info);
}

static void pX__FC (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FC[mne >> 20 & 0xF](mne, pc, info);
}

static void pX__FD (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FD[mne >> 20 & 0xF](mne, pc, info);
}

static void p1_7c5 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_7c5_exec(mne, pc, info);
}

static void p1_7c6 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_7c6_exec(mne, pc, info);
}

static void p2_8a1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_8a1_exec(mne, pc, info);
}

static void pX__FE (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE[mne >> 20 & 0xF](mne, pc, info);
}

static void pX__FE_6 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_6[mne >> 16 & 0xF](mne, pc, info);
}

static void pX__FE_7 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_7[mne >> 16 & 0xF](mne, pc, info);
}

static void p2_8a2 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_8a2_exec(mne, pc, info);
}

static void pX__FE_8 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_8[mne >> 16 & 0xF](mne, pc, info);
}

static void p2_8a3 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_8a3_exec(mne, pc, info);
}

static void p2_131 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_131_exec(mne, pc, info);
}

static void pX__FE_B (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_B[mne >> 16 & 0xF](mne, pc, info);
}

static void p2_132 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_132_exec(mne, pc, info);
}

static void p2_91 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_91_exec(mne, pc, info);
}

static void pX__FE_C (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_C[mne >> 16 & 0xF](mne, pc, info);
}

static void pX__FE_C_0 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_C_0[mne >> 12 & 0xF](mne, pc, info);
}

static void p2_92 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_92_exec(mne, pc, info);
}

static void p2_101 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p2_101_exec(mne, pc, info);
}

static void pX__FE_C_1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_C_1[mne >> 12 & 0xF](mne, pc, info);
}

static void pX__FE_C_2 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_C_2[mne >> 12 & 0xF](mne, pc, info);
}

static void pX__FE_C_3 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_C_3[mne >> 12 & 0xF](mne, pc, info);
}

static void p1_8a4 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_8a4_exec(mne, pc, info);
}

static void pX__FE_9 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_9[mne >> 16 & 0xF](mne, pc, info);
}

static void pX__FE_A (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_A[mne >> 16 & 0xF](mne, pc, info);
}

static void p1_8a5 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_8a5_exec(mne, pc, info);
}

static void p1_8b1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_8b1_exec(mne, pc, info);
}

static void p1_8b2 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_8b2_exec(mne, pc, info);
}

static void p1_93 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_93_exec(mne, pc, info);
}

static void p1_94 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_94_exec(mne, pc, info);
}

static void p1_102 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_102_exec(mne, pc, info);
}

static void pX__FE_C_4 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_C_4[mne >> 12 & 0xF](mne, pc, info);
}

static void pX__FE_C_5 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_C_5[mne >> 12 & 0xF](mne, pc, info);
}

static void p1_11 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p1_11_exec(mne, pc, info);
}

static void pX__FE_C_6 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_C_6[mne >> 12 & 0xF](mne, pc, info);
}

static void p0_12a (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p0_12a_exec(mne, pc, info);
}

static void pX__FE_C_6_4 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_C_6_4[mne >> 8 & 0xF](mne, pc, info);
}

static void pX__FE_C_6_4_0 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_C_6_4_0[mne >> 4 & 0xF](mne, pc, info);
}

static void pX__FE_C_6_4_0_0 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_C_6_4_0_0[mne >> 0 & 0xF](mne, pc, info);
}

static void pX__FE_C_6_4_0_1 (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FE_C_6_4_0_1[mne >> 0 & 0xF](mne, pc, info);
}

static void p0_12b (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p0_12b_exec(mne, pc, info);
}

static void pX__FF (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FF[mne >> 20 & 0xF](mne, pc, info);
}

static void pX__FF_F (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FF_F[mne >> 16 & 0xF](mne, pc, info);
}

static void pX__FF_F_F (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FF_F_F[mne >> 12 & 0xF](mne, pc, info);
}

static void pX__FF_F_F_F (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FF_F_F_F[mne >> 8 & 0xF](mne, pc, info);
}

static void pX__FF_F_F_F_F (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FF_F_F_F_F[mne >> 4 & 0xF](mne, pc, info);
}

static void pX__FF_F_F_F_F_F (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	fcnPtr_FF_F_F_F_F_F[mne >> 0 & 0xF](mne, pc, info);
}

static void p0_12c (uint32_t mne, bfd_vma pc, disassemble_info * info) {
	p0_12c_exec(mne, pc, info);
}




static void init_ptr() {
	fcnPtr[0x0] = p2_0a1;
	fcnPtr[0x1] = p2_0a1;
	fcnPtr[0x2] = p2_0a1;
	fcnPtr[0x3] = p2_0a1;
	fcnPtr[0x4] = p2_0a1;
	fcnPtr[0x5] = p2_0a1;
	fcnPtr[0x6] = p2_0a1;
	fcnPtr[0x7] = p2_0a1;
	fcnPtr[0x8] = p2_0a1;
	fcnPtr[0x9] = p2_0a1;
	fcnPtr[0xA] = p2_0a1;
	fcnPtr[0xB] = p2_0a1;
	fcnPtr[0xC] = p2_0a1;
	fcnPtr[0xD] = p2_0a1;
	fcnPtr[0xE] = p2_0a2;
	fcnPtr[0xF] = p2_0a2;
	fcnPtr[0x10] = p2_0a2;
	fcnPtr[0x11] = p2_0a2;
	fcnPtr[0x12] = p2_0a2;
	fcnPtr[0x13] = p2_0a2;
	fcnPtr[0x14] = p2_0a2;
	fcnPtr[0x15] = p2_0a2;
	fcnPtr[0x16] = p2_0a2;
	fcnPtr[0x17] = p2_0a2;
	fcnPtr[0x18] = p2_0a2;
	fcnPtr[0x19] = p2_0a2;
	fcnPtr[0x1A] = p2_0a2;
	fcnPtr[0x1B] = p2_0a2;
	fcnPtr[0x1C] = p2_0b1;
	fcnPtr[0x1D] = p2_0b1;
	fcnPtr[0x1E] = p2_0b1;
	fcnPtr[0x1F] = p2_0b1;
	fcnPtr[0x20] = p2_0b1;
	fcnPtr[0x21] = p2_0b1;
	fcnPtr[0x22] = p2_0b1;
	fcnPtr[0x23] = p2_0b1;
	fcnPtr[0x24] = p2_0b1;
	fcnPtr[0x25] = p2_0b1;
	fcnPtr[0x26] = p2_0b1;
	fcnPtr[0x27] = p2_0b1;
	fcnPtr[0x28] = p2_0b1;
	fcnPtr[0x29] = p2_0b1;
	fcnPtr[0x2A] = p2_0b1;
	fcnPtr[0x2B] = p2_0b1;
	fcnPtr[0x2C] = p2_0b1;
	fcnPtr[0x2D] = p2_0b1;
	fcnPtr[0x2E] = p2_0b1;
	fcnPtr[0x2F] = p2_0b1;
	fcnPtr[0x30] = p2_0b1;
	fcnPtr[0x31] = p2_0b1;
	fcnPtr[0x32] = p2_0b1;
	fcnPtr[0x33] = p2_0b1;
	fcnPtr[0x34] = p2_0b2;
	fcnPtr[0x35] = p2_0b2;
	fcnPtr[0x36] = p2_0b2;
	fcnPtr[0x37] = p2_0b2;
	fcnPtr[0x38] = p2_0b2;
	fcnPtr[0x39] = p2_0b2;
	fcnPtr[0x3A] = p2_0b2;
	fcnPtr[0x3B] = p2_0b2;
	fcnPtr[0x3C] = p2_0b2;
	fcnPtr[0x3D] = p2_0b2;
	fcnPtr[0x3E] = p2_0b2;
	fcnPtr[0x3F] = p2_0b2;
	fcnPtr[0x40] = p2_0b2;
	fcnPtr[0x41] = p2_0b2;
	fcnPtr[0x42] = p2_0b3;
	fcnPtr[0x43] = p2_0b3;
	fcnPtr[0x44] = p2_0b3;
	fcnPtr[0x45] = p2_0b3;
	fcnPtr[0x46] = p2_0b3;
	fcnPtr[0x47] = p2_0b3;
	fcnPtr[0x48] = p2_0b3;
	fcnPtr[0x49] = p2_0b3;
	fcnPtr[0x4A] = p2_0b3;
	fcnPtr[0x4B] = p2_0b3;
	fcnPtr[0x4C] = p2_0b3;
	fcnPtr[0x4D] = p2_0b3;
	fcnPtr[0x4E] = p2_0b3;
	fcnPtr[0x4F] = p2_0b3;
	fcnPtr[0x50] = p2_0b3;
	fcnPtr[0x51] = p2_0b3;
	fcnPtr[0x52] = p2_0b3;
	fcnPtr[0x53] = p2_0b3;
	fcnPtr[0x54] = p2_0b3;
	fcnPtr[0x55] = p2_0b3;
	fcnPtr[0x56] = p2_0b3;
	fcnPtr[0x57] = p2_0b3;
	fcnPtr[0x58] = p2_0b3;
	fcnPtr[0x59] = p2_0b3;
	fcnPtr[0x5A] = p2_0b4;
	fcnPtr[0x5B] = p2_0b4;
	fcnPtr[0x5C] = p2_0b4;
	fcnPtr[0x5D] = p2_0b4;
	fcnPtr[0x5E] = p2_0b4;
	fcnPtr[0x5F] = p2_0b4;
	fcnPtr[0x60] = p2_0b4;
	fcnPtr[0x61] = p2_0b4;
	fcnPtr[0x62] = p2_0b4;
	fcnPtr[0x63] = p2_0b4;
	fcnPtr[0x64] = p2_0b4;
	fcnPtr[0x65] = p2_0b4;
	fcnPtr[0x66] = p2_0b4;
	fcnPtr[0x67] = p2_0b4;
	fcnPtr[0x68] = p2_0c1;
	fcnPtr[0x69] = p2_0c1;
	fcnPtr[0x6A] = p2_0c1;
	fcnPtr[0x6B] = p2_0c1;
	fcnPtr[0x6C] = p2_0c1;
	fcnPtr[0x6D] = p2_0c1;
	fcnPtr[0x6E] = p2_0c1;
	fcnPtr[0x6F] = p2_0c1;
	fcnPtr[0x70] = p2_0c1;
	fcnPtr[0x71] = p2_0c1;
	fcnPtr[0x72] = p2_0c1;
	fcnPtr[0x73] = p2_0c1;
	fcnPtr[0x74] = p2_0c1;
	fcnPtr[0x75] = p2_0c1;
	fcnPtr[0x76] = p2_0c1;
	fcnPtr[0x77] = p2_0c1;
	fcnPtr[0x78] = p2_0c1;
	fcnPtr[0x79] = p2_0c1;
	fcnPtr[0x7A] = p2_0c1;
	fcnPtr[0x7B] = p2_0c1;
	fcnPtr[0x7C] = p2_0c1;
	fcnPtr[0x7D] = p2_0c1;
	fcnPtr[0x7E] = p2_0c1;
	fcnPtr[0x7F] = p2_0c1;
	fcnPtr[0x80] = p2_0c2;
	fcnPtr[0x81] = p2_0c2;
	fcnPtr[0x82] = p2_0c2;
	fcnPtr[0x83] = p2_0c2;
	fcnPtr[0x84] = p2_0c2;
	fcnPtr[0x85] = p2_0c2;
	fcnPtr[0x86] = p2_0c2;
	fcnPtr[0x87] = p2_0c2;
	fcnPtr[0x88] = p2_0c2;
	fcnPtr[0x89] = p2_0c2;
	fcnPtr[0x8A] = p2_0c2;
	fcnPtr[0x8B] = p2_0c2;
	fcnPtr[0x8C] = p2_0c2;
	fcnPtr[0x8D] = p2_0c2;
	fcnPtr[0x8E] = p2_0d1;
	fcnPtr[0x8F] = p2_0d1;
	fcnPtr[0x90] = p2_0d1;
	fcnPtr[0x91] = p2_0d1;
	fcnPtr[0x92] = p2_0d1;
	fcnPtr[0x93] = p2_0d1;
	fcnPtr[0x94] = p2_0d1;
	fcnPtr[0x95] = p2_0d1;
	fcnPtr[0x96] = p2_0d1;
	fcnPtr[0x97] = p2_0d1;
	fcnPtr[0x98] = p2_0d1;
	fcnPtr[0x99] = p2_0d1;
	fcnPtr[0x9A] = p2_0d1;
	fcnPtr[0x9B] = p2_0d1;
	fcnPtr[0x9C] = p2_0d2;
	fcnPtr[0x9D] = p2_0d2;
	fcnPtr[0x9E] = p2_0d2;
	fcnPtr[0x9F] = p2_0d2;
	fcnPtr[0xA0] = p2_0d2;
	fcnPtr[0xA1] = p2_0d2;
	fcnPtr[0xA2] = p2_0d2;
	fcnPtr[0xA3] = p2_0d2;
	fcnPtr[0xA4] = p2_0d2;
	fcnPtr[0xA5] = p2_0d2;
	fcnPtr[0xA6] = p2_0d2;
	fcnPtr[0xA7] = p2_0d2;
	fcnPtr[0xA8] = p2_0d2;
	fcnPtr[0xA9] = p2_0d2;
	fcnPtr[0xAA] = p2_0d2;
	fcnPtr[0xAB] = p2_0d2;
	fcnPtr[0xAC] = p2_0d2;
	fcnPtr[0xAD] = p2_0d2;
	fcnPtr[0xAE] = p2_0d2;
	fcnPtr[0xAF] = p2_0d2;
	fcnPtr[0xB0] = p2_0d2;
	fcnPtr[0xB1] = p2_0d2;
	fcnPtr[0xB2] = p2_0d2;
	fcnPtr[0xB3] = p2_0d2;
	fcnPtr[0xB4] = p2_0d3;
	fcnPtr[0xB5] = p2_0d3;
	fcnPtr[0xB6] = p2_0d3;
	fcnPtr[0xB7] = p2_0d3;
	fcnPtr[0xB8] = p2_0d3;
	fcnPtr[0xB9] = p2_0d3;
	fcnPtr[0xBA] = p2_0d3;
	fcnPtr[0xBB] = p2_0d3;
	fcnPtr[0xBC] = p2_0d3;
	fcnPtr[0xBD] = p2_0d3;
	fcnPtr[0xBE] = p2_0d3;
	fcnPtr[0xBF] = p2_0d3;
	fcnPtr[0xC0] = p2_0d3;
	fcnPtr[0xC1] = p2_0d3;
	fcnPtr[0xC2] = p2_0e;
	fcnPtr[0xC3] = p2_0e;
	fcnPtr[0xC4] = p2_0e;
	fcnPtr[0xC5] = p2_0e;
	fcnPtr[0xC6] = p2_0e;
	fcnPtr[0xC7] = p2_0e;
	fcnPtr[0xC8] = p2_0e;
	fcnPtr[0xC9] = p2_0e;
	fcnPtr[0xCA] = p2_0e;
	fcnPtr[0xCB] = p2_0e;
	fcnPtr[0xCC] = p2_0e;
	fcnPtr[0xCD] = p2_0e;
	fcnPtr[0xCE] = p2_0e;
	fcnPtr[0xCF] = p2_0e;
	fcnPtr[0xD0] = p2_0f1;
	fcnPtr[0xD1] = p2_0f1;
	fcnPtr[0xD2] = p2_0f1;
	fcnPtr[0xD3] = p2_0f1;
	fcnPtr[0xD4] = p2_0f1;
	fcnPtr[0xD5] = p2_0f1;
	fcnPtr[0xD6] = p2_0f1;
	fcnPtr[0xD7] = p2_0f1;
	fcnPtr[0xD8] = p2_0f1;
	fcnPtr[0xD9] = p2_0f1;
	fcnPtr[0xDA] = p2_0f1;
	fcnPtr[0xDB] = p2_0f1;
	fcnPtr[0xDC] = p2_0f1;
	fcnPtr[0xDD] = p2_0f1;
	fcnPtr[0xDE] = p1_0f2;
	fcnPtr[0xDF] = p1_0f2;
	fcnPtr[0xE0] = p1_0f3;
	fcnPtr[0xE1] = p1_0f3;
	fcnPtr[0xE2] = p1_0f3;
	fcnPtr[0xE3] = p1_0f3;
	fcnPtr[0xE4] = p2_0g1;
	fcnPtr[0xE5] = p1_0g2;
	fcnPtr[0xE6] = p1_0g3;
	fcnPtr[0xE7] = p1_0g3;
	fcnPtr[0xE8] = p1_0g3;
	fcnPtr[0xE9] = p1_0g3;
	fcnPtr[0xEA] = pX__EA;
	fcnPtr_EA[0x0] = p1_1;
	fcnPtr_EA[0x1] = p1_1;
	fcnPtr_EA[0x2] = p1_1;
	fcnPtr_EA[0x3] = p1_1;
	fcnPtr_EA[0x4] = p1_1;
	fcnPtr_EA[0x5] = p1_1;
	fcnPtr_EA[0x6] = p1_1;
	fcnPtr_EA[0x7] = p1_1;
	fcnPtr_EA[0x8] = p1_1;
	fcnPtr_EA[0x9] = p1_1;
	fcnPtr_EA[0xa] = p1_1;
	fcnPtr_EA[0xb] = p1_1;
	fcnPtr_EA[0xc] = p1_1;
	fcnPtr_EA[0xd] = p1_1;
	fcnPtr_EA[0xe] = p1_1;
	fcnPtr_EA[0xf] = p1_1;
	fcnPtr[0xEB] = pX__EB;
	fcnPtr_EB[0x0] = p1_1;
	fcnPtr_EB[0x1] = p1_1;
	fcnPtr_EB[0x2] = p1_1;
	fcnPtr_EB[0x3] = p1_1;
	fcnPtr_EB[0x4] = p1_1;
	fcnPtr_EB[0x5] = p1_1;
	fcnPtr_EB[0x6] = p1_1;
	fcnPtr_EB[0x7] = p1_1;
	fcnPtr_EB[0x8] = p1_1;
	fcnPtr_EB[0x9] = p1_1;
	fcnPtr_EB[0xa] = p1_1;
	fcnPtr_EB[0xb] = p1_1;
	fcnPtr_EB[0xc] = p1_1;
	fcnPtr_EB[0xd] = p1_1;
	fcnPtr_EB[0xe] = p1_1;
	fcnPtr_EB[0xf] = p1_1;
	fcnPtr[0xEC] = pX__EC;
	fcnPtr_EC[0x0] = p1_1;
	fcnPtr_EC[0x1] = p1_1;
	fcnPtr_EC[0x2] = p1_1;
	fcnPtr_EC[0x3] = p1_1;
	fcnPtr_EC[0x4] = p1_1;
	fcnPtr_EC[0x5] = p1_1;
	fcnPtr_EC[0x6] = p1_1;
	fcnPtr_EC[0x7] = p1_1;
	fcnPtr_EC[0x8] = p1_1;
	fcnPtr_EC[0x9] = p1_1;
	fcnPtr_EC[0xa] = p1_1;
	fcnPtr_EC[0xb] = p1_1;
	fcnPtr_EC[0xc] = p1_1;
	fcnPtr_EC[0xd] = p1_1;
	fcnPtr_EC[0xe] = p1_1;
	fcnPtr_EC[0xf] = p1_1;
	fcnPtr[0xED] = pX__ED;
	fcnPtr_ED[0x0] = p1_1;
	fcnPtr_ED[0x1] = p1_1;
	fcnPtr_ED[0x2] = p1_1;
	fcnPtr_ED[0x3] = p1_1;
	fcnPtr_ED[0x4] = p1_1;
	fcnPtr_ED[0x5] = p1_1;
	fcnPtr_ED[0x6] = p1_1;
	fcnPtr_ED[0x7] = p1_1;
	fcnPtr_ED[0x8] = p1_1;
	fcnPtr_ED[0x9] = p1_1;
	fcnPtr_ED[0xa] = p1_1;
	fcnPtr_ED[0xb] = p1_1;
	fcnPtr_ED[0xc] = p1_1;
	fcnPtr_ED[0xd] = p1_1;
	fcnPtr_ED[0xe] = p1_1;
	fcnPtr_ED[0xf] = p1_1;
	fcnPtr[0xEE] = pX__EE;
	fcnPtr_EE[0x0] = p1_1;
	fcnPtr_EE[0x1] = p1_1;
	fcnPtr_EE[0x2] = p1_1;
	fcnPtr_EE[0x3] = p1_1;
	fcnPtr_EE[0x4] = p1_1;
	fcnPtr_EE[0x5] = p1_1;
	fcnPtr_EE[0x6] = p1_1;
	fcnPtr_EE[0x7] = p1_1;
	fcnPtr_EE[0x8] = p1_1;
	fcnPtr_EE[0x9] = p1_1;
	fcnPtr_EE[0xa] = p1_1;
	fcnPtr_EE[0xb] = p1_1;
	fcnPtr_EE[0xc] = p1_1;
	fcnPtr_EE[0xd] = p1_1;
	fcnPtr_EE[0xe] = p1_1;
	fcnPtr_EE[0xf] = p1_1;
	fcnPtr[0xEF] = pX__EF;
	fcnPtr_EF[0x0] = p1_1;
	fcnPtr_EF[0x1] = p1_1;
	fcnPtr_EF[0x2] = p1_1;
	fcnPtr_EF[0x3] = p1_1;
	fcnPtr_EF[0x4] = p1_1;
	fcnPtr_EF[0x5] = p1_1;
	fcnPtr_EF[0x6] = p1_1;
	fcnPtr_EF[0x7] = p1_1;
	fcnPtr_EF[0x8] = p1_1;
	fcnPtr_EF[0x9] = p1_1;
	fcnPtr_EF[0xa] = p1_1;
	fcnPtr_EF[0xb] = p1_1;
	fcnPtr_EF[0xc] = p1_1;
	fcnPtr_EF[0xd] = p1_1;
	fcnPtr_EF[0xe] = p1_1;
	fcnPtr_EF[0xf] = p1_1;
	fcnPtr[0xF0] = pX__F0;
	fcnPtr_F0[0x0] = p2_2a;
	fcnPtr_F0[0x1] = p2_2a;
	fcnPtr_F0[0x2] = p2_2a;
	fcnPtr_F0[0x3] = p2_2a;
	fcnPtr_F0[0x4] = p2_2a;
	fcnPtr_F0[0x5] = p2_2a;
	fcnPtr_F0[0x6] = p2_2a;
	fcnPtr_F0[0x7] = p2_2a;
	fcnPtr_F0[0x8] = p2_2a;
	fcnPtr_F0[0x9] = p2_2a;
	fcnPtr_F0[0xa] = p2_2a;
	fcnPtr_F0[0xb] = p2_2a;
	fcnPtr_F0[0xc] = p2_2b;
	fcnPtr_F0[0xd] = p2_2b;
	fcnPtr_F0[0xe] = p2_2b;
	fcnPtr_F0[0xf] = p2_2b;
	fcnPtr[0xF1] = pX__F1;
	fcnPtr_F1[0x0] = p2_2b;
	fcnPtr_F1[0x1] = p2_2b;
	fcnPtr_F1[0x2] = p2_2b;
	fcnPtr_F1[0x3] = p2_2b;
	fcnPtr_F1[0x4] = p2_2b;
	fcnPtr_F1[0x5] = p2_2b;
	fcnPtr_F1[0x6] = p2_2b;
	fcnPtr_F1[0x7] = p2_2b;
	fcnPtr_F1[0x8] = pX__F1_8;
	fcnPtr_F1_8[0x0] = p2_3;
	fcnPtr_F1_8[0x1] = p2_3;
	fcnPtr_F1_8[0x2] = p2_3;
	fcnPtr_F1_8[0x3] = p2_3;
	fcnPtr_F1_8[0x4] = p2_3;
	fcnPtr_F1_8[0x5] = p2_3;
	fcnPtr_F1_8[0x6] = p2_3;
	fcnPtr_F1_8[0x7] = p2_3;
	fcnPtr_F1_8[0x8] = p2_3;
	fcnPtr_F1_8[0x9] = p2_3;
	fcnPtr_F1_8[0xa] = p2_3;
	fcnPtr_F1_8[0xb] = p2_3;
	fcnPtr_F1_8[0xC] = pX__F1_8_C;
	fcnPtr_F1_8_C[0x0] = p2_4;
	fcnPtr_F1_8_C[0x1] = p2_4;
	fcnPtr_F1_8_C[0x2] = p2_4;
	fcnPtr_F1_8_C[0x3] = p2_4;
	fcnPtr_F1_8_C[0x4] = p2_4;
	fcnPtr_F1_8_C[0x5] = p2_4;
	fcnPtr_F1_8_C[0x6] = p2_4;
	fcnPtr_F1_8_C[0x7] = p2_4;
	fcnPtr_F1_8_C[0x8] = p2_4;
	fcnPtr_F1_8_C[0x9] = p2_4;
	fcnPtr_F1_8_C[0xa] = p2_4;
	fcnPtr_F1_8_C[0xb] = p2_4;
	fcnPtr_F1_8_C[0xc] = p2_5;
	fcnPtr_F1_8_C[0xd] = p2_5;
	fcnPtr_F1_8_C[0xe] = p2_5;
	fcnPtr_F1_8_C[0xf] = p2_5;
	fcnPtr_F1_8[0xD] = pX__F1_8_D;
	fcnPtr_F1_8_D[0x0] = p2_5;
	fcnPtr_F1_8_D[0x1] = p2_5;
	fcnPtr_F1_8_D[0x2] = p2_5;
	fcnPtr_F1_8_D[0x3] = p2_5;
	fcnPtr_F1_8_D[0x4] = p2_5;
	fcnPtr_F1_8_D[0x5] = p2_5;
	fcnPtr_F1_8_D[0x6] = p2_5;
	fcnPtr_F1_8_D[0x7] = p2_5;
	fcnPtr_F1[0xa] = p2_6;
	fcnPtr_F1[0xb] = p2_6;
	fcnPtr_F1[0xc] = p2_6;
	fcnPtr_F1[0xd] = p2_6;
	fcnPtr_F1[0xe] = p2_6;
	fcnPtr_F1[0xf] = p2_6;
	fcnPtr[0xF2] = pX__F2;
	fcnPtr_F2[0x0] = p2_6;
	fcnPtr_F2[0x1] = p2_6;
	fcnPtr_F2[0x2] = p2_6;
	fcnPtr_F2[0x3] = p2_6;
	fcnPtr_F2[0x4] = p2_6;
	fcnPtr_F2[0x5] = p2_6;
	fcnPtr_F2[0x6] = p2_6;
	fcnPtr_F2[0x7] = p2_6;
	fcnPtr_F2[0x8] = p2_6;
	fcnPtr_F2[0x9] = p2_6;
	fcnPtr_F2[0xa] = p2_6;
	fcnPtr_F2[0xb] = p2_6;
	fcnPtr_F2[0xc] = p2_6;
	fcnPtr_F2[0xd] = p2_6;
	fcnPtr_F2[0xe] = p2_6;
	fcnPtr_F2[0xf] = p2_6;
	fcnPtr[0xF3] = pX__F3;
	fcnPtr_F3[0x0] = p2_6;
	fcnPtr_F3[0x1] = p2_6;
	fcnPtr_F3[0x2] = p2_6;
	fcnPtr_F3[0x3] = p2_6;
	fcnPtr_F3[0x4] = p2_6;
	fcnPtr_F3[0x5] = p2_6;
	fcnPtr_F3[0x6] = p2_7a1;
	fcnPtr_F3[0x7] = p2_7a1;
	fcnPtr_F3[0x8] = p2_7a1;
	fcnPtr_F3[0x9] = p2_7a1;
	fcnPtr_F3[0xa] = p2_7a1;
	fcnPtr_F3[0xb] = p2_7a1;
	fcnPtr_F3[0xc] = p2_7a1;
	fcnPtr_F3[0xd] = p2_7a1;
	fcnPtr_F3[0xe] = p2_7a1;
	fcnPtr_F3[0xf] = p2_7a1;
	fcnPtr[0xF4] = pX__F4;
	fcnPtr_F4[0x0] = p2_7a1;
	fcnPtr_F4[0x1] = p2_7a1;
	fcnPtr_F4[0x2] = p2_7a1;
	fcnPtr_F4[0x3] = p2_7a1;
	fcnPtr_F4[0x4] = p1_7a2;
	fcnPtr_F4[0x5] = p1_7a2;
	fcnPtr_F4[0x6] = p1_7a2;
	fcnPtr_F4[0x7] = p1_7a2;
	fcnPtr_F4[0x8] = p1_7a2;
	fcnPtr_F4[0x9] = p1_7a2;
	fcnPtr_F4[0xa] = p1_7a2;
	fcnPtr_F4[0xb] = p1_7a2;
	fcnPtr_F4[0xc] = p1_7a2;
	fcnPtr_F4[0xd] = p1_7a2;
	fcnPtr_F4[0xe] = p1_7a2;
	fcnPtr_F4[0xf] = p1_7a2;
	fcnPtr[0xF5] = pX__F5;
	fcnPtr_F5[0xa] = p2_7b1;
	fcnPtr_F5[0xb] = p2_7b1;
	fcnPtr_F5[0xc] = p2_7b1;
	fcnPtr_F5[0xd] = p2_7b1;
	fcnPtr_F5[0xe] = p2_7b1;
	fcnPtr_F5[0xf] = p2_7b1;
	fcnPtr_F5[0x0] = p1_7a2;
	fcnPtr_F5[0x1] = p1_7a2;
	fcnPtr_F5[0x2] = p1_7a3;
	fcnPtr_F5[0x3] = p1_7a3;
	fcnPtr_F5[0x4] = p1_7a3;
	fcnPtr_F5[0x5] = p1_7a3;
	fcnPtr_F5[0x6] = p1_7a3;
	fcnPtr_F5[0x7] = p1_7a3;
	fcnPtr_F5[0x8] = p1_7a3;
	fcnPtr_F5[0x9] = p1_7a3;
	fcnPtr[0xF6] = pX__F6;
	fcnPtr_F6[0x0] = p2_7b1;
	fcnPtr_F6[0x1] = p2_7b1;
	fcnPtr_F6[0x2] = p2_7b1;
	fcnPtr_F6[0x3] = p2_7b1;
	fcnPtr_F6[0x4] = p2_7b1;
	fcnPtr_F6[0x5] = p2_7b1;
	fcnPtr_F6[0x6] = p2_7b1;
	fcnPtr_F6[0x7] = p2_7b1;
	fcnPtr_F6[0x8] = p2_7b1;
	fcnPtr_F6[0x9] = p2_7b1;
	fcnPtr_F6[0xa] = p2_7b1;
	fcnPtr_F6[0xb] = p2_7b1;
	fcnPtr_F6[0xc] = p2_7b1;
	fcnPtr_F6[0xd] = p2_7b1;
	fcnPtr_F6[0xe] = p2_7b1;
	fcnPtr_F6[0xf] = p2_7b1;
	fcnPtr[0xF7] = pX__F7;
	fcnPtr_F7[0x0] = p2_7b1;
	fcnPtr_F7[0x1] = p2_7b1;
	fcnPtr_F7[0x2] = p2_7b1;
	fcnPtr_F7[0x3] = p2_7b1;
	fcnPtr_F7[0x4] = p2_7b2;
	fcnPtr_F7[0x5] = p2_7b2;
	fcnPtr_F7[0x6] = p2_7b2;
	fcnPtr_F7[0x7] = p2_7b2;
	fcnPtr_F7[0x8] = p2_7b2;
	fcnPtr_F7[0x9] = p2_7b2;
	fcnPtr_F7[0xa] = p2_7b2;
	fcnPtr_F7[0xb] = p2_7b2;
	fcnPtr_F7[0xc] = p2_7b2;
	fcnPtr_F7[0xd] = p2_7b2;
	fcnPtr_F7[0xe] = p2_7b2;
	fcnPtr_F7[0xf] = p2_7b2;
	fcnPtr[0xF8] = pX__F8;
	fcnPtr_F8[0x0] = p2_7b2;
	fcnPtr_F8[0x1] = p2_7b2;
	fcnPtr_F8[0x2] = p2_7c1;
	fcnPtr_F8[0x3] = p2_7c1;
	fcnPtr_F8[0x4] = p2_7c1;
	fcnPtr_F8[0x5] = p2_7c1;
	fcnPtr_F8[0x6] = p2_7c1;
	fcnPtr_F8[0x7] = p2_7c1;
	fcnPtr_F8[0x8] = p2_7c1;
	fcnPtr_F8[0x9] = p2_7c1;
	fcnPtr_F8[0xa] = p2_7c1;
	fcnPtr_F8[0xb] = p2_7c1;
	fcnPtr_F8[0xc] = p2_7c1;
	fcnPtr_F8[0xd] = p2_7c1;
	fcnPtr_F8[0xe] = p2_7c1;
	fcnPtr_F8[0xf] = p2_7c1;
	fcnPtr[0xF9] = pX__F9;
	fcnPtr_F9[0x0] = p2_7c1;
	fcnPtr_F9[0x1] = p2_7c1;
	fcnPtr_F9[0x2] = p2_7c1;
	fcnPtr_F9[0x3] = p2_7c1;
	fcnPtr_F9[0x4] = p2_7c1;
	fcnPtr_F9[0x5] = p2_7c1;
	fcnPtr_F9[0x6] = p2_7c1;
	fcnPtr_F9[0x7] = p2_7c1;
	fcnPtr_F9[0x8] = p2_7c1;
	fcnPtr_F9[0x9] = p2_7c1;
	fcnPtr_F9[0xa] = p2_7c2;
	fcnPtr_F9[0xb] = p2_7c2;
	fcnPtr_F9[0xc] = p2_7c2;
	fcnPtr_F9[0xd] = p2_7c2;
	fcnPtr_F9[0xe] = p2_7c2;
	fcnPtr_F9[0xf] = p2_7c2;
	fcnPtr[0xFA] = pX__FA;
	fcnPtr_FA[0x0] = p2_7c2;
	fcnPtr_FA[0x1] = p2_7c2;
	fcnPtr_FA[0x2] = p2_7c2;
	fcnPtr_FA[0x3] = p2_7c2;
	fcnPtr_FA[0x4] = p2_7c2;
	fcnPtr_FA[0x5] = p2_7c2;
	fcnPtr_FA[0x6] = p2_7c2;
	fcnPtr_FA[0x7] = p2_7c2;
	fcnPtr_FA[0x8] = p1_7c3;
	fcnPtr_FA[0x9] = p1_7c3;
	fcnPtr_FA[0xa] = p1_7c3;
	fcnPtr_FA[0xb] = p1_7c3;
	fcnPtr_FA[0xc] = p1_7c3;
	fcnPtr_FA[0xd] = p1_7c3;
	fcnPtr_FA[0xe] = p1_7c3;
	fcnPtr_FA[0xf] = p1_7c3;
	fcnPtr[0xFB] = pX__FB;
	fcnPtr_FB[0x0] = p1_7c3;
	fcnPtr_FB[0x1] = p1_7c3;
	fcnPtr_FB[0x2] = p1_7c3;
	fcnPtr_FB[0x3] = p1_7c3;
	fcnPtr_FB[0x4] = p1_7c3;
	fcnPtr_FB[0x5] = p1_7c3;
	fcnPtr_FB[0x6] = p1_7c3;
	fcnPtr_FB[0x7] = p1_7c3;
	fcnPtr_FB[0x8] = p1_7c3;
	fcnPtr_FB[0x9] = p1_7c3;
	fcnPtr_FB[0xa] = p1_7c3;
	fcnPtr_FB[0xb] = p1_7c3;
	fcnPtr_FB[0xc] = p1_7c3;
	fcnPtr_FB[0xd] = p1_7c3;
	fcnPtr_FB[0xe] = p1_7c3;
	fcnPtr_FB[0xf] = p1_7c4;
	fcnPtr[0xFC] = pX__FC;
	fcnPtr_FC[0x0] = p1_7c4;
	fcnPtr_FC[0x1] = p1_7c4;
	fcnPtr_FC[0x2] = p1_7c4;
	fcnPtr_FC[0x3] = p1_7c4;
	fcnPtr_FC[0x4] = p1_7c4;
	fcnPtr_FC[0x5] = p1_7c4;
	fcnPtr_FC[0x6] = p1_7c4;
	fcnPtr_FC[0x7] = p1_7c4;
	fcnPtr_FC[0x8] = p1_7c4;
	fcnPtr_FC[0x9] = p1_7c4;
	fcnPtr_FC[0xa] = p1_7c4;
	fcnPtr_FC[0xb] = p1_7c4;
	fcnPtr_FC[0xc] = p1_7c4;
	fcnPtr_FC[0xd] = p1_7c4;
	fcnPtr_FC[0xe] = p1_7c4;
	fcnPtr_FC[0xf] = p1_7c4;
	fcnPtr[0xFD] = pX__FD;
	fcnPtr_FD[0x0] = p1_7c4;
	fcnPtr_FD[0x1] = p1_7c4;
	fcnPtr_FD[0x2] = p1_7c4;
	fcnPtr_FD[0x3] = p1_7c4;
	fcnPtr_FD[0x4] = p1_7c4;
	fcnPtr_FD[0x5] = p1_7c4;
	fcnPtr_FD[0x6] = p1_7c5;
	fcnPtr_FD[0x7] = p1_7c5;
	fcnPtr_FD[0x8] = p1_7c5;
	fcnPtr_FD[0x9] = p1_7c5;
	fcnPtr_FD[0xa] = p1_7c5;
	fcnPtr_FD[0xb] = p1_7c5;
	fcnPtr_FD[0xc] = p1_7c5;
	fcnPtr_FD[0xd] = p1_7c5;
	fcnPtr_FD[0xe] = p1_7c6;
	fcnPtr_FD[0xf] = p1_7c6;
	fcnPtr[0xFE] = pX__FE;
	fcnPtr_FE[0x6] = pX__FE_6;
	fcnPtr_FE_6[0x0] = p2_8a1;
	fcnPtr_FE_6[0x1] = p2_8a1;
	fcnPtr_FE_6[0x2] = p2_8a1;
	fcnPtr_FE_6[0x3] = p2_8a1;
	fcnPtr_FE_6[0x4] = p2_8a1;
	fcnPtr_FE_6[0x5] = p2_8a1;
	fcnPtr_FE_6[0x6] = p2_8a1;
	fcnPtr_FE_6[0x7] = p2_8a1;
	fcnPtr_FE_6[0x8] = p2_8a1;
	fcnPtr_FE_6[0x9] = p2_8a1;
	fcnPtr_FE_6[0xa] = p2_8a1;
	fcnPtr_FE_6[0xb] = p2_8a1;
	fcnPtr_FE_6[0xc] = p2_8a1;
	fcnPtr_FE_6[0xd] = p2_8a1;
	fcnPtr_FE_6[0xe] = p2_8a1;
	fcnPtr_FE_6[0xf] = p2_8a1;
	fcnPtr_FE[0x7] = pX__FE_7;
	fcnPtr_FE_7[0x0] = p2_8a1;
	fcnPtr_FE_7[0x1] = p2_8a1;
	fcnPtr_FE_7[0x2] = p2_8a1;
	fcnPtr_FE_7[0x3] = p2_8a1;
	fcnPtr_FE_7[0x4] = p2_8a1;
	fcnPtr_FE_7[0x5] = p2_8a1;
	fcnPtr_FE_7[0x6] = p2_8a1;
	fcnPtr_FE_7[0x7] = p2_8a1;
	fcnPtr_FE_7[0x8] = p2_8a1;
	fcnPtr_FE_7[0x9] = p2_8a1;
	fcnPtr_FE_7[0xa] = p2_8a2;
	fcnPtr_FE_7[0xb] = p2_8a2;
	fcnPtr_FE_7[0xc] = p2_8a2;
	fcnPtr_FE_7[0xd] = p2_8a2;
	fcnPtr_FE_7[0xe] = p2_8a2;
	fcnPtr_FE_7[0xf] = p2_8a2;
	fcnPtr_FE[0x8] = pX__FE_8;
	fcnPtr_FE_8[0x0] = p2_8a2;
	fcnPtr_FE_8[0x1] = p2_8a2;
	fcnPtr_FE_8[0x2] = p2_8a2;
	fcnPtr_FE_8[0x3] = p2_8a2;
	fcnPtr_FE_8[0x4] = p2_8a2;
	fcnPtr_FE_8[0x5] = p2_8a2;
	fcnPtr_FE_8[0x6] = p2_8a2;
	fcnPtr_FE_8[0x7] = p2_8a2;
	fcnPtr_FE_8[0x8] = p2_8a3;
	fcnPtr_FE_8[0x9] = p2_8a3;
	fcnPtr_FE[0xB] = pX__FE_B;
	fcnPtr_FE_B[0xd] = p2_131;
	fcnPtr_FE_B[0xe] = p2_132;
	fcnPtr_FE[0xC] = pX__FE_C;
	fcnPtr_FE_C[0x0] = pX__FE_C_0;
	fcnPtr_FE_C_0[0x0] = p2_91;
	fcnPtr_FE_C_0[0x1] = p2_91;
	fcnPtr_FE_C_0[0x2] = p2_92;
	fcnPtr_FE_C_0[0x3] = p2_92;
	fcnPtr_FE_C_0[0x4] = p2_92;
	fcnPtr_FE_C_0[0x5] = p2_92;
	fcnPtr_FE_C_0[0x6] = p2_92;
	fcnPtr_FE_C_0[0x7] = p2_92;
	fcnPtr_FE_C_0[0x8] = p2_92;
	fcnPtr_FE_C_0[0x9] = p2_92;
	fcnPtr_FE_C[0x1] = pX__FE_C_1;
	fcnPtr_FE_C_1[0xe] = p2_101;
	fcnPtr_FE_C_1[0xf] = p2_101;
	fcnPtr_FE_C[0x2] = pX__FE_C_2;
	fcnPtr_FE_C_2[0x0] = p2_101;
	fcnPtr_FE_C_2[0x1] = p2_101;
	fcnPtr_FE_C_2[0x2] = p2_101;
	fcnPtr_FE_C_2[0x3] = p2_101;
	fcnPtr_FE_C_2[0x4] = p2_101;
	fcnPtr_FE_C_2[0x5] = p2_101;
	fcnPtr_FE_C_2[0x6] = p2_101;
	fcnPtr_FE_C_2[0x7] = p2_101;
	fcnPtr_FE_C_2[0x8] = p2_101;
	fcnPtr_FE_C_2[0x9] = p2_101;
	fcnPtr_FE_C_2[0xa] = p2_101;
	fcnPtr_FE_C_2[0xb] = p2_101;
	fcnPtr_FE_C_2[0xc] = p2_101;
	fcnPtr_FE_C_2[0xd] = p2_101;
	fcnPtr_FE_C_2[0xe] = p2_101;
	fcnPtr_FE_C_2[0xf] = p2_101;
	fcnPtr_FE_C[0x3] = pX__FE_C_3;
	fcnPtr_FE_C_3[0x0] = p2_101;
	fcnPtr_FE_C_3[0x1] = p2_101;
	fcnPtr_FE_C_3[0x2] = p2_101;
	fcnPtr_FE_C_3[0x3] = p2_101;
	fcnPtr_FE_C_3[0x4] = p2_101;
	fcnPtr_FE_C_3[0x5] = p2_101;
	fcnPtr_FE_C_3[0x6] = p2_101;
	fcnPtr_FE_C_3[0x7] = p2_101;
	fcnPtr_FE[0x0] = p1_7c6;
	fcnPtr_FE[0x1] = p1_7c6;
	fcnPtr_FE[0x2] = p1_7c6;
	fcnPtr_FE[0x3] = p1_7c6;
	fcnPtr_FE[0x4] = p1_7c6;
	fcnPtr_FE[0x5] = p1_7c6;
	fcnPtr_FE_8[0xa] = p1_8a4;
	fcnPtr_FE_8[0xb] = p1_8a4;
	fcnPtr_FE_8[0xc] = p1_8a4;
	fcnPtr_FE_8[0xd] = p1_8a4;
	fcnPtr_FE_8[0xe] = p1_8a4;
	fcnPtr_FE_8[0xf] = p1_8a4;
	fcnPtr_FE[0x9] = pX__FE_9;
	fcnPtr_FE_9[0x0] = p1_8a4;
	fcnPtr_FE_9[0x1] = p1_8a4;
	fcnPtr_FE_9[0x2] = p1_8a4;
	fcnPtr_FE_9[0x3] = p1_8a4;
	fcnPtr_FE_9[0x4] = p1_8a4;
	fcnPtr_FE_9[0x5] = p1_8a4;
	fcnPtr_FE_9[0x6] = p1_8a4;
	fcnPtr_FE_9[0x7] = p1_8a4;
	fcnPtr_FE_9[0x8] = p1_8a4;
	fcnPtr_FE_9[0x9] = p1_8a4;
	fcnPtr_FE_9[0xa] = p1_8a4;
	fcnPtr_FE_9[0xb] = p1_8a4;
	fcnPtr_FE_9[0xc] = p1_8a4;
	fcnPtr_FE_9[0xd] = p1_8a4;
	fcnPtr_FE_9[0xe] = p1_8a4;
	fcnPtr_FE_9[0xf] = p1_8a4;
	fcnPtr_FE[0xA] = pX__FE_A;
	fcnPtr_FE_A[0x0] = p1_8a4;
	fcnPtr_FE_A[0x1] = p1_8a5;
	fcnPtr_FE_A[0x2] = p1_8a5;
	fcnPtr_FE_A[0x3] = p1_8a5;
	fcnPtr_FE_A[0x4] = p1_8a5;
	fcnPtr_FE_A[0x5] = p1_8a5;
	fcnPtr_FE_A[0x6] = p1_8a5;
	fcnPtr_FE_A[0x7] = p1_8a5;
	fcnPtr_FE_A[0x8] = p1_8a5;
	fcnPtr_FE_A[0x9] = p1_8b1;
	fcnPtr_FE_A[0xa] = p1_8b1;
	fcnPtr_FE_A[0xb] = p1_8b1;
	fcnPtr_FE_A[0xc] = p1_8b1;
	fcnPtr_FE_A[0xd] = p1_8b1;
	fcnPtr_FE_A[0xe] = p1_8b1;
	fcnPtr_FE_A[0xf] = p1_8b1;
	fcnPtr_FE_B[0x0] = p1_8b1;
	fcnPtr_FE_B[0x1] = p1_8b1;
	fcnPtr_FE_B[0x2] = p1_8b1;
	fcnPtr_FE_B[0x3] = p1_8b1;
	fcnPtr_FE_B[0x4] = p1_8b1;
	fcnPtr_FE_B[0x5] = p1_8b2;
	fcnPtr_FE_B[0x6] = p1_8b2;
	fcnPtr_FE_B[0x7] = p1_8b2;
	fcnPtr_FE_B[0x8] = p1_8b2;
	fcnPtr_FE_B[0x9] = p1_8b2;
	fcnPtr_FE_B[0xa] = p1_8b2;
	fcnPtr_FE_B[0xb] = p1_8b2;
	fcnPtr_FE_B[0xc] = p1_8b2;
	fcnPtr_FE_C_0[0xa] = p1_93;
	fcnPtr_FE_C_0[0xb] = p1_93;
	fcnPtr_FE_C_0[0xc] = p1_93;
	fcnPtr_FE_C_0[0xd] = p1_93;
	fcnPtr_FE_C_0[0xe] = p1_93;
	fcnPtr_FE_C_0[0xf] = p1_93;
	fcnPtr_FE_C_1[0x0] = p1_93;
	fcnPtr_FE_C_1[0x1] = p1_93;
	fcnPtr_FE_C_1[0x2] = p1_93;
	fcnPtr_FE_C_1[0x3] = p1_93;
	fcnPtr_FE_C_1[0x4] = p1_93;
	fcnPtr_FE_C_1[0x5] = p1_93;
	fcnPtr_FE_C_1[0x6] = p1_94;
	fcnPtr_FE_C_1[0x7] = p1_94;
	fcnPtr_FE_C_1[0x8] = p1_94;
	fcnPtr_FE_C_1[0x9] = p1_94;
	fcnPtr_FE_C_1[0xa] = p1_94;
	fcnPtr_FE_C_1[0xb] = p1_94;
	fcnPtr_FE_C_1[0xc] = p1_94;
	fcnPtr_FE_C_1[0xd] = p1_94;
	fcnPtr_FE_C_3[0x8] = p1_102;
	fcnPtr_FE_C_3[0x9] = p1_102;
	fcnPtr_FE_C_3[0xa] = p1_102;
	fcnPtr_FE_C_3[0xb] = p1_102;
	fcnPtr_FE_C_3[0xc] = p1_102;
	fcnPtr_FE_C_3[0xd] = p1_102;
	fcnPtr_FE_C_3[0xe] = p1_102;
	fcnPtr_FE_C_3[0xf] = p1_102;
	fcnPtr_FE_C[0x4] = pX__FE_C_4;
	fcnPtr_FE_C_4[0x0] = p1_102;
	fcnPtr_FE_C_4[0x1] = p1_102;
	fcnPtr_FE_C_4[0x2] = p1_102;
	fcnPtr_FE_C_4[0x3] = p1_102;
	fcnPtr_FE_C_4[0x4] = p1_102;
	fcnPtr_FE_C_4[0x5] = p1_102;
	fcnPtr_FE_C_4[0x6] = p1_102;
	fcnPtr_FE_C_4[0x7] = p1_102;
	fcnPtr_FE_C_4[0x8] = p1_102;
	fcnPtr_FE_C_4[0x9] = p1_102;
	fcnPtr_FE_C_4[0xa] = p1_102;
	fcnPtr_FE_C_4[0xb] = p1_102;
	fcnPtr_FE_C_4[0xc] = p1_102;
	fcnPtr_FE_C_4[0xd] = p1_102;
	fcnPtr_FE_C_4[0xe] = p1_102;
	fcnPtr_FE_C_4[0xf] = p1_102;
	fcnPtr_FE_C[0x5] = pX__FE_C_5;
	fcnPtr_FE_C_5[0x0] = p1_102;
	fcnPtr_FE_C_5[0x1] = p1_11;
	fcnPtr_FE_C_5[0x2] = p1_11;
	fcnPtr_FE_C_5[0x3] = p1_11;
	fcnPtr_FE_C_5[0x4] = p1_11;
	fcnPtr_FE_C_5[0x5] = p1_11;
	fcnPtr_FE_C_5[0x6] = p1_11;
	fcnPtr_FE_C_5[0x7] = p1_11;
	fcnPtr_FE_C_5[0x8] = p1_11;
	fcnPtr_FE_C_5[0x9] = p1_11;
	fcnPtr_FE_C_5[0xa] = p1_11;
	fcnPtr_FE_C_5[0xb] = p1_11;
	fcnPtr_FE_C_5[0xc] = p1_11;
	fcnPtr_FE_C_5[0xd] = p1_11;
	fcnPtr_FE_C_5[0xe] = p1_11;
	fcnPtr_FE_C_5[0xf] = p1_11;
	fcnPtr_FE_C[0x6] = pX__FE_C_6;
	fcnPtr_FE_C_6[0x0] = p1_11;
	fcnPtr_FE_C_6[0x1] = p1_11;
	fcnPtr_FE_C_6[0x2] = p1_11;
	fcnPtr_FE_C_6[0x3] = p1_11;
	fcnPtr_FE_C_6[0x4] = pX__FE_C_6_4;
	fcnPtr_FE_C_6_4[0x0] = pX__FE_C_6_4_0;
	fcnPtr_FE_C_6_4_0[0x0] = pX__FE_C_6_4_0_0;
	fcnPtr_FE_C_6_4_0_0[0x0] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0x1] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0x2] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0x3] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0x4] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0x5] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0x6] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0x7] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0x8] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0x9] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0xa] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0xb] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0xc] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0xd] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0xe] = p0_12a;
	fcnPtr_FE_C_6_4_0_0[0xf] = p0_12a;
	fcnPtr_FE_C_6_4_0[0x1] = pX__FE_C_6_4_0_1;
	fcnPtr_FE_C_6_4_0_1[0x0] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0x1] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0x2] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0x3] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0x4] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0x5] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0x6] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0x7] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0x8] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0x9] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0xa] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0xb] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0xc] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0xd] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0xe] = p0_12a;
	fcnPtr_FE_C_6_4_0_1[0xf] = p0_12a;
	fcnPtr[0xFF] = pX__FF;
	fcnPtr_FF[0xF] = pX__FF_F;
	fcnPtr_FF_F[0xF] = pX__FF_F_F;
	fcnPtr_FF_F_F[0xF] = pX__FF_F_F_F;
	fcnPtr_FF_F_F_F[0xF] = pX__FF_F_F_F_F;
	fcnPtr_FF_F_F_F_F[0xF] = pX__FF_F_F_F_F_F;
	fcnPtr_FF_F_F_F_F_F[0xe] = p0_12b;
	fcnPtr_FF_F_F_F_F_F[0xf] = p0_12c;
}

int
print_insn_mk (bfd_vma pc, disassemble_info * info)
{
    int32_t tgt = 0;
    int r = -1;
    unsigned char data[4];
  unsigned int words_read = 0;
  unsigned int words_to_read = 4;

  if (!is_init) {
    init_inst();
    init_ptr();
    is_init = 1;
  }

  info->bytes_per_line  = 4;
  info->bytes_per_chunk = 2;

  if ((info->section->flags & SEC_DATA) && info->symbol_at_address_func (pc, info)) {
    for (int n = 0; n < info->symtab_size; ++n) {
      if (pc == bfd_asymbol_value (info->symtab[n])) {
        if (bfd_get_flavour (((struct objdump_disasm_info *) info->application_data)->abfd) == bfd_target_elf_flavour) {
            Elf_Internal_Sym s = ((elf_symbol_type *) info->symtab[n])->internal_elf_sym;
            if(s.st_size < 2 && (s.st_info & 0xF) == 1) { // 1 == STT_OBJECT
                words_to_read = 2;
            }
        } else {
          // we have no idea about the size, so set it to minimal
          words_to_read = 2;
        }
      }
    }
  }

  r = info->read_memory_func (pc, data, words_to_read, info);
  words_read = words_to_read;

  if (r != 0) {
    words_read = 2;

    if ((r = info->read_memory_func (pc, data, 2, info)) != 0) {
        info->memory_error_func(r, pc, info);
        //abort ();
        return -1;
    }
  }

  if (words_read == 4) {
    tgt |= (uint32_t)data[0] << 24;
    tgt |= (uint32_t)data[1] << 16;
    tgt |= (uint32_t)data[2] <<  8;
    tgt |= (uint32_t)data[3] <<  0;
  } else {
    tgt |= (uint32_t)data[0] <<  8;
    tgt |= (uint32_t)data[1] <<  0;
  }

  // only treat data as data if input is elf -> hack to make binary input, which is in a .data section..., be treated as code
  if (info->section->flags & SEC_DATA && bfd_get_flavour (((struct objdump_disasm_info *) info->application_data)->abfd) == bfd_target_elf_flavour) {
    if (words_read == 4) {
        info->fprintf_func (info->stream, "dw 0x%x, 0x%x", data[0] << 8 | data[1], data[2] << 8 | data[3]);
    } else {
        info->fprintf_func (info->stream, "dw 0x%x", data[0] << 8 | data[1]);
    }
  } else {
    fcnPtr[data[0]](tgt, pc, info);
  }

  return words_read;
}


