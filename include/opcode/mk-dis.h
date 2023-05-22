//TODO symbol prints for everything with literals!!

//[('opcode', 32)]
static inline void p0_12a_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s", p0_inst_12a[((mne) & 0xFF) - p0_12a_OFFSET]);
}
//[('opcode', 32)]
static inline void p0_12b_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s", p0_inst_12b[((mne) & 0xFF) - p0_12b_OFFSET]);
}
//[('opcode', 32)]
static inline void p0_12c_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "impl-%s", p0_inst_12c[((mne) & 0xFF) - p0_12c_OFFSET]);
}
//[('opcode', 8), ('literalA', 8), ('regC', 4), ('regD', 4), ('literalB', 8)]
static inline void p1_0f2_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s 0x%x:%s + %s + 0x%x", p1_inst_0f2[((mne >> 24) & 0xFF) - p1_0f2_OFFSET],
                                                             (mne >> 16) & 0xff,
                                                             registers[(mne >> 12) & 0xf],
                                                             registers[(mne >> 8) & 0xf],
                                                             mne & 0xff);
}
//[('opcode', 8), ('literalA', 8), ('regC', 4), ('regD', 4), ('literalB', 8)]
static inline void p1_0f3_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (0x%x : %s + %s + 0x%x)", p1_inst_0f3[((mne >> 24) & 0xff) - p1_0f3_OFFSET],
                                                                 (mne >> 16) & 0xff,
                                                                 registers[(mne >> 12) & 0xf],
                                                                 registers[(mne >>  8) & 0xf],
                                                                 (mne >>  0) & 0xff);
}
//[('opcode', 8), ('literalA', 24)]
static inline void p1_0g2_exec(uint32_t mne, bfd_vma pc, disassemble_info * info) {
  // jmp with L24 is techincally a 25 bit jump -> sign bit is bit 25 after shifting
  int32_t lit = (mne & 0xffffff) << 1;
  if (1 & (lit >> 24)) { // test if sign bit is set at 25 (shifted by one)
    lit |= 0xFE000000;   // expand to 32 bit
  }
 info->fprintf_func (info->stream, "%s %d # <0x%x>", p1_inst_0g2[((mne >> 24) & 0xff) - p1_0g2_OFFSET], lit, pc + ((mne & 0xFFFFFF) << 1));
 print_symbol(pc, lit, info);
}
//[('opcode', 8), ('literalA', 24)]
static inline void p1_0g3_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (0x%x)", p1_inst_0g3[((mne >> 24) & 0xff) - p1_0g3_OFFSET], mne & 0xffffff);
}
//[('opcode', 9), ('literalA', 23)] //width=8
static inline void p1_1_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
  uint32_t lit_addr = (mne << 1) & 0xFFFFFF;
  info->fprintf_func (info->stream, "%s 0x%x", p1_inst_1[((((mne >> 23) & 0x1F) << 3) - p1_1_OFFSET) >> 3], lit_addr);
  print_symbol(0, lit_addr, info);
}
//[('opcode', 20), ('z', 2), ('aE', 1), ('aF', 1), ('regE', 4), ('regF', 4)]
static inline void p1_102_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s : %s", p1_inst_102[((mne >> 12) & 0xFF) - p1_102_OFFSET],
                                                 registers[((mne >> 4) & 0xF) | ((mne >> 9) & 1) << 4],
                                                 registers[((mne >> 0) & 0xF) | ((mne >> 8) & 1) << 4]);
}
//[('opcode', 20), ('z', 3), ('aF', 1), ('z', 4), ('regF', 4)]
static inline void p1_11_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s", p1_inst_11[((mne >> 12) & 0xff) - p1_11_OFFSET],
                                            registers[((mne >> 0) & 0xF) | ((mne >> 8) & 1) << 4]);
}
//[('opcode', 12), ('regB', 4), ('literalA', 16)]
static inline void p1_7a2_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s 0x%x + %s", p1_inst_7a2[((mne >> 20) & 0xFF) - p1_7a2_OFFSET], mne & 0xffff, registers[(mne >> 16) & 0xf]);
}
//[('opcode', 12), ('regB', 4), ('literalA', 16)]
static inline void p1_7a3_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (0x%x + %s)", p1_inst_7a3[((mne >> 20) & 0xFF) - p1_7a3_OFFSET], mne & 0xffff, registers[(mne >> 16) & 0xf]);
}
//[('opcode', 12), ('regB', 4), ('regC', 4), ('regD', 4), ('literalA', 8)]
static inline void p1_7c3_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s : %s + %s + 0x%x", p1_inst_7c3[((mne >> 20) & 0xFF) - p1_7c3_OFFSET],
                                                             registers[(mne >> 16) & 0xf],
                                                             registers[(mne >> 12) & 0xf],
                                                             registers[(mne >> 8) & 0xf],
                                                             mne & 0xFF);
}
//[('opcode', 12), ('regB', 4), ('regC', 4), ('regD', 4), ('literalA', 8)]
static inline void p1_7c4_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s 0x%x : %s + %s + %s", p1_inst_7c4[((mne >> 20) & 0xFF) - p1_7c4_OFFSET],
                                                             mne & 0xFF,
                                                             registers[(mne >> 16) & 0xf],
                                                             registers[(mne >> 12) & 0xf],
                                                             registers[(mne >> 8) & 0xf]);
}
//[('opcode', 12), ('regB', 4), ('regC', 4), ('regD', 4), ('literalA', 8)]
static inline void p1_7c5_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (%s : %s + %s + 0x%x)", p1_inst_7c5[((mne >> 20) & 0xFF) - p1_7c5_OFFSET],
                                                               registers[(mne >> 16) & 0xf],
                                                               registers[(mne >> 12) & 0xf],
                                                               registers[(mne >> 8) & 0xf],
                                                               mne & 0xFF);
}
//[('opcode', 12), ('regB', 4), ('regC', 4), ('regD', 4), ('literalA', 8)]
static inline void p1_7c6_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (0x%x : %s + %s + %s)", p1_inst_7c6[((mne >> 20) & 0xFF) - p1_7c6_OFFSET],
                                                               mne & 0xFF,
                                                               registers[(mne >> 16) & 0xf],
                                                               registers[(mne >> 12) & 0xf],
                                                               registers[(mne >> 8) & 0xf]);
}
//[('opcode', 16), ('regC', 4), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p1_8a4_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s : %s + %s + %s", p1_inst_8a4[((mne >> 16) & 0xFF) - p1_8a4_OFFSET],
                                                           registers[(mne >> 12) & 0xf],
                                                           registers[(mne >> 8) & 0xf],
                                                           registers[(mne >> 4) & 0xf],
                                                           registers[(mne >> 0) & 0xf]);
}
//[('opcode', 16), ('regC', 4), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p1_8a5_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (%s : %s + %s + %s)", p1_inst_8a5[((mne >> 16) & 0xFF) - p1_8a5_OFFSET],
                                                             registers[(mne >> 12) & 0xf],
                                                             registers[(mne >> 8) & 0xf],
                                                             registers[(mne >> 4) & 0xf],
                                                             registers[(mne >> 0) & 0xf]);
}
//[('opcode', 16), ('regC', 4), ('regD', 4), ('literalA', 8)]
static inline void p1_8b1_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s : %s + %s + 0x%x", p1_inst_8b1[((mne >> 16) & 0xFF) - p1_8b1_OFFSET],
                                                          registers[(mne >> 12) & 0xf],
                                                          registers[(mne >> 8) & 0xf],
                                                          mne & 0xFF);
}
//[('opcode', 16), ('regC', 4), ('regD', 4), ('literalA', 8)]
static inline void p1_8b2_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s ( : %s + %s + 0x%x )", p1_inst_8b2[((mne >> 16) & 0xFF) - p1_8b2_OFFSET],
                                                              registers[(mne >> 12) & 0xf],
                                                              registers[(mne >> 8) & 0xf],
                                                              mne & 0xFF);
}
//[('opcode', 20), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p1_93_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s : %s + %s + %s", p1_inst_93[((mne >> 12) & 0xFF) - p1_93_OFFSET],
                                                        registers[(mne >> 8) & 0xf],
                                                        registers[(mne >> 4) & 0xf],
                                                        registers[(mne >> 0) & 0xf]);
}
//[('opcode', 20), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p1_94_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s ( : %s + %s + %s )", p1_inst_94[((mne >> 12) & 0xFF) - p1_94_OFFSET],
                                                            registers[(mne >> 8) & 0xf],
                                                            registers[(mne >> 4) & 0xf],
                                                            registers[(mne >> 0) & 0xf]);
}
//[('opcode', 8), ('regA', 4), ('regB', 4), ('regC', 4), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p2_0a1_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (%s : %s + %s), (%s : %s + %s)", p2_inst_0a1[((mne >> 24) & 0xFF) - p2_0a1_OFFSET],
                                                                        registers[(mne >> 20) & 0xf],
                                                                        registers[(mne >> 16) & 0xf],
                                                                        registers[(mne >> 12) & 0xf],
                                                                        registers[(mne >> 8) & 0xf],
                                                                        registers[(mne >> 4) & 0xf],
                                                                        registers[(mne >> 0) & 0xf]);
}
//[('opcode', 8), ('regA', 4), ('regB', 4), ('regC', 4), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p2_0a2_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s ( : %s + %s + %s), ( : %s + %s + %s )", p2_inst_0a2[((mne >> 24) & 0xFF) - p2_0a2_OFFSET],
                                                                               registers[(mne >> 20) & 0xf],
                                                                               registers[(mne >> 16) & 0xf],
                                                                               registers[(mne >> 12) & 0xf],
                                                                               registers[(mne >> 8) & 0xf],
                                                                               registers[(mne >> 4) & 0xf],
                                                                               registers[(mne >> 0) & 0xf]);
}
//[('opcode', 8), ('regA', 4), ('regB', 4), ('regC', 4), ('regD', 4), ('literalA', 8)]
static inline void p2_0b1_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (%s : %s + %s + 0x%x), %s", p2_inst_0b1[((mne >> 24) & 0xFF) - p2_0b1_OFFSET],
                                                                   registers[(mne >> 20) & 0xf],
                                                                   registers[(mne >> 16) & 0xf],
                                                                   registers[(mne >> 12) & 0xf],
                                                                   mne & 0xff,
                                                                   registers[(mne >> 8) & 0xf]);
}
//[('opcode', 8), ('regA', 4), ('regB', 4), ('regC', 4), ('regD', 4), ('literalA', 8)]
static inline void p2_0b2_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s, (%s : %s + %s + 0x%x)", p2_inst_0b2[((mne >> 24) & 0xFF) - p2_0b2_OFFSET],
                                                                   registers[(mne >> 20) & 0xf],
                                                                   registers[(mne >> 16) & 0xf],
                                                                   registers[(mne >> 12) & 0xf],
                                                                   registers[(mne >> 8) & 0xf], mne & 0xff);
}
//[('opcode', 8), ('regA', 4), ('regB', 4), ('regC', 4), ('regD', 4), ('literalA', 8)]
static inline void p2_0b3_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (0x%x : %s + %s + %s), %s", p2_inst_0b3[((mne >> 24) & 0xFF) - p2_0b3_OFFSET],
                                                                   mne & 0xff,
                                                                   registers[(mne >> 20) & 0xf],
                                                                   registers[(mne >> 16) & 0xf],
                                                                   registers[(mne >> 12) & 0xf],
                                                                   registers[(mne >> 8) & 0xf]);
}
//[('opcode', 8), ('regA', 4), ('regB', 4), ('regC', 4), ('regD', 4), ('literalA', 8)]
static inline void p2_0b4_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s  %s, (0x%x : %s + %s + %s)", p2_inst_0b4[((mne >> 24) & 0xFF) - p2_0b4_OFFSET],
                                                                    registers[(mne >> 20) & 0xf],
                                                                    mne & 0xff,
                                                                    registers[(mne >> 16) & 0xf],
                                                                    registers[(mne >> 12) & 0xf],
                                                                    registers[(mne >> 8) & 0xf]);
}
//[('opcode', 8), ('regA', 4), ('regB', 4), ('regC', 4), ('literalA', 12)]
static inline void p2_0c1_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
  int16_t lit = mne & 0xfff;
  if (0x8 & (lit >> 8))
      lit |= 0xF000;
 info->fprintf_func (info->stream, "%s (%d + %s + %s), %s", p2_inst_0c1[((mne >> 24) & 0xFF) - p2_0c1_OFFSET],
                                                            lit,
                                                            registers[(mne >> 20) & 0xf],
                                                            registers[(mne >> 16) & 0xf],
                                                            registers[(mne >> 12) & 0xf]);
}
//[('opcode', 8), ('regA', 4), ('regB', 4), ('regC', 4), ('literalA', 12)]
static inline void p2_0c2_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
  int16_t lit = mne & 0xfff;
  if (0x8 & (lit >> 8))
      lit |= 0xF000;
 info->fprintf_func (info->stream, "%s %s, (%d + %s + %s)", p2_inst_0c2[((mne >> 24) & 0xFF) - p2_0c2_OFFSET],
                                                            registers[(mne >> 20) & 0xf],
                                                            lit,
                                                            registers[(mne >> 16) & 0xf],
                                                            registers[(mne >> 12) & 0xf]);
}
//[('opcode', 8), ('regA', 4), ('regB', 4), ('literalA', 16)]
static inline void p2_0d1_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (%s : %s), 0x%x", p2_inst_0d1[((mne >> 24) & 0xFF) - p2_0d1_OFFSET],
                                                         registers[(mne >> 20) & 0xf],
                                                         registers[(mne >> 16) & 0xf],
                                                         mne & 0xffff);
}
//[('opcode', 8), ('regA', 4), ('regB', 4), ('literalA', 16)]
static inline void p2_0d2_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (0x%x + %s), %s", p2_inst_0d2[((mne >> 24) & 0xFF) - p2_0d2_OFFSET],
                                                         mne & 0xffff,
                                                         registers[(mne >> 20) & 0xf],
                                                         registers[(mne >> 16) & 0xf]);
}
//[('opcode', 8), ('regA', 4), ('regB', 4), ('literalA', 16)]
static inline void p2_0d3_exec(uint32_t mne, bfd_vma pc, disassemble_info * info) {
 int16_t lit_addr = mne & 0xffff;
 info->fprintf_func (info->stream, "%s %s, (%d + %s)", p2_inst_0d3[((mne >> 24) & 0xFF) - p2_0d3_OFFSET],
                                                       registers[(mne >> 20) & 0xf],
                                                       lit_addr,
                                                       registers[(mne >> 16) & 0xf]);
 print_symbol(pc, lit_addr, info);
}
//[('opcode', 8), ('literalA', 8), ('literalB', 16)]
static inline void p2_0e_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (%%x5 : 0x%x), 0x%x", p2_inst_0e[((mne >> 24) & 0xFF) - p2_0e_OFFSET], (mne >> 16) & 0xff, mne & 0xffff);
}
//[('opcode', 8), ('literalA', 8), ('regC', 4), ('regD', 4), ('literalB', 8)]
static inline void p2_0f1_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (0x%x : %s), (0x%x : %s)", p2_inst_0f1[((mne >> 24) & 0xFF) - p2_0f1_OFFSET],
                                                                  (mne >> 16) & 0xFF,
                                                                  registers[(mne >> 12) & 0xF],
                                                                  (mne >> 0) & 0xFF,
                                                                  registers[(mne >> 8) & 0xF]);
}
//[('opcode', 8), ('literalA', 24)]
static inline void p2_0g1_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
  uint32_t lit_addr = mne & 0xFFFFFF;
  info->fprintf_func (info->stream, "%s %%r13, 0x%x", p2_inst_0g1[((mne >> 24) & 0xFF) - p2_0g1_OFFSET], lit_addr);
  print_symbol(0, lit_addr, info);
}
//[('opcode', 20), ('z', 2), ('aE', 1), ('aF', 1), ('regE', 4), ('regF', 4)]
static inline void p2_101_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s, %s", p2_inst_101[((mne >> 12) & 0xFF) - p2_101_OFFSET],
                                                registers[((mne >> 4) & 0xF) | ((mne >> 9) & 1) << 4],
                                                registers[((mne >> 0) & 0xF) | ((mne >> 8) & 1) << 4]);
}
//[('opcode', 16), ('regC', 4), ('z', 1), ('aC', 1), ('aE', 1), ('aF', 1), ('regE', 4), ('regF', 4)]
static inline void p2_131_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s, (%s : %s)", p2_inst_131[((mne >> 16) & 0xFF) - p2_131_OFFSET],
                                                       registers[((mne >> 12) & 0xF) | ((mne >> 10) & 1) << 4],
                                                       registers[ ((mne >> 4) & 0xF) | ((mne >> 9) & 1) << 4 ],
                                                       registers[((mne) & 0xF) | ((mne >> 8) & 1) << 4]);
}
//[('opcode', 16), ('regC', 4), ('z', 1), ('aC', 1), ('aE', 1), ('aF', 1), ('regE', 4), ('regF', 4)]
static inline void p2_132_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (%s : %s), %s", p2_inst_132[((mne >> 16) & 0xFF) - p2_132_OFFSET],
                                                       registers[((mne >> 12) & 0xF) | ((mne >> 10) & 1) << 4],
                                                       registers[ ((mne >> 4) & 0xF) | ((mne >> 9) & 1) << 4 ],
                                                       registers[((mne) & 0xF) | ((mne >> 8) & 1) << 4]);
}
//[('opcode', 12), ('literalA', 4), ('regC', 4), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p2_2a_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (%s : %s + %s + %s), 0x%x", p2_inst_2a[((mne >> 20) & 0xFF) - p2_2a_OFFSET],
                                                                   registers[(mne >> 12) & 0xf],
                                                                   registers[(mne >> 8) & 0xf],
                                                                   registers[(mne >> 4) & 0xf],
                                                                   registers[(mne >> 0) & 0xf],
                                                                   (mne >> 16) & 0xF);
}
//[('opcode', 12), ('literalB', 4), ('regC', 4), ('regD', 4), ('literalA', 8)]
static inline void p2_2b_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (0x%x : %s + %s), 0x%x", p2_inst_2b[((mne >> 20) & 0xFF) - p2_2b_OFFSET],
                                                                (mne >> 0) & 0xFF,
                                                                registers[(mne >> 12) & 0xf],
                                                                registers[(mne >> 8) & 0xf],
                                                                (mne >> 16) & 0xF);
}
//[('opcode', 12), ('literalA', 4), ('opB', 4), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p2_3_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s ( : %s + %s + %s), 0x%x", p2_inst_3[((mne >> 12) & 0xF) - p2_3_OFFSET],
                                                                 registers[(mne >> 8) & 0xF],
                                                                 registers[(mne >> 4) & 0xF],
                                                                 registers[(mne >> 0) & 0xF],
                                                                 (mne >> 16) & 0xF);
}
//[('opcode', 12), ('literalB', 4), ('opB', 8), ('literalA', 8)]
static inline void p2_4_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 uint32_t lit_addr = mne & 0xFF;
 info->fprintf_func (info->stream, "%s (%%x5 : 0x%x), 0x%x", p2_inst_4[((mne >> 8) & 0xFF) - p2_4_OFFSET], lit_addr, (mne >> 16) & 0xF);
}
//[('opcode', 12), ('literalA', 4), ('opB', 8), ('z', 3), ('aF', 1), ('regF', 4)]
static inline void p2_5_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s, 0x%x", p2_inst_5[((mne >> 8) & 0xFF) - p2_5_OFFSET],
                                                  registers[((mne >> 0) & 0x1F)],
                                                  (mne >> 16) & 0xf);
}
//[('opcode', 11), ('aB', 1), ('regB', 4), ('literalA', 16)] //width=2
static inline void p2_6_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s, 0x%x", p2_inst_6[((((mne >> 21) & 0x7F) << 1) - p2_6_OFFSET) >> 1],
                                                  registers[(mne >> 16) & 0x1f],
                                                  mne & 0xffff);
}
//[('opcode', 12), ('regB', 4), ('literalA', 16)]
static inline void p2_7a1_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s ( : %s ), 0x%x", p2_inst_7a1[((mne >> 20) & 0xFF) - p2_7a1_OFFSET],
                                                        registers[(mne >> 16) & 0xf],
                                                        mne & 0xffff);
}
//[('opcode', 12), ('regB', 4), ('regC', 4), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p2_7b1_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s (%s : %s + %s + %s), %s", p2_inst_7b1[((mne >> 20) & 0xFF) - p2_7b1_OFFSET],
                                                                 registers[(mne >> 16) & 0xf],
                                                                 registers[(mne >> 12) & 0xf],
                                                                 registers[(mne >> 8) & 0xf],
                                                                 registers[(mne >> 4) & 0xf],
                                                                 registers[(mne >> 0) & 0xf]);
}
//[('opcode', 12), ('regB', 4), ('regC', 4), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p2_7b2_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s, (%s : %s + %s + %s)", p2_inst_7b2[((mne >> 20) & 0xFF) - p2_7b2_OFFSET],
                                                                 registers[(mne >> 16) & 0xf],
                                                                 registers[(mne >> 12) & 0xf],
                                                                 registers[(mne >> 8) & 0xf],
                                                                 registers[(mne >> 4) & 0xf],
                                                                 registers[(mne >> 0) & 0xf]);
}
//[('opcode', 12), ('regB', 4), ('regC', 4), ('regD', 4), ('literalA', 8)]
static inline void p2_7c1_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s ( : %s + %s + 0x%x), %s", p2_inst_7c1[((mne >> 20) & 0xFF) - p2_7c1_OFFSET],
                                                                 registers[(mne >> 16) & 0xf],
                                                                 registers[(mne >> 12) & 0xf],
                                                                 (mne >> 0) & 0xFF,
                                                                 registers[(mne >> 8) & 0xf]);
}
//[('opcode', 12), ('regB', 4), ('regC', 4), ('regD', 4), ('literalA', 8)]
static inline void p2_7c2_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s, ( : %s + %s + 0x%x)", p2_inst_7c2[((mne >> 20) & 0xFF) - p2_7c2_OFFSET],
                                                                 registers[(mne >> 16) & 0xf],
                                                                 registers[(mne >> 12) & 0xf],
                                                                 registers[(mne >> 8) & 0xf],
                                                                 (mne >> 0) & 0xFF);
}
//[('opcode', 16), ('regC', 4), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p2_8a1_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s ( : %s + %s + %s), %s", p2_inst_8a1[((mne >> 16) & 0xFF) - p2_8a1_OFFSET],
                                                               registers[(mne >> 12) & 0xf],
                                                               registers[(mne >> 8) & 0xf],
                                                               registers[(mne >> 4) & 0xf],
                                                               registers[(mne >> 0) & 0xf]);
}
//[('opcode', 16), ('regC', 4), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p2_8a2_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s, ( : %s + %s + %s)", p2_inst_8a2[((mne >> 16) & 0xFF) - p2_8a2_OFFSET],
                                                               registers[(mne >> 12) & 0xf],
                                                               registers[(mne >> 8) & 0xf],
                                                               registers[(mne >> 4) & 0xf],
                                                               registers[(mne >> 0) & 0xf]);
}
//[('opcode', 16), ('regC', 4), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p2_8a3_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s : %s, %s, %s", p2_inst_8a3[((mne >> 16) & 0xFF) - p2_8a3_OFFSET],
                                                         registers[(mne >> 12) & 0xf],
                                                         registers[(mne >> 8) & 0xf],
                                                         registers[(mne >> 4) & 0xf],
                                                         registers[(mne >> 0) & 0xf]);
}
//[('opcode', 20), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p2_91_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s, %s, %s", p2_inst_91[((mne >> 12) & 0xFF) - p2_91_OFFSET],
                                                    registers[(mne >> 8) & 0xf],
                                                    registers[(mne >> 4) & 0xf],
                                                    registers[(mne >> 0) & 0xf]);
}
//[('opcode', 20), ('regD', 4), ('regE', 4), ('regF', 4)]
static inline void p2_92_exec(uint32_t mne, bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info * info) {
 info->fprintf_func (info->stream, "%s %s : %s, %s", p2_inst_92[((mne >> 12) & 0xFF) - p2_92_OFFSET],
                                                     registers[(mne >> 8) & 0xf],
                                                     registers[(mne >> 4) & 0xf],
                                                     registers[(mne >> 0) & 0xf]);
}
