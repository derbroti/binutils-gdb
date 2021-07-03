# name: MVE vabs and vneg instructions
# as: -march=armv8.1-m.main+mve.fp
# objdump: -dr --prefix-addresses --show-raw-insn -marmv8.1-m.main

.*: +file format .*arm.*

Disassembly of section .text:
[^>]*> ffb1 0340 	vabs.s8	q0, q0
[^>]*> ffb1 0342 	vabs.s8	q0, q1
[^>]*> ffb1 0344 	vabs.s8	q0, q2
[^>]*> ffb1 0348 	vabs.s8	q0, q4
[^>]*> ffb1 034e 	vabs.s8	q0, q7
[^>]*> ffb1 2340 	vabs.s8	q1, q0
[^>]*> ffb1 2342 	vabs.s8	q1, q1
[^>]*> ffb1 2344 	vabs.s8	q1, q2
[^>]*> ffb1 2348 	vabs.s8	q1, q4
[^>]*> ffb1 234e 	vabs.s8	q1, q7
[^>]*> ffb1 4340 	vabs.s8	q2, q0
[^>]*> ffb1 4342 	vabs.s8	q2, q1
[^>]*> ffb1 4344 	vabs.s8	q2, q2
[^>]*> ffb1 4348 	vabs.s8	q2, q4
[^>]*> ffb1 434e 	vabs.s8	q2, q7
[^>]*> ffb1 8340 	vabs.s8	q4, q0
[^>]*> ffb1 8342 	vabs.s8	q4, q1
[^>]*> ffb1 8344 	vabs.s8	q4, q2
[^>]*> ffb1 8348 	vabs.s8	q4, q4
[^>]*> ffb1 834e 	vabs.s8	q4, q7
[^>]*> ffb1 e340 	vabs.s8	q7, q0
[^>]*> ffb1 e342 	vabs.s8	q7, q1
[^>]*> ffb1 e344 	vabs.s8	q7, q2
[^>]*> ffb1 e348 	vabs.s8	q7, q4
[^>]*> ffb1 e34e 	vabs.s8	q7, q7
[^>]*> ffb5 0340 	vabs.s16	q0, q0
[^>]*> ffb5 0342 	vabs.s16	q0, q1
[^>]*> ffb5 0344 	vabs.s16	q0, q2
[^>]*> ffb5 0348 	vabs.s16	q0, q4
[^>]*> ffb5 034e 	vabs.s16	q0, q7
[^>]*> ffb5 2340 	vabs.s16	q1, q0
[^>]*> ffb5 2342 	vabs.s16	q1, q1
[^>]*> ffb5 2344 	vabs.s16	q1, q2
[^>]*> ffb5 2348 	vabs.s16	q1, q4
[^>]*> ffb5 234e 	vabs.s16	q1, q7
[^>]*> ffb5 4340 	vabs.s16	q2, q0
[^>]*> ffb5 4342 	vabs.s16	q2, q1
[^>]*> ffb5 4344 	vabs.s16	q2, q2
[^>]*> ffb5 4348 	vabs.s16	q2, q4
[^>]*> ffb5 434e 	vabs.s16	q2, q7
[^>]*> ffb5 8340 	vabs.s16	q4, q0
[^>]*> ffb5 8342 	vabs.s16	q4, q1
[^>]*> ffb5 8344 	vabs.s16	q4, q2
[^>]*> ffb5 8348 	vabs.s16	q4, q4
[^>]*> ffb5 834e 	vabs.s16	q4, q7
[^>]*> ffb5 e340 	vabs.s16	q7, q0
[^>]*> ffb5 e342 	vabs.s16	q7, q1
[^>]*> ffb5 e344 	vabs.s16	q7, q2
[^>]*> ffb5 e348 	vabs.s16	q7, q4
[^>]*> ffb5 e34e 	vabs.s16	q7, q7
[^>]*> ffb9 0340 	vabs.s32	q0, q0
[^>]*> ffb9 0342 	vabs.s32	q0, q1
[^>]*> ffb9 0344 	vabs.s32	q0, q2
[^>]*> ffb9 0348 	vabs.s32	q0, q4
[^>]*> ffb9 034e 	vabs.s32	q0, q7
[^>]*> ffb9 2340 	vabs.s32	q1, q0
[^>]*> ffb9 2342 	vabs.s32	q1, q1
[^>]*> ffb9 2344 	vabs.s32	q1, q2
[^>]*> ffb9 2348 	vabs.s32	q1, q4
[^>]*> ffb9 234e 	vabs.s32	q1, q7
[^>]*> ffb9 4340 	vabs.s32	q2, q0
[^>]*> ffb9 4342 	vabs.s32	q2, q1
[^>]*> ffb9 4344 	vabs.s32	q2, q2
[^>]*> ffb9 4348 	vabs.s32	q2, q4
[^>]*> ffb9 434e 	vabs.s32	q2, q7
[^>]*> ffb9 8340 	vabs.s32	q4, q0
[^>]*> ffb9 8342 	vabs.s32	q4, q1
[^>]*> ffb9 8344 	vabs.s32	q4, q2
[^>]*> ffb9 8348 	vabs.s32	q4, q4
[^>]*> ffb9 834e 	vabs.s32	q4, q7
[^>]*> ffb9 e340 	vabs.s32	q7, q0
[^>]*> ffb9 e342 	vabs.s32	q7, q1
[^>]*> ffb9 e344 	vabs.s32	q7, q2
[^>]*> ffb9 e348 	vabs.s32	q7, q4
[^>]*> ffb9 e34e 	vabs.s32	q7, q7
[^>]*> ffb5 0740 	vabs.f16	q0, q0
[^>]*> ffb5 0742 	vabs.f16	q0, q1
[^>]*> ffb5 0744 	vabs.f16	q0, q2
[^>]*> ffb5 0748 	vabs.f16	q0, q4
[^>]*> ffb5 074e 	vabs.f16	q0, q7
[^>]*> ffb5 2740 	vabs.f16	q1, q0
[^>]*> ffb5 2742 	vabs.f16	q1, q1
[^>]*> ffb5 2744 	vabs.f16	q1, q2
[^>]*> ffb5 2748 	vabs.f16	q1, q4
[^>]*> ffb5 274e 	vabs.f16	q1, q7
[^>]*> ffb5 4740 	vabs.f16	q2, q0
[^>]*> ffb5 4742 	vabs.f16	q2, q1
[^>]*> ffb5 4744 	vabs.f16	q2, q2
[^>]*> ffb5 4748 	vabs.f16	q2, q4
[^>]*> ffb5 474e 	vabs.f16	q2, q7
[^>]*> ffb5 8740 	vabs.f16	q4, q0
[^>]*> ffb5 8742 	vabs.f16	q4, q1
[^>]*> ffb5 8744 	vabs.f16	q4, q2
[^>]*> ffb5 8748 	vabs.f16	q4, q4
[^>]*> ffb5 874e 	vabs.f16	q4, q7
[^>]*> ffb5 e740 	vabs.f16	q7, q0
[^>]*> ffb5 e742 	vabs.f16	q7, q1
[^>]*> ffb5 e744 	vabs.f16	q7, q2
[^>]*> ffb5 e748 	vabs.f16	q7, q4
[^>]*> ffb5 e74e 	vabs.f16	q7, q7
[^>]*> ffb9 0740 	vabs.f32	q0, q0
[^>]*> ffb9 0742 	vabs.f32	q0, q1
[^>]*> ffb9 0744 	vabs.f32	q0, q2
[^>]*> ffb9 0748 	vabs.f32	q0, q4
[^>]*> ffb9 074e 	vabs.f32	q0, q7
[^>]*> ffb9 2740 	vabs.f32	q1, q0
[^>]*> ffb9 2742 	vabs.f32	q1, q1
[^>]*> ffb9 2744 	vabs.f32	q1, q2
[^>]*> ffb9 2748 	vabs.f32	q1, q4
[^>]*> ffb9 274e 	vabs.f32	q1, q7
[^>]*> ffb9 4740 	vabs.f32	q2, q0
[^>]*> ffb9 4742 	vabs.f32	q2, q1
[^>]*> ffb9 4744 	vabs.f32	q2, q2
[^>]*> ffb9 4748 	vabs.f32	q2, q4
[^>]*> ffb9 474e 	vabs.f32	q2, q7
[^>]*> ffb9 8740 	vabs.f32	q4, q0
[^>]*> ffb9 8742 	vabs.f32	q4, q1
[^>]*> ffb9 8744 	vabs.f32	q4, q2
[^>]*> ffb9 8748 	vabs.f32	q4, q4
[^>]*> ffb9 874e 	vabs.f32	q4, q7
[^>]*> ffb9 e740 	vabs.f32	q7, q0
[^>]*> ffb9 e742 	vabs.f32	q7, q1
[^>]*> ffb9 e744 	vabs.f32	q7, q2
[^>]*> ffb9 e748 	vabs.f32	q7, q4
[^>]*> ffb9 e74e 	vabs.f32	q7, q7
[^>]*> fe31 cf4d 	vpstte
[^>]*> ffb1 0342 	vabst.s8	q0, q1
[^>]*> ffb5 2348 	vabst.s16	q1, q4
[^>]*> ffb9 434a 	vabse.s32	q2, q5
[^>]*> fe71 8f4d 	vpste
[^>]*> ffb5 0748 	vabst.f16	q0, q4
[^>]*> ffb9 e74a 	vabse.f32	q7, q5
[^>]*> ffb1 03c0 	vneg.s8	q0, q0
[^>]*> ffb1 03c2 	vneg.s8	q0, q1
[^>]*> ffb1 03c4 	vneg.s8	q0, q2
[^>]*> ffb1 03c8 	vneg.s8	q0, q4
[^>]*> ffb1 03ce 	vneg.s8	q0, q7
[^>]*> ffb1 23c0 	vneg.s8	q1, q0
[^>]*> ffb1 23c2 	vneg.s8	q1, q1
[^>]*> ffb1 23c4 	vneg.s8	q1, q2
[^>]*> ffb1 23c8 	vneg.s8	q1, q4
[^>]*> ffb1 23ce 	vneg.s8	q1, q7
[^>]*> ffb1 43c0 	vneg.s8	q2, q0
[^>]*> ffb1 43c2 	vneg.s8	q2, q1
[^>]*> ffb1 43c4 	vneg.s8	q2, q2
[^>]*> ffb1 43c8 	vneg.s8	q2, q4
[^>]*> ffb1 43ce 	vneg.s8	q2, q7
[^>]*> ffb1 83c0 	vneg.s8	q4, q0
[^>]*> ffb1 83c2 	vneg.s8	q4, q1
[^>]*> ffb1 83c4 	vneg.s8	q4, q2
[^>]*> ffb1 83c8 	vneg.s8	q4, q4
[^>]*> ffb1 83ce 	vneg.s8	q4, q7
[^>]*> ffb1 e3c0 	vneg.s8	q7, q0
[^>]*> ffb1 e3c2 	vneg.s8	q7, q1
[^>]*> ffb1 e3c4 	vneg.s8	q7, q2
[^>]*> ffb1 e3c8 	vneg.s8	q7, q4
[^>]*> ffb1 e3ce 	vneg.s8	q7, q7
[^>]*> ffb5 03c0 	vneg.s16	q0, q0
[^>]*> ffb5 03c2 	vneg.s16	q0, q1
[^>]*> ffb5 03c4 	vneg.s16	q0, q2
[^>]*> ffb5 03c8 	vneg.s16	q0, q4
[^>]*> ffb5 03ce 	vneg.s16	q0, q7
[^>]*> ffb5 23c0 	vneg.s16	q1, q0
[^>]*> ffb5 23c2 	vneg.s16	q1, q1
[^>]*> ffb5 23c4 	vneg.s16	q1, q2
[^>]*> ffb5 23c8 	vneg.s16	q1, q4
[^>]*> ffb5 23ce 	vneg.s16	q1, q7
[^>]*> ffb5 43c0 	vneg.s16	q2, q0
[^>]*> ffb5 43c2 	vneg.s16	q2, q1
[^>]*> ffb5 43c4 	vneg.s16	q2, q2
[^>]*> ffb5 43c8 	vneg.s16	q2, q4
[^>]*> ffb5 43ce 	vneg.s16	q2, q7
[^>]*> ffb5 83c0 	vneg.s16	q4, q0
[^>]*> ffb5 83c2 	vneg.s16	q4, q1
[^>]*> ffb5 83c4 	vneg.s16	q4, q2
[^>]*> ffb5 83c8 	vneg.s16	q4, q4
[^>]*> ffb5 83ce 	vneg.s16	q4, q7
[^>]*> ffb5 e3c0 	vneg.s16	q7, q0
[^>]*> ffb5 e3c2 	vneg.s16	q7, q1
[^>]*> ffb5 e3c4 	vneg.s16	q7, q2
[^>]*> ffb5 e3c8 	vneg.s16	q7, q4
[^>]*> ffb5 e3ce 	vneg.s16	q7, q7
[^>]*> ffb9 03c0 	vneg.s32	q0, q0
[^>]*> ffb9 03c2 	vneg.s32	q0, q1
[^>]*> ffb9 03c4 	vneg.s32	q0, q2
[^>]*> ffb9 03c8 	vneg.s32	q0, q4
[^>]*> ffb9 03ce 	vneg.s32	q0, q7
[^>]*> ffb9 23c0 	vneg.s32	q1, q0
[^>]*> ffb9 23c2 	vneg.s32	q1, q1
[^>]*> ffb9 23c4 	vneg.s32	q1, q2
[^>]*> ffb9 23c8 	vneg.s32	q1, q4
[^>]*> ffb9 23ce 	vneg.s32	q1, q7
[^>]*> ffb9 43c0 	vneg.s32	q2, q0
[^>]*> ffb9 43c2 	vneg.s32	q2, q1
[^>]*> ffb9 43c4 	vneg.s32	q2, q2
[^>]*> ffb9 43c8 	vneg.s32	q2, q4
[^>]*> ffb9 43ce 	vneg.s32	q2, q7
[^>]*> ffb9 83c0 	vneg.s32	q4, q0
[^>]*> ffb9 83c2 	vneg.s32	q4, q1
[^>]*> ffb9 83c4 	vneg.s32	q4, q2
[^>]*> ffb9 83c8 	vneg.s32	q4, q4
[^>]*> ffb9 83ce 	vneg.s32	q4, q7
[^>]*> ffb9 e3c0 	vneg.s32	q7, q0
[^>]*> ffb9 e3c2 	vneg.s32	q7, q1
[^>]*> ffb9 e3c4 	vneg.s32	q7, q2
[^>]*> ffb9 e3c8 	vneg.s32	q7, q4
[^>]*> ffb9 e3ce 	vneg.s32	q7, q7
[^>]*> ffb5 07c0 	vneg.f16	q0, q0
[^>]*> ffb5 07c2 	vneg.f16	q0, q1
[^>]*> ffb5 07c4 	vneg.f16	q0, q2
[^>]*> ffb5 07c8 	vneg.f16	q0, q4
[^>]*> ffb5 07ce 	vneg.f16	q0, q7
[^>]*> ffb5 27c0 	vneg.f16	q1, q0
[^>]*> ffb5 27c2 	vneg.f16	q1, q1
[^>]*> ffb5 27c4 	vneg.f16	q1, q2
[^>]*> ffb5 27c8 	vneg.f16	q1, q4
[^>]*> ffb5 27ce 	vneg.f16	q1, q7
[^>]*> ffb5 47c0 	vneg.f16	q2, q0
[^>]*> ffb5 47c2 	vneg.f16	q2, q1
[^>]*> ffb5 47c4 	vneg.f16	q2, q2
[^>]*> ffb5 47c8 	vneg.f16	q2, q4
[^>]*> ffb5 47ce 	vneg.f16	q2, q7
[^>]*> ffb5 87c0 	vneg.f16	q4, q0
[^>]*> ffb5 87c2 	vneg.f16	q4, q1
[^>]*> ffb5 87c4 	vneg.f16	q4, q2
[^>]*> ffb5 87c8 	vneg.f16	q4, q4
[^>]*> ffb5 87ce 	vneg.f16	q4, q7
[^>]*> ffb5 e7c0 	vneg.f16	q7, q0
[^>]*> ffb5 e7c2 	vneg.f16	q7, q1
[^>]*> ffb5 e7c4 	vneg.f16	q7, q2
[^>]*> ffb5 e7c8 	vneg.f16	q7, q4
[^>]*> ffb5 e7ce 	vneg.f16	q7, q7
[^>]*> ffb9 07c0 	vneg.f32	q0, q0
[^>]*> ffb9 07c2 	vneg.f32	q0, q1
[^>]*> ffb9 07c4 	vneg.f32	q0, q2
[^>]*> ffb9 07c8 	vneg.f32	q0, q4
[^>]*> ffb9 07ce 	vneg.f32	q0, q7
[^>]*> ffb9 27c0 	vneg.f32	q1, q0
[^>]*> ffb9 27c2 	vneg.f32	q1, q1
[^>]*> ffb9 27c4 	vneg.f32	q1, q2
[^>]*> ffb9 27c8 	vneg.f32	q1, q4
[^>]*> ffb9 27ce 	vneg.f32	q1, q7
[^>]*> ffb9 47c0 	vneg.f32	q2, q0
[^>]*> ffb9 47c2 	vneg.f32	q2, q1
[^>]*> ffb9 47c4 	vneg.f32	q2, q2
[^>]*> ffb9 47c8 	vneg.f32	q2, q4
[^>]*> ffb9 47ce 	vneg.f32	q2, q7
[^>]*> ffb9 87c0 	vneg.f32	q4, q0
[^>]*> ffb9 87c2 	vneg.f32	q4, q1
[^>]*> ffb9 87c4 	vneg.f32	q4, q2
[^>]*> ffb9 87c8 	vneg.f32	q4, q4
[^>]*> ffb9 87ce 	vneg.f32	q4, q7
[^>]*> ffb9 e7c0 	vneg.f32	q7, q0
[^>]*> ffb9 e7c2 	vneg.f32	q7, q1
[^>]*> ffb9 e7c4 	vneg.f32	q7, q2
[^>]*> ffb9 e7c8 	vneg.f32	q7, q4
[^>]*> ffb9 e7ce 	vneg.f32	q7, q7
[^>]*> fe71 4f4d 	vpstee
[^>]*> ffb1 03c2 	vnegt.s8	q0, q1
[^>]*> ffb5 23cc 	vnege.s16	q1, q6
[^>]*> ffb9 43ca 	vnege.s32	q2, q5
[^>]*> fe71 8f4d 	vpste
[^>]*> ffb5 27c8 	vnegt.f16	q1, q4
[^>]*> ffb9 e7ca 	vnege.f32	q7, q5
