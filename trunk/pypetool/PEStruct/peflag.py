#!/usr/bin/env python
#-*- coding=utf-8 -*-

IMAGE_SUBSYSTEM_DICT = {
    0x00:'Unknown',
    0x01:'Native',
    0x02:'Windows GUI',
    0x03:'Windows CUI',
    0x05:'OS2 CUI',
    0x07:'POSIX CUI',
    0x09:'WinCE GUI',
    0x0A:'EFI Application',
    0x0B:'EFI Boot Service Driver',
    0x0C:'EFI Runtime Driver',
    0x0D:'EFI ROM',
    0x0E:'XBox',
    0x10:'Windows Boot Application'
    }

IMAGE_MACHINE_DICT = {
    0x0000:'Unknown',
    0x014C:'Intel386',
    0x0162:'MIPS(R2000,R3000)',
    0x0166:'MIPS(R4000)',
    0x0168:'MIPS(R10000)',
    0x0169:'MIPS WCE v2',
    0x0184:'DEC Alpha AXP',
    0x01A2:'Hitachi SH-3',
    0x01A3:'Hitachi SH-3E',
    0x01A4:'Hitachi SH-3DSP',
    0x01A6:'Hitachi SH-4',
    0x01C0:'ARM',
    0x01C2:'Thumb',
    0x01F0:'IBM PowerPC',
    0x0200:'Intel 64',
    0x0266:'MIPS 16',
    0x0284:'Alpha 64/AXP 64',
    0x0366:'MIPS FPU',
    0x0466:'MIPS FPU 16',
    0x0520:'Tricore',
    0x0EBC:'EBC'
    0x8664:'AMD 64',
    0x9041:'M32R',
    0xC0EE:'CEE'
    }