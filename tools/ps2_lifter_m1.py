#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ps2_lifter_m1.py — Milestone 1 Static Lifter Front-End for PlayStation 2 (R5900 / ELF32-MIPS)
=============================================================================================
Deliverable for Milestone 1 (Scope C — Homebrew ELF Static Lifter):
1. ELF32 Little-Endian MIPS Reader:
   - Parses ELF32 header, Program Headers, Section Headers, Symbol Table (.symtab/.strtab),
     and Relocation sections (.rel.text).
2. R5900 Disassembler for Explicitly Declared Instruction Families:
   - Family 1: ALU_REG      (32/64-bit register arithmetic, logic, shifts, mult/div, conditional moves)
   - Family 2: ALU_IMM      (32/64-bit immediate arithmetic & logic, LUI)
   - Family 3: LOAD_STORE   (Standard scalar 8/16/32/64-bit loads and stores)
   - Family 4: BRANCH_JUMP  (J, JAL, JR, JALR, conditional branches & branch-likely)
   - Family 5: SYSTEM       (SYSCALL, BREAK, conditional traps)
   - Zero Silent Skipping Rule: Every 32-bit word in .text outside the 5 declared families
     is recorded and reported as UNDECODED with its exact virtual address, raw 32-bit hex
     encoding, enclosing function, and architectural classification reason.
3. Static Call Graph & PS2 EE BIOS Syscall Surface Analyzer:
   - Extracts STT_FUNC symbols, builds static JAL/J call graph, and tracks $v1 ($3)
     assignments feeding SYSCALL instructions against the PS2 EE BIOS syscall table.
"""

import argparse
from collections import Counter
from dataclasses import dataclass, asdict
import hashlib
import json
import os
import struct
import sys
from typing import Dict, List, Optional, Tuple


# =============================================================================
# 1. Constants & Official PS2 EE Architecture Tables
# =============================================================================

GPR_NAMES: List[str] = [
    "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
    "$t0",   "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0",   "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8",   "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
]

# Declared Instruction Families covered in Milestone 1
DECLARED_FAMILIES: Dict[str, str] = {
    "ALU_REG":     "حسابيات ومنطق وإزاحات السجلات (32/64-bit Register ALU, Shifts, Mult/Div, Cond Move)",
    "ALU_IMM":     "حسابيات ومنطق الفوريات (32/64-bit Immediate ALU & LUI)",
    "LOAD_STORE":  "التحميل والتخزين القياسي (Scalar 8/16/32/64-bit Loads & Stores)",
    "BRANCH_JUMP": "القفزات والفروع الشرطية (J, JAL, JR, JALR, Conditional Branches)",
    "SYSTEM":      "نداءات النظام والفخاخ (SYSCALL, BREAK, Traps)",
}

# Official PS2 EE BIOS Syscall Table (from pcsx2/R5900OpcodeImpl.cpp:90-145 & ps2tek)
PS2_EE_SYSCALLS: Dict[int, Tuple[str, str]] = {
    0x00: ("RFU000_FullReset", "إعادة ضبط كاملة لمعالج EE"),
    0x01: ("ResetEE", "إعادة ضبط وحدات EE الفرعية (DMAC/VU/VIF/GIF/IPU)"),
    0x02: ("SetGsCrt", "تهيئة أبعاد وتوقيت عرض شريحة GS (PCRTC)"),
    0x04: ("Exit", "إنهاء البرنامج والعودة إلى متصفح النظام OSDSYS"),
    0x06: ("LoadExecPS2", "تحميل وتنفيذ ملف ELF جديد"),
    0x07: ("ExecPS2", "مسح حالة النواة وبدء خيط رئيسي عند نقطة دخول جديدة"),
    0x10: ("AddIntcHandler", "تسجيل معالج مقاطعة INTC"),
    0x11: ("RemoveIntcHandler", "إزالة معالج مقاطعة INTC"),
    0x12: ("AddDmacHandler", "تسجيل معالج مقاطعة DMAC"),
    0x13: ("RemoveDmacHandler", "إزالة معالج مقاطعة DMAC"),
    0x14: ("_EnableIntc", "تفعيل قناع مقاطعة INTC"),
    0x15: ("_DisableIntc", "تعطيل قناع مقاطعة INTC"),
    0x16: ("_EnableDmac", "تفعيل قناع مقاطعة DMAC"),
    0x17: ("_DisableDmac", "تعطيل قناع مقاطعة DMAC"),
    0x20: ("CreateThread", "إنشاء خيط تنفيذ جديد في حالة سبات (DORMANT)"),
    0x21: ("DeleteThread", "حذف خيط تنفيذ"),
    0x22: ("StartThread", "بدء تشغيل خيط تنفيذ"),
    0x23: ("ExitThread", "إنهاء الخيط الحالي وإعادته لحالة DORMANT"),
    0x24: ("ExitDeleteThread", "إنهاء وحذف الخيط الحالي"),
    0x25: ("TerminateThread", "إيقاف خيط محدد قسرياً"),
    0x2F: ("GetThreadId", "استرجاع معرّف الخيط الحالي"),
    0x32: ("SleepThread", "وضع الخيط الحالي في حالة انتظار (WAIT)"),
    0x33: ("WakeupThread", "إيقاظ خيط نائم"),
    0x3C: ("SetupThread / RFU060 (InitMainThread)", "تهيئة مكدس الخيط الرئيسي ($sp) ومؤشر $gp قبل main"),
    0x3D: ("SetupHeap / RFU061 (InitHeap)", "تهيئة كومة الذاكرة (Heap) للخيط الرئيسي"),
    0x3E: ("EndOfHeap", "استرجاع عنوان نهاية الكومة"),
    0x40: ("CreateSema", "إنشاء سيمافور تزامن"),
    0x41: ("DeleteSema", "حذف سيمافور"),
    0x42: ("SignalSema", "إطلاق إشارة سيمافور"),
    0x44: ("WaitSema", "انتظار سيمافور"),
    0x64: ("FlushCache", "تفريغ أو إبطال مخبأ البيانات/التعليمات (0=Data Writeback, 2=ICache)"),
    0x68: ("iFlushCache", "تفريغ المخبأ من سياق المقاطعة"),
    0x70: ("GsGetIMR", "قراءة سجل قناع مقاطعات GS_IMR"),
    0x71: ("GsPutIMR", "كتابة سجل قناع مقاطعات GS_IMR"),
    0x73: ("SetVSyncFlag", "تعيين مؤشرات راية التزامن الرأسي VSync"),
    0x74: ("SetSyscall / RFU116", "تعديل جدول نداءات النظام في النواة"),
    0x75: ("print", "طباعة نصية مباشرة عبر BIOS (SysPrintOut)"),
    0x76: ("sceSifDmaStat", "فحص حالة نقل SIF DMA"),
    0x77: ("sceSifSetDma", "جدولة وبدء نقل SIF1 DMA نحو معالج IOP"),
    0x78: ("sceSifSetDChain", "تفعيل وضع السلسلة لقناة SIF0 DMA"),
    0x7C: ("Deci2Call", "واجهة التصحيح والطباعة النصية عبر بروتوكول DECI2 (subcall 0x10 = print)"),
    0x7F: ("GetMemorySize", "إرجاع حجم ذاكرة RDRAM بالبايت (32MB)"),
}

SH_TYPE_NAMES: Dict[int, str] = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    10: "SHLIB",
    11: "DYNSYM",
    0x70000006: "MIPS_REGINFO",
}

PH_TYPE_NAMES: Dict[int, str] = {
    0: "NULL",
    1: "LOAD",
    2: "DYNAMIC",
    3: "INTERP",
    4: "NOTE",
    6: "PHDR",
    0x70000000: "MIPS_REGINFO",
}

STT_NAMES: Dict[int, str] = {
    0: "NOTYPE",
    1: "OBJECT",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
}

STB_NAMES: Dict[int, str] = {
    0: "LOCAL",
    1: "GLOBAL",
    2: "WEAK",
}

MIPS_REL_NAMES: Dict[int, str] = {
    0: "R_MIPS_NONE",
    1: "R_MIPS_16",
    2: "R_MIPS_32",
    3: "R_MIPS_REL32",
    4: "R_MIPS_26",
    5: "R_MIPS_HI16",
    6: "R_MIPS_LO16",
    7: "R_MIPS_GPREL16",
    8: "R_MIPS_LITERAL",
    9: "R_MIPS_GOT16",
    10: "R_MIPS_PC16",
    11: "R_MIPS_CALL16",
    12: "R_MIPS_GPREL32",
}


# =============================================================================
# 2. Data Structures
# =============================================================================

@dataclass
class ElfHeaderInfo:
    magic: str
    ei_class: str
    ei_data: str
    e_type: int
    e_type_str: str
    e_machine: int
    e_machine_str: str
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int


@dataclass
class ProgramHeaderInfo:
    index: int
    p_type: int
    p_type_str: str
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_flags: int
    p_flags_str: str
    p_align: int


@dataclass
class SectionHeaderInfo:
    index: int
    name: str
    sh_name: int
    sh_type: int
    sh_type_str: str
    sh_flags: int
    sh_flags_str: str
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int


@dataclass
class SymbolInfo:
    index: int
    name: str
    st_value: int
    st_size: int
    bind: str
    sym_type: str
    st_other: int
    st_shndx: int
    shndx_str: str


@dataclass
class RelocationInfo:
    section_name: str
    r_offset: int
    r_info: int
    r_type: int
    r_type_str: str
    sym_index: int
    sym_name: str
    sym_value: int


@dataclass
class DecodedInstruction:
    vaddr: int
    file_offset: int
    raw_word: int
    enclosing_func: str
    decoded: bool
    family: str
    mnemonic: str
    operands: str
    comment: str
    undecoded_reason: str = ""
    branch_target: Optional[int] = None
    call_target: Optional[int] = None


# =============================================================================
# 3. ELF32-MIPS Parser (ELF32Reader)
# =============================================================================

class ELF32Reader:
    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.file_size = len(self.data)
        self.sha256 = hashlib.sha256(self.data).hexdigest()

        self.header = self._parse_elf_header()
        self.program_headers = self._parse_program_headers()
        self.section_headers = self._parse_section_headers()
        self.symbols = self._parse_symbols()
        self.relocations = self._parse_relocations()

    def _read_cstring(self, table: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(table):
            return ""
        end = table.find(b"\x00", offset)
        if end == -1:
            end = len(table)
        return table[offset:end].decode("ascii", errors="replace")

    def _parse_elf_header(self) -> ElfHeaderInfo:
        if len(self.data) < 52:
            raise ValueError("File is smaller than 52-byte ELF32 header.")
        (
            e_ident,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = struct.unpack("<16sHHIIIIIHHHHHH", self.data[:52])

        if e_ident[:4] != b"\x7fELF":
            raise ValueError("Invalid ELF magic bytes.")
        if e_ident[4] != 1:
            raise ValueError(f"Unsupported ELF class {e_ident[4]} (expected ELFCLASS32=1).")
        if e_ident[5] != 1:
            raise ValueError(f"Unsupported ELF endianness {e_ident[5]} (expected ELFDATA2LSB=1).")

        type_map = {0: "NONE", 1: "REL (Relocatable)", 2: "EXEC (Executable file)", 3: "DYN", 4: "CORE"}
        mach_map = {8: "MIPS R3000 / R5900 (EM_MIPS = 8)"}

        return ElfHeaderInfo(
            magic=" ".join(f"{b:02x}" for b in e_ident),
            ei_class="ELF32",
            ei_data="2's complement, little endian",
            e_type=e_type,
            e_type_str=type_map.get(e_type, f"UNKNOWN({e_type})"),
            e_machine=e_machine,
            e_machine_str=mach_map.get(e_machine, f"UNKNOWN({e_machine})"),
            e_version=e_version,
            e_entry=e_entry,
            e_phoff=e_phoff,
            e_shoff=e_shoff,
            e_flags=e_flags,
            e_ehsize=e_ehsize,
            e_phentsize=e_phentsize,
            e_phnum=e_phnum,
            e_shentsize=e_shentsize,
            e_shnum=e_shnum,
            e_shstrndx=e_shstrndx,
        )

    def _parse_program_headers(self) -> List[ProgramHeaderInfo]:
        phdrs: List[ProgramHeaderInfo] = []
        for i in range(self.header.e_phnum):
            off = self.header.e_phoff + i * self.header.e_phentsize
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(
                "<IIIIIIII", self.data[off : off + 32]
            )
            flg = "".join([
                "R" if (p_flags & 4) else " ",
                "W" if (p_flags & 2) else " ",
                "E" if (p_flags & 1) else " ",
            ])
            phdrs.append(
                ProgramHeaderInfo(
                    index=i,
                    p_type=p_type,
                    p_type_str=PH_TYPE_NAMES.get(p_type, f"0x{p_type:08x}"),
                    p_offset=p_offset,
                    p_vaddr=p_vaddr,
                    p_paddr=p_paddr,
                    p_filesz=p_filesz,
                    p_memsz=p_memsz,
                    p_flags=p_flags,
                    p_flags_str=flg,
                    p_align=p_align,
                )
            )
        return phdrs

    def _parse_section_headers(self) -> List[SectionHeaderInfo]:
        raw_shdrs = []
        for i in range(self.header.e_shnum):
            off = self.header.e_shoff + i * self.header.e_shentsize
            fields = struct.unpack("<IIIIIIIIII", self.data[off : off + 40])
            raw_shdrs.append(fields)

        shstrtab_bytes = b""
        if 0 <= self.header.e_shstrndx < len(raw_shdrs):
            _, _, _, _, sh_off, sh_sz, _, _, _, _ = raw_shdrs[self.header.e_shstrndx]
            shstrtab_bytes = self.data[sh_off : sh_off + sh_sz]

        shdrs: List[SectionHeaderInfo] = []
        for i, fields in enumerate(raw_shdrs):
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = fields
            name = self._read_cstring(shstrtab_bytes, sh_name)
            flag_chars = []
            if sh_flags & 0x1:
                flag_chars.append("W")
            if sh_flags & 0x2:
                flag_chars.append("A")
            if sh_flags & 0x4:
                flag_chars.append("X")
            if sh_flags & 0x40:
                flag_chars.append("I")
            shdrs.append(
                SectionHeaderInfo(
                    index=i,
                    name=name,
                    sh_name=sh_name,
                    sh_type=sh_type,
                    sh_type_str=SH_TYPE_NAMES.get(sh_type, f"0x{sh_type:08x}"),
                    sh_flags=sh_flags,
                    sh_flags_str="".join(flag_chars),
                    sh_addr=sh_addr,
                    sh_offset=sh_offset,
                    sh_size=sh_size,
                    sh_link=sh_link,
                    sh_info=sh_info,
                    sh_addralign=sh_addralign,
                    sh_entsize=sh_entsize,
                )
            )
        return shdrs

    def _parse_symbols(self) -> List[SymbolInfo]:
        syms: List[SymbolInfo] = []
        for sh in self.section_headers:
            if sh.sh_type != 2:  # SHT_SYMTAB
                continue
            strtab_sh = self.section_headers[sh.sh_link]
            strtab_bytes = self.data[strtab_sh.sh_offset : strtab_sh.sh_offset + strtab_sh.sh_size]
            num_syms = sh.sh_size // (sh.sh_entsize or 16)
            for idx in range(num_syms):
                off = sh.sh_offset + idx * 16
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack(
                    "<IIIBBH", self.data[off : off + 16]
                )
                bind = STB_NAMES.get(st_info >> 4, f"STB_{st_info >> 4}")
                stype = STT_NAMES.get(st_info & 0xF, f"STT_{st_info & 0xF}")
                name = self._read_cstring(strtab_bytes, st_name)
                if st_shndx == 0:
                    shndx_str = "UND"
                elif st_shndx == 0xFFF1:
                    shndx_str = "ABS"
                elif st_shndx == 0xFFF2:
                    shndx_str = "COM"
                else:
                    shndx_str = str(st_shndx)
                syms.append(
                    SymbolInfo(
                        index=idx,
                        name=name,
                        st_value=st_value,
                        st_size=st_size,
                        bind=bind,
                        sym_type=stype,
                        st_other=st_other,
                        st_shndx=st_shndx,
                        shndx_str=shndx_str,
                    )
                )
        return syms

    def _parse_relocations(self) -> List[RelocationInfo]:
        rels: List[RelocationInfo] = []
        for sh in self.section_headers:
            if sh.sh_type == 9:  # SHT_REL
                num_entries = sh.sh_size // (sh.sh_entsize or 8)
                for idx in range(num_entries):
                    off = sh.sh_offset + idx * 8
                    r_offset, r_info = struct.unpack("<II", self.data[off : off + 8])
                    sym_idx = r_info >> 8
                    r_type = r_info & 0xFF
                    sym_name = ""
                    sym_val = 0
                    if 0 <= sym_idx < len(self.symbols):
                        sym = self.symbols[sym_idx]
                        sym_name = sym.name or (
                            self.section_headers[sym.st_shndx].name
                            if 0 < sym.st_shndx < len(self.section_headers)
                            else ""
                        )
                        sym_val = sym.st_value
                    rels.append(
                        RelocationInfo(
                            section_name=sh.name,
                            r_offset=r_offset,
                            r_info=r_info,
                            r_type=r_type,
                            r_type_str=MIPS_REL_NAMES.get(r_type, f"R_MIPS_{r_type}"),
                            sym_index=sym_idx,
                            sym_name=sym_name,
                            sym_value=sym_val,
                        )
                    )
        return rels

    def get_section_by_name(self, name: str) -> Optional[SectionHeaderInfo]:
        for sh in self.section_headers:
            if sh.name == name:
                return sh
        return None


# =============================================================================
# 4. R5900 Disassembler for Explicitly Declared Families (R5900Decoder)
# =============================================================================

class R5900Decoder:
    """
    Decodes MIPS III / R5900 instructions belonging to the 5 declared families:
    ALU_REG, ALU_IMM, LOAD_STORE, BRANCH_JUMP, SYSTEM.
    Every instruction word outside these families is explicitly flagged as UNDECODED.
    """

    def __init__(self, func_map: Dict[int, str], addr_to_func: Dict[int, str]):
        self.func_map = func_map          # exact entry vaddr -> func name
        self.addr_to_func = addr_to_func  # any vaddr inside function -> func name

    @staticmethod
    def sign_ext16(val: int) -> int:
        return val - 0x10000 if (val & 0x8000) else val

    def decode_word(self, vaddr: int, file_offset: int, word: int) -> DecodedInstruction:
        op    = (word >> 26) & 0x3F
        rs    = (word >> 21) & 0x1F
        rt    = (word >> 16) & 0x1F
        rd    = (word >> 11) & 0x1F
        sa    = (word >> 6)  & 0x1F
        funct = word & 0x3F
        imm   = word & 0xFFFF
        simm  = self.sign_ext16(imm)
        jidx  = word & 0x03FFFFFF

        enclosing = self.addr_to_func.get(vaddr, "<unknown>")

        # ---------------------------------------------------------------------
        # Opcode 0x00: SPECIAL Table
        # ---------------------------------------------------------------------
        if op == 0x00:
            if word == 0x00000000:
                return DecodedInstruction(
                    vaddr, file_offset, word, enclosing, True,
                    "ALU_REG", "nop", "", "sll $zero, $zero, 0"
                )
            # Shifts with immediate sa
            if funct in (0x00, 0x02, 0x03, 0x38, 0x3A, 0x3B, 0x3C, 0x3E, 0x3F) and rs == 0:
                mnem = {
                    0x00: "sll", 0x02: "srl", 0x03: "sra",
                    0x38: "dsll", 0x3A: "dsrl", 0x3B: "dsra",
                    0x3C: "dsll32", 0x3E: "dsrl32", 0x3F: "dsra32",
                }[funct]
                return DecodedInstruction(
                    vaddr, file_offset, word, enclosing, True,
                    "ALU_REG", mnem, f"{GPR_NAMES[rd]}, {GPR_NAMES[rt]}, {sa}", ""
                )
            # Variable shifts
            if funct in (0x04, 0x06, 0x07, 0x14, 0x16, 0x17) and sa == 0:
                mnem = {
                    0x04: "sllv", 0x06: "srlv", 0x07: "srav",
                    0x14: "dsllv", 0x16: "dsrlv", 0x17: "dsrav",
                }[funct]
                return DecodedInstruction(
                    vaddr, file_offset, word, enclosing, True,
                    "ALU_REG", mnem, f"{GPR_NAMES[rd]}, {GPR_NAMES[rt]}, {GPR_NAMES[rs]}", ""
                )
            # JR / JALR
            if funct == 0x08 and rt == 0 and rd == 0:
                return DecodedInstruction(
                    vaddr, file_offset, word, enclosing, True,
                    "BRANCH_JUMP", "jr", f"{GPR_NAMES[rs]}", "Jump Register"
                )
            if funct == 0x09 and rt == 0:
                return DecodedInstruction(
                    vaddr, file_offset, word, enclosing, True,
                    "BRANCH_JUMP", "jalr", f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}", "Jump and Link Register"
                )
            # Conditional Moves MOVZ / MOVN
            if funct in (0x0A, 0x0B) and sa == 0:
                mnem = "movz" if funct == 0x0A else "movn"
                return DecodedInstruction(
                    vaddr, file_offset, word, enclosing, True,
                    "ALU_REG", mnem, f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}", ""
                )
            # SYSCALL / BREAK
            if funct == 0x0C:
                code = (word >> 6) & 0xFFFFF
                op_str = f"0x{code:x}" if code else ""
                return DecodedInstruction(
                    vaddr, file_offset, word, enclosing, True,
                    "SYSTEM", "syscall", op_str, "EE BIOS System Call"
                )
            if funct == 0x0D:
                code = (word >> 6) & 0xFFFFF
                return DecodedInstruction(
                    vaddr, file_offset, word, enclosing, True,
                    "SYSTEM", "break", f"0x{code:x}", "Breakpoint Exception"
                )
            # HI/LO Moves
            if funct in (0x10, 0x12) and rs == 0 and rt == 0 and sa == 0:
                mnem = "mfhi" if funct == 0x10 else "mflo"
                return DecodedInstruction(
                    vaddr, file_offset, word, enclosing, True,
                    "ALU_REG", mnem, f"{GPR_NAMES[rd]}", ""
                )
            if funct in (0x11, 0x13) and rt == 0 and rd == 0 and sa == 0:
                mnem = "mthi" if funct == 0x11 else "mtlo"
                return DecodedInstruction(
                    vaddr, file_offset, word, enclosing, True,
                    "ALU_REG", mnem, f"{GPR_NAMES[rs]}", ""
                )
            # Multiply / Divide
            if funct in (0x18, 0x19, 0x1A, 0x1B) and sa == 0:
                mnem = {0x18: "mult", 0x19: "multu", 0x1A: "div", 0x1B: "divu"}[funct]
                if rd == 0:
                    ops = f"{GPR_NAMES[rs]}, {GPR_NAMES[rt]}"
                else:
                    ops = f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}"
                return DecodedInstruction(
                    vaddr, file_offset, word, enclosing, True,
                    "ALU_REG", mnem, ops, ""
                )
            # 3-operand Register ALU
            if funct in (0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F) and sa == 0:
                mnem = {
                    0x20: "add",  0x21: "addu",  0x22: "sub",  0x23: "subu",
                    0x24: "and",  0x25: "or",    0x26: "xor",  0x27: "nor",
                    0x2A: "slt",  0x2B: "sltu",  0x2C: "dadd", 0x2D: "daddu",
                    0x2E: "dsub", 0x2F: "dsubu",
                }[funct]
                return DecodedInstruction(
                    vaddr, file_offset, word, enclosing, True,
                    "ALU_REG", mnem, f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}", ""
                )
            # Traps
            if funct in (0x30, 0x31, 0x32, 0x33, 0x34, 0x36):
                mnem = {0x30: "tge", 0x31: "tgeu", 0x32: "tlt", 0x33: "tltu", 0x34: "teq", 0x36: "tne"}[funct]
                return DecodedInstruction(
                    vaddr, file_offset, word, enclosing, True,
                    "SYSTEM", mnem, f"{GPR_NAMES[rs]}, {GPR_NAMES[rt]}", ""
                )
            # Anything else in SPECIAL (e.g. funct=0x0F SYNC.L/SYNC.P, funct=0x28 MFSA, funct=0x29 MTSA)
            if funct == 0x0F:
                reason = "MEMORY_BARRIER_SYNC (R5900 SPECIAL funct=0x0f: sync.l / sync.p خارج العائلات الخمس المعلنة)"
            elif funct in (0x28, 0x29):
                reason = f"R5900_SA_REG (SPECIAL funct=0x{funct:02x}: mfsa/mtsa)"
            else:
                reason = f"SPECIAL_UNCOVERED (op=0x00, funct=0x{funct:02x})"
            return DecodedInstruction(
                vaddr, file_offset, word, enclosing, False,
                "UNDECODED", "UNDECODED", f"0x{word:08x}", "", reason
            )

        # ---------------------------------------------------------------------
        # Opcode 0x01: REGIMM Branches
        # ---------------------------------------------------------------------
        if op == 0x01:
            regimm_branches = {
                0x00: "bltz",   0x01: "bgez",   0x02: "bltzl",   0x03: "bgezl",
                0x10: "bltzal", 0x11: "bgezal", 0x12: "bltzall", 0x13: "bgezall",
            }
            if rt in regimm_branches:
                mnem = regimm_branches[rt]
                target = (vaddr + 4 + (simm << 2)) & 0xFFFFFFFF
                return DecodedInstruction(
                    vaddr, file_offset, word, enclosing, True,
                    "BRANCH_JUMP", mnem, f"{GPR_NAMES[rs]}, 0x{target:08x}",
                    f"offset={simm:+d} insns", branch_target=target
                )
            reason = f"REGIMM_UNCOVERED (op=0x01, rt=0x{rt:02x} مثلاً mtsab/mtsah أو trap immediate)"
            return DecodedInstruction(
                vaddr, file_offset, word, enclosing, False,
                "UNDECODED", "UNDECODED", f"0x{word:08x}", "", reason
            )

        # ---------------------------------------------------------------------
        # Opcode 0x02, 0x03: J / JAL
        # ---------------------------------------------------------------------
        if op in (0x02, 0x03):
            mnem = "j" if op == 0x02 else "jal"
            target = ((vaddr + 4) & 0xF0000000) | (jidx << 2)
            sym_label = self.func_map.get(target, "")
            comment = f"-> {sym_label}" if sym_label else ""
            return DecodedInstruction(
                vaddr, file_offset, word, enclosing, True,
                "BRANCH_JUMP", mnem, f"0x{target:08x}", comment,
                branch_target=target if op == 0x02 else None,
                call_target=target,
            )

        # ---------------------------------------------------------------------
        # Conditional Branches (BEQ, BNE, BLEZ, BGTZ, BEQL, BNEL, BLEZL, BGTZL)
        # ---------------------------------------------------------------------
        if op in (0x04, 0x05, 0x14, 0x15):
            mnem = {0x04: "beq", 0x05: "bne", 0x14: "beql", 0x15: "bnel"}[op]
            target = (vaddr + 4 + (simm << 2)) & 0xFFFFFFFF
            return DecodedInstruction(
                vaddr, file_offset, word, enclosing, True,
                "BRANCH_JUMP", mnem, f"{GPR_NAMES[rs]}, {GPR_NAMES[rt]}, 0x{target:08x}",
                f"offset={simm:+d} insns", branch_target=target
            )
        if op in (0x06, 0x07, 0x16, 0x17) and rt == 0:
            mnem = {0x06: "blez", 0x07: "bgtz", 0x16: "blezl", 0x17: "bgtzl"}[op]
            target = (vaddr + 4 + (simm << 2)) & 0xFFFFFFFF
            return DecodedInstruction(
                vaddr, file_offset, word, enclosing, True,
                "BRANCH_JUMP", mnem, f"{GPR_NAMES[rs]}, 0x{target:08x}",
                f"offset={simm:+d} insns", branch_target=target
            )

        # ---------------------------------------------------------------------
        # Immediate Arithmetic / Logic (ALU_IMM)
        # ---------------------------------------------------------------------
        if op in (0x08, 0x09, 0x0A, 0x0B, 0x18, 0x19):
            mnem = {
                0x08: "addi", 0x09: "addiu", 0x0A: "slti",
                0x0B: "sltiu", 0x18: "daddi", 0x19: "daddiu",
            }[op]
            return DecodedInstruction(
                vaddr, file_offset, word, enclosing, True,
                "ALU_IMM", mnem, f"{GPR_NAMES[rt]}, {GPR_NAMES[rs]}, {simm}",
                f"0x{imm:04x}"
            )
        if op in (0x0C, 0x0D, 0x0E):
            mnem = {0x0C: "andi", 0x0D: "ori", 0x0E: "xori"}[op]
            return DecodedInstruction(
                vaddr, file_offset, word, enclosing, True,
                "ALU_IMM", mnem, f"{GPR_NAMES[rt]}, {GPR_NAMES[rs]}, 0x{imm:04x}", ""
            )
        if op == 0x0F and rs == 0:
            return DecodedInstruction(
                vaddr, file_offset, word, enclosing, True,
                "ALU_IMM", "lui", f"{GPR_NAMES[rt]}, 0x{imm:04x}",
                f"upper = 0x{(imm << 16):08x}"
            )

        # ---------------------------------------------------------------------
        # Standard Scalar Loads & Stores (LOAD_STORE)
        # ---------------------------------------------------------------------
        scalar_mem_ops = {
            0x1A: "ldl", 0x1B: "ldr",
            0x20: "lb",  0x21: "lh",  0x22: "lwl", 0x23: "lw",
            0x24: "lbu", 0x25: "lhu", 0x26: "lwr", 0x27: "lwu",
            0x28: "sb",  0x29: "sh",  0x2A: "swl", 0x2B: "sw",
            0x2C: "sdl", 0x2D: "sdr", 0x2E: "swr",
            0x37: "ld",  0x3F: "sd",
        }
        if op in scalar_mem_ops:
            mnem = scalar_mem_ops[op]
            return DecodedInstruction(
                vaddr, file_offset, word, enclosing, True,
                "LOAD_STORE", mnem, f"{GPR_NAMES[rt]}, {simm}({GPR_NAMES[rs]})", ""
            )

        # ---------------------------------------------------------------------
        # Everything else is UNDECODED (Zero Silent Skipping!)
        # Classify exact R5900 architectural reason for Milestone 2 planning
        # ---------------------------------------------------------------------
        if op == 0x10:
            if word == 0x42000038:
                reason = "COP0_SYSTEM (op=0x10, funct=0x38: تعليمة ei لتفعيل المقاطعات في R5900)"
            elif word == 0x42000039:
                reason = "COP0_SYSTEM (op=0x10, funct=0x39: تعليمة di لتعطيل المقاطعات في R5900)"
            elif rs == 0x00:
                reason = f"COP0_SYSTEM (op=0x10, rs=0x00: تعليمة mfc0 {GPR_NAMES[rt]}, ${rd} لقراءة سجل COP0)"
            elif rs == 0x04:
                reason = f"COP0_SYSTEM (op=0x10, rs=0x04: تعليمة mtc0 {GPR_NAMES[rt]}, ${rd} للكتابة في سجل COP0)"
            else:
                reason = f"COP0_SYSTEM (op=0x10, rs=0x{rs:02x})"
        elif op == 0x11:
            reason = f"COP1_FPU (op=0x11: تعليمة فاصلة عائمة COP1 غير مشمولة في المرحلة 1)"
        elif op == 0x12:
            reason = f"COP2_VU0_MACRO (op=0x12: تعليمة متجهات VU0 Macro غير مشمولة في المرحلة 1)"
        elif op == 0x1C:
            reason = f"R5900_MMI_SIMD (op=0x1c, sa=0x{sa:02x}, funct=0x{funct:02x}: تعليمة الوسائط المتعددة 128-بت مثل pcpyld)"
        elif op in (0x1E, 0x1F):
            mnem_q = "lq" if op == 0x1E else "sq"
            reason = f"R5900_QUADWORD_MEM (op=0x{op:02x}: تعليمة {mnem_q} {GPR_NAMES[rt]}, {simm}({GPR_NAMES[rs]}) للوصول 128-بت الخاص بـ R5900)"
        elif op == 0x2F:
            reason = "CACHE_OP (op=0x2f: تعليمة CACHE)"
        else:
            reason = f"UNKNOWN_OPCODE (op=0x{op:02x})"

        return DecodedInstruction(
            vaddr, file_offset, word, enclosing, False,
            "UNDECODED", "UNDECODED", f"0x{word:08x}", "", reason
        )


# =============================================================================
# 5. Full Binary Analysis Pipeline (Call Graph, Syscalls, Coverage)
# =============================================================================

def analyze_elf(elf_path: str) -> Dict:
    reader = ELF32Reader(elf_path)
    text_sh = reader.get_section_by_name(".text")
    if text_sh is None:
        raise ValueError("No .text section found in ELF.")

    # Build function lookup maps from .symtab
    func_symbols = sorted(
        [s for s in reader.symbols if s.sym_type == "FUNC" and s.st_value > 0],
        key=lambda s: s.st_value,
    )
    func_map: Dict[int, str] = {s.st_value: s.name for s in func_symbols}
    addr_to_func: Dict[int, str] = {}
    for idx, s in enumerate(func_symbols):
        start = s.st_value
        end = s.st_value + s.st_size if s.st_size > 0 else (
            func_symbols[idx + 1].st_value if idx + 1 < len(func_symbols) else text_sh.sh_addr + text_sh.sh_size
        )
        for a in range(start, end, 4):
            addr_to_func[a] = s.name

    decoder = R5900Decoder(func_map, addr_to_func)

    # Disassemble every 4-byte instruction word in .text
    instructions: List[DecodedInstruction] = []
    text_bytes = reader.data[text_sh.sh_offset : text_sh.sh_offset + text_sh.sh_size]
    num_insns = len(text_bytes) // 4
    for i in range(num_insns):
        vaddr = text_sh.sh_addr + i * 4
        foff = text_sh.sh_offset + i * 4
        word = struct.unpack("<I", text_bytes[i * 4 : (i + 1) * 4])[0]
        instructions.append(decoder.decode_word(vaddr, foff, word))

    # Compute Coverage & Histograms
    decoded_insns = [ins for ins in instructions if ins.decoded]
    undecoded_insns = [ins for ins in instructions if not ins.decoded]
    family_counts = Counter(ins.family for ins in instructions)
    mnemonic_counts = Counter(ins.mnemonic for ins in decoded_insns)
    undecoded_reasons = Counter(ins.undecoded_reason.split(" (")[0] for ins in undecoded_insns)

    # Build Static Call Graph from JAL and tail-call J instructions targeting functions
    call_edges: List[Dict] = []
    for ins in instructions:
        if ins.call_target is not None:
            callee_name = func_map.get(ins.call_target, f"sub_{ins.call_target:08x}")
            call_edges.append({
                "caller": ins.enclosing_func,
                "call_site_vaddr": f"0x{ins.vaddr:08x}",
                "instruction": f"{ins.mnemonic} 0x{ins.call_target:08x}",
                "callee": callee_name,
                "callee_vaddr": f"0x{ins.call_target:08x}",
                "is_tail_jump": ins.mnemonic == "j",
            })

    # Extract Syscall Inventory by tracking $v1 ($3) assignments before `syscall`
    syscalls_found: List[Dict] = []
    for idx, ins in enumerate(instructions):
        if ins.mnemonic == "syscall":
            v1_val: Optional[int] = None
            a0_val: Optional[int] = None
            # Scan backwards up to 6 instructions in the same function
            for back in range(idx - 1, max(-1, idx - 7), -1):
                prev = instructions[back]
                if prev.enclosing_func != ins.enclosing_func:
                    break
                if v1_val is None and prev.mnemonic in ("addiu", "ori", "addi") and prev.operands.startswith("$v1, $zero,"):
                    imm_str = prev.operands.split(",")[-1].strip()
                    v1_val = int(imm_str, 0)
                if a0_val is None and prev.mnemonic in ("addiu", "ori", "addi") and prev.operands.startswith("$a0, $zero,"):
                    imm_str = prev.operands.split(",")[-1].strip()
                    a0_val = int(imm_str, 0)
            sys_num = abs(v1_val) if v1_val is not None else -1
            is_negative = (v1_val is not None and v1_val < 0)
            sys_name, sys_desc = PS2_EE_SYSCALLS.get(sys_num, (f"Unknown_0x{sys_num:02x}", "غير معرّف في جدول النواة"))
            syscalls_found.append({
                "vaddr": f"0x{ins.vaddr:08x}",
                "enclosing_func": ins.enclosing_func,
                "v1_raw": f"0x{v1_val:02x}" if v1_val is not None else "dynamic",
                "syscall_num": sys_num,
                "is_negative_handler_mode": is_negative,
                "bios_name": sys_name,
                "a0_subcall": f"0x{a0_val:02x}" if a0_val is not None else None,
                "description": sys_desc,
            })

    return {
        "file_path": os.path.basename(elf_path),
        "file_size": reader.file_size,
        "sha256": reader.sha256,
        "elf_header": asdict(reader.header),
        "program_headers": [asdict(p) for p in reader.program_headers],
        "section_headers": [asdict(s) for s in reader.section_headers],
        "symbols": [asdict(s) for s in reader.symbols],
        "functions": [asdict(s) for s in func_symbols],
        "relocations": [asdict(r) for r in reader.relocations],
        "coverage": {
            "total_instructions": len(instructions),
            "decoded_instructions": len(decoded_insns),
            "undecoded_instructions": len(undecoded_insns),
            "coverage_percent": round(100.0 * len(decoded_insns) / len(instructions), 2),
            "family_histogram": dict(family_counts),
            "mnemonic_histogram": dict(mnemonic_counts.most_common()),
            "undecoded_category_counts": dict(undecoded_reasons),
        },
        "call_graph": call_edges,
        "syscalls": syscalls_found,
        "undecoded_list": [
            {
                "vaddr": f"0x{u.vaddr:08x}",
                "file_offset": f"0x{u.file_offset:04x}",
                "raw_hex": f"0x{u.raw_word:08x}",
                "function": u.enclosing_func,
                "reason": u.undecoded_reason,
            }
            for u in undecoded_insns
        ],
        "disassembly": [
            {
                "vaddr": f"0x{ins.vaddr:08x}",
                "file_offset": f"0x{ins.file_offset:04x}",
                "raw_hex": f"0x{ins.raw_word:08x}",
                "function": ins.enclosing_func,
                "decoded": ins.decoded,
                "family": ins.family,
                "mnemonic": ins.mnemonic,
                "operands": ins.operands,
                "comment": ins.comment,
                "undecoded_reason": ins.undecoded_reason,
            }
            for ins in instructions
        ],
    }


def main_cli() -> None:
    parser = argparse.ArgumentParser(description="PS2 Static Lifter Milestone 1 — ELF32 Reader & R5900 Disassembler")
    parser.add_argument("elf_file", help="Path to input PS2 ELF32-MIPS executable")
    parser.add_argument("--json", dest="json_out", help="Write full structured analysis to JSON file")
    args = parser.parse_args()

    result = analyze_elf(args.elf_file)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

    hdr = result["elf_header"]
    cov = result["coverage"]
    print(f"=== PS2 Static Lifter M1 — Analysis Summary for {result['file_path']} ===")
    print(f"SHA-256:            {result['sha256']}")
    print(f"File Size:          {result['file_size']} bytes")
    print(f"ELF Class / Data:   {hdr['ei_class']} / {hdr['ei_data']}")
    print(f"Machine / Flags:    {hdr['e_machine_str']} / 0x{hdr['e_flags']:08x}")
    print(f"Entry Point:        0x{hdr['e_entry']:08x}")
    print(f"Program Headers:    {hdr['e_phnum']}")
    print(f"Section Headers:    {hdr['e_shnum']} ({', '.join(s['name'] or 'NULL' for s in result['section_headers'])})")
    print(f"Functions (.symtab):{len(result['functions'])}")
    print(f"Relocations:        {len(result['relocations'])}")
    print(f"Total Instructions: {cov['total_instructions']}")
    print(f"Decoded:            {cov['decoded_instructions']} ({cov['coverage_percent']:.2f}%)")
    print(f"UNDECODED:          {cov['undecoded_instructions']}")
    print("\n--- UNDECODED Instructions ---")
    for u in result["undecoded_list"]:
        print(f"  {u['vaddr']} ({u['raw_hex']}) in {u['function']}: {u['reason']}")
    print("\n--- Detected EE BIOS Syscalls ---")
    for sc in result["syscalls"]:
        sub = f", $a0={sc['a0_subcall']}" if sc["a0_subcall"] else ""
        print(f"  {sc['vaddr']} in {sc['enclosing_func']}: $v1={sc['v1_raw']}{sub} -> {sc['bios_name']}")


if __name__ == "__main__":
    main_cli()
