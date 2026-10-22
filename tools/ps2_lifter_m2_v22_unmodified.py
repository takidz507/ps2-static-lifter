#!/usr/bin/env python3
"""
PS2 Static Lifter - Milestone 2.1 (ps2_lifter_m2.py)
====================================================
Clean-room static binary lifter for PS2 Emotion Engine (R5900) ELF32 binaries.
Upgraded in Milestone 2.1 following the documented blind test on hello_real.elf
(ee-gcc 15.2.0, ps2dev/ps2sdk @ 329e2bb):

  1. Indirect Call/Jump Modeling (Item 1):
     - Tracks $t9 constant loads (lui + addiu) and static pointer loads (lui + lw from .data/.ctors).
     - Decodes .rodata jump tables (including stack-spilled base pointers) and links every slot
       to its local C label via a switch statement.
     - Records every statically unresolvable indirect call/jump as a declared INDIRECT blocker
       (address + raw word + reason) and emits ps2_indirect_dispatch() which fails loudly with
       the site address if an unresolved target is reached at runtime.
  2. Robustness Law (Item 2):
     - No single instruction can crash or abort the lifting pipeline with a Python Traceback.
     - Always finishes with a full summary (lifted vs. classified blockers) and distinct exit codes:
         * 0 = Full lift success with zero blockers
         * 2 = Lift completed with declared blockers (C code emitted & compilable)
         * 1 = Structural failure reading/parsing input ELF
  3. Exotic Instruction Families Lifted with Documented Semantics (Item 3):
     - CACHE ops -> documented host no-op (ps2_cache_op)
     - COP0 (mfc0/mtc0 on Status/TagLo/EPC/Cause/Count + ei/di) -> ps2_cop0_* state helpers
     - SYNC (sync.l / sync.p) -> documented memory barrier (ps2_sync_barrier)
     - R5900 MMI (pcpyld in hello_kernel_min.elf; madd, pmfhl.lw in __muldi3 of hello_real.elf)
       & 128-bit LQ/SQ in __start
     - Full MIPS III/IV scalar coverage (mult/multu/div/divu, movz/movn, ldl/ldr/sdl/sdr, bgezal, teq)
  4. Guest Memory Image Generation (Item 4):
     - Emits PT_LOAD segments as C byte arrays with virtual-address-to-offset mapping and
       initializes $gp from .reginfo / _gp symbol so all $gp-relative .sdata accesses work natively.
  5. Expanded Syscall Inventory (Item 5):
     - Recognizes and annotates all 34 PS2 EE kernel syscalls observed in hello_real.elf
       (across positive and negative $v1 numbers) plus Deci2Call (0x7c) and print (0x75).
"""

import argparse
import dataclasses
import hashlib
import json
import os
import re
import struct
import sys
from typing import Dict, List, Optional, Set, Tuple

LIFTER_VERSION = "2.2.0"

GPR_NAMES = [
    "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
    "$t0",   "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0",   "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8",   "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
]

COP0_REG_NAMES = {
    0: "Index", 1: "Random", 2: "EntryLo0", 3: "EntryLo1",
    4: "Context", 5: "PageMask", 6: "Wired", 8: "BadVAddr",
    9: "Count", 10: "EntryHi", 11: "Compare", 12: "Status",
    13: "Cause", 14: "EPC", 15: "PRId", 16: "Config",
    23: "BadPAddr", 24: "Debug", 25: "Perf", 28: "TagLo",
    29: "TagHi", 30: "ErrorEPC",
}

PS2_SYSCALL_TABLE: Dict[int, str] = {
    0x01: "ResetEE",
    0x02: "SetGsCrt",
    0x04: "Exit",
    0x06: "LoadExecPS2",
    0x07: "ExecPS2",
    0x0D: "SetVTLBRefillHandler",
    0x10: "AddIntcHandler",
    0x11: "RemoveIntcHandler",
    0x12: "AddDmacHandler",
    0x13: "RemoveDmacHandler",
    0x14: "EnableIntc",
    0x15: "DisableIntc",
    0x16: "EnableDmac",
    0x17: "DisableDmac",
    0x18: "SetAlarm",
    0x19: "ReleaseAlarm",
    0x1A: "_EnableIntc",
    0x1B: "_DisableIntc",
    0x1C: "_EnableDmac",
    0x1D: "_DisableDmac",
    0x1E: "_SetAlarm",
    0x1F: "_ReleaseAlarm",
    0x20: "CreateThread",
    0x21: "DeleteThread",
    0x22: "StartThread",
    0x23: "ExitThread",
    0x24: "ExitDeleteThread",
    0x25: "TerminateThread",
    0x29: "ChangeThreadPriority",
    0x2B: "RotateThreadReadyQueue",
    0x2C: "ReleaseWaitThread",
    0x2F: "GetThreadId",
    0x32: "SleepThread",
    0x33: "WakeupThread",
    0x34: "iWakeupThread",
    0x35: "CancelWakeupThread",
    0x37: "SuspendThread",
    0x39: "ResumeThread",
    0x3C: "RFU060_SetupThread",
    0x3D: "RFU061_SetupHeap",
    0x3E: "EndOfHeap",
    0x40: "CreateSema",
    0x41: "DeleteSema",
    0x42: "SignalSema",
    0x43: "iSignalSema",
    0x44: "WaitSema",
    0x45: "PollSema",
    0x46: "iPollSema",
    0x4A: "SetOsdConfigParam",
    0x4B: "GetOsdConfigParam",
    0x64: "FlushCache",
    0x70: "GsGetIMR",
    0x71: "GsPutIMR",
    0x75: "print",
    0x76: "SifStopDma",
    0x77: "SifSetDChain",
    0x78: "SifSetDma",
    0x79: "SifSetReg",
    0x7A: "SifGetReg",
    0x7C: "Deci2Call",
    0x7F: "GetMemorySize",
}


def sign_extend_16(val: int) -> int:
    val &= 0xFFFF
    return val - 0x10000 if (val & 0x8000) else val


def sanitize_c_ident(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_]", "_", name)
    return clean if clean else "sub"


def c_func_name(sym_name: str, vaddr: int) -> str:
    return f"fn_{vaddr:08x}_{sanitize_c_ident(sym_name)}"


@dataclasses.dataclass
class Instruction:
    vaddr: int
    word: int
    mnemonic: str
    operands: str
    family: str
    decoded: bool
    opcode: int = 0
    rs: int = 0
    rt: int = 0
    rd: int = 0
    shamt: int = 0
    funct: int = 0
    simm: int = 0
    uimm: int = 0
    target_vaddr: Optional[int] = None
    has_delay_slot: bool = False
    is_branch: bool = False
    is_branch_likely: bool = False
    is_jump: bool = False
    is_call: bool = False
    is_return: bool = False
    is_syscall: bool = False


@dataclasses.dataclass
class IndirectResolution:
    vaddr: int
    raw_word: int
    func_name: str
    mnemonic: str
    kind: str  # "JUMP_TABLE", "CONST_LUI_ADDIU", "STATIC_DATA_PTR", "UNRESOLVED"
    resolved: bool
    target_vaddr: Optional[int] = None
    target_name: Optional[str] = None
    jump_table_base: Optional[int] = None
    jump_table_entries: Optional[List[int]] = None
    data_ptr_vaddr: Optional[int] = None
    reason: str = ""


@dataclasses.dataclass
class BlockerEntry:
    vaddr: int
    vaddr_hex: str
    raw_hex: str
    func_name: str
    category: str  # "INDIRECT" or "UNLIFTED_INSN"
    mnemonic: str
    reason: str


class Elf32Parser:
    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.raw = f.read()
        self.sha256 = hashlib.sha256(self.raw).hexdigest()
        self.size_bytes = len(self.raw)
        self.header: Dict[str, int] = {}
        self.phdrs: List[Dict[str, int]] = []
        self.shdrs: List[Dict[str, object]] = []
        self.symbols: List[Dict[str, object]] = []
        self.functions: List[Dict[str, object]] = []
        self.gp_value: int = 0
        self._parse()

    def _parse(self) -> None:
        if len(self.raw) < 52 or self.raw[:4] != b"\x7fELF":
            raise ValueError("Not a valid ELF32 binary")
        ei_class, ei_data = self.raw[4], self.raw[5]
        if ei_class != 1 or ei_data != 1:
            raise ValueError(f"Unsupported ELF class/endianness: class={ei_class}, data={ei_data}")

        (
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
            e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
        ) = struct.unpack("<HHIIIIIHHHHHH", self.raw[16:52])

        self.header = {
            "e_type": e_type,
            "e_machine": e_machine,
            "e_version": e_version,
            "e_entry": e_entry,
            "e_phoff": e_phoff,
            "e_shoff": e_shoff,
            "e_flags": e_flags,
            "e_phnum": e_phnum,
            "e_shnum": e_shnum,
        }

        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(
                "<IIIIIIII", self.raw[off:off + 32]
            )
            self.phdrs.append({
                "index": i,
                "p_type": p_type,
                "p_offset": p_offset,
                "p_vaddr": p_vaddr,
                "p_paddr": p_paddr,
                "p_filesz": p_filesz,
                "p_memsz": p_memsz,
                "p_flags": p_flags,
                "p_align": p_align,
            })

        shstrtab = b""
        if e_shstrndx < e_shnum:
            sh_off = e_shoff + e_shstrndx * e_shentsize
            _, _, _, _, s_offset, s_size, _, _, _, _ = struct.unpack("<IIIIIIIIII", self.raw[sh_off:sh_off + 40])
            shstrtab = self.raw[s_offset:s_offset + s_size]

        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = (
                struct.unpack("<IIIIIIIIII", self.raw[off:off + 40])
            )
            end_idx = shstrtab.find(b"\x00", sh_name)
            name_str = shstrtab[sh_name:end_idx].decode("ascii", errors="replace") if end_idx != -1 else f"sec_{i}"
            self.shdrs.append({
                "index": i,
                "name": name_str,
                "sh_type": sh_type,
                "sh_flags": sh_flags,
                "sh_addr": sh_addr,
                "sh_offset": sh_offset,
                "sh_size": sh_size,
                "sh_link": sh_link,
                "sh_info": sh_info,
                "sh_addralign": sh_addralign,
                "sh_entsize": sh_entsize,
            })
            if name_str == ".reginfo" and sh_size >= 24:
                self.gp_value = struct.unpack("<I", self.raw[sh_offset + 20:sh_offset + 24])[0]

        for s in self.shdrs:
            if s["sh_type"] == 2:  # SHT_SYMTAB
                strtab_sec = self.shdrs[int(s["sh_link"])]
                strtab = self.raw[int(strtab_sec["sh_offset"]):int(strtab_sec["sh_offset"]) + int(strtab_sec["sh_size"])]
                entsize = int(s["sh_entsize"]) or 16
                count = int(s["sh_size"]) // entsize
                base = int(s["sh_offset"])
                for idx in range(count):
                    soff = base + idx * entsize
                    st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack(
                        "<IIIBBH", self.raw[soff:soff + 16]
                    )
                    end_idx = strtab.find(b"\x00", st_name)
                    sym_name = strtab[st_name:end_idx].decode("ascii", errors="replace") if end_idx != -1 else ""
                    st_type = st_info & 0xF
                    st_bind = st_info >> 4
                    entry = {
                        "index": idx,
                        "name": sym_name,
                        "st_value": st_value,
                        "st_size": st_size,
                        "st_type": st_type,
                        "st_bind": st_bind,
                        "st_shndx": st_shndx,
                    }
                    self.symbols.append(entry)
                    if sym_name in ("_gp", "_gp_disp") and st_value != 0 and self.gp_value == 0:
                        self.gp_value = st_value
                    if st_type == 2 and st_value != 0:  # STT_FUNC
                        self.functions.append(entry)

        by_addr: Dict[int, Dict[str, object]] = {}
        for fn in sorted(self.functions, key=lambda x: (int(x["st_value"]), str(x["name"]))):
            addr = int(fn["st_value"])
            if addr not in by_addr:
                by_addr[addr] = dict(fn)
            else:
                if int(fn["st_size"]) > int(by_addr[addr]["st_size"]):
                    by_addr[addr]["st_size"] = fn["st_size"]
        self.functions = [by_addr[k] for k in sorted(by_addr.keys())]

    def get_section(self, name: str) -> Optional[Dict[str, object]]:
        for s in self.shdrs:
            if s["name"] == name:
                return s
        return None

    def read_u32_at_vaddr(self, vaddr: int) -> Optional[int]:
        """Reads an initialized 32-bit Little-Endian word from any allocated section or PT_LOAD segment."""
        for s in self.shdrs:
            sh_addr = int(s["sh_addr"])
            sh_size = int(s["sh_size"])
            sh_type = int(s["sh_type"])
            sh_off = int(s["sh_offset"])
            if sh_addr != 0 and sh_addr <= vaddr <= sh_addr + sh_size - 4:
                if sh_type == 8:  # SHT_NOBITS (.bss / .sbss)
                    return 0
                off = sh_off + (vaddr - sh_addr)
                if 0 <= off <= len(self.raw) - 4:
                    return struct.unpack("<I", self.raw[off:off + 4])[0]
        for p in self.phdrs:
            if p["p_type"] == 1:  # PT_LOAD
                pv = p["p_vaddr"]
                pm = p["p_memsz"]
                pf = p["p_filesz"]
                po = p["p_offset"]
                if pv <= vaddr <= pv + pm - 4:
                    delta = vaddr - pv
                    if delta <= pf - 4:
                        return struct.unpack("<I", self.raw[po + delta:po + delta + 4])[0]
                    return 0
        return None


def decode_r5900(word: int, vaddr: int) -> Instruction:
    """Decodes a 32-bit MIPS III / R5900 instruction word."""
    if word == 0x00000000:
        return Instruction(vaddr=vaddr, word=word, mnemonic="nop", operands="", family="NOP", decoded=True)

    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    rd = (word >> 11) & 0x1F
    shamt = (word >> 6) & 0x1F
    funct = word & 0x3F
    uimm = word & 0xFFFF
    simm = sign_extend_16(uimm)
    jidx = word & 0x03FFFFFF

    # SPECIAL (op == 0x00)
    if op == 0x00:
        if funct == 0x00:
            return Instruction(
                vaddr, word, "sll", f"{GPR_NAMES[rd]}, {GPR_NAMES[rt]}, {shamt}",
                "SHIFT_32_64", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x02:
            return Instruction(
                vaddr, word, "srl", f"{GPR_NAMES[rd]}, {GPR_NAMES[rt]}, {shamt}",
                "SHIFT_32_64", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x03:
            return Instruction(
                vaddr, word, "sra", f"{GPR_NAMES[rd]}, {GPR_NAMES[rt]}, {shamt}",
                "SHIFT_32_64", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x04:
            return Instruction(
                vaddr, word, "sllv", f"{GPR_NAMES[rd]}, {GPR_NAMES[rt]}, {GPR_NAMES[rs]}",
                "SHIFT_32_64", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x06:
            return Instruction(
                vaddr, word, "srlv", f"{GPR_NAMES[rd]}, {GPR_NAMES[rt]}, {GPR_NAMES[rs]}",
                "SHIFT_32_64", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x07:
            return Instruction(
                vaddr, word, "srav", f"{GPR_NAMES[rd]}, {GPR_NAMES[rt]}, {GPR_NAMES[rs]}",
                "SHIFT_32_64", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x08:
            return Instruction(
                vaddr, word, "jr", f"{GPR_NAMES[rs]}",
                "CONTROL_FLOW", True, op, rs, rt, rd, shamt, funct,
                has_delay_slot=True, is_jump=True, is_return=(rs == 31)
            )
        if funct == 0x09:
            return Instruction(
                vaddr, word, "jalr", f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}",
                "CONTROL_FLOW", True, op, rs, rt, rd, shamt, funct,
                has_delay_slot=True, is_jump=True, is_call=True
            )
        if funct == 0x0A:
            return Instruction(
                vaddr, word, "movz", f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "COND_MOVE", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x0B:
            return Instruction(
                vaddr, word, "movn", f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "COND_MOVE", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x0C:
            return Instruction(
                vaddr, word, "syscall", "",
                "SYSTEM_CALL", True, op, rs, rt, rd, shamt, funct, is_syscall=True
            )
        if funct == 0x0D:
            return Instruction(
                vaddr, word, "break", "",
                "SYSTEM_CALL", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x0F:
            stype = shamt
            mnem = "sync.p" if (stype & 0x10) else "sync.l"
            return Instruction(
                vaddr, word, mnem, f"stype=0x{stype:x}",
                "MEMORY_BARRIER_SYNC", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x10:
            return Instruction(
                vaddr, word, "mfhi", f"{GPR_NAMES[rd]}",
                "MULT_DIV", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x11:
            return Instruction(
                vaddr, word, "mthi", f"{GPR_NAMES[rs]}",
                "MULT_DIV", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x12:
            return Instruction(
                vaddr, word, "mflo", f"{GPR_NAMES[rd]}",
                "MULT_DIV", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x13:
            return Instruction(
                vaddr, word, "mtlo", f"{GPR_NAMES[rs]}",
                "MULT_DIV", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x14:
            return Instruction(
                vaddr, word, "dsllv", f"{GPR_NAMES[rd]}, {GPR_NAMES[rt]}, {GPR_NAMES[rs]}",
                "SHIFT_32_64", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x16:
            return Instruction(
                vaddr, word, "dsrlv", f"{GPR_NAMES[rd]}, {GPR_NAMES[rt]}, {GPR_NAMES[rs]}",
                "SHIFT_32_64", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x17:
            return Instruction(
                vaddr, word, "dsrav", f"{GPR_NAMES[rd]}, {GPR_NAMES[rt]}, {GPR_NAMES[rs]}",
                "SHIFT_32_64", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x18:
            return Instruction(
                vaddr, word, "mult", f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "MULT_DIV", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x19:
            return Instruction(
                vaddr, word, "multu", f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "MULT_DIV", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x1A:
            return Instruction(
                vaddr, word, "div", f"{GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "MULT_DIV", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x1B:
            return Instruction(
                vaddr, word, "divu", f"{GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "MULT_DIV", True, op, rs, rt, rd, shamt, funct
            )
        if funct in (0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F):
            mnem_map = {
                0x20: "add", 0x21: "addu", 0x22: "sub", 0x23: "subu",
                0x24: "and", 0x25: "or",   0x26: "xor", 0x27: "nor",
                0x2A: "slt", 0x2B: "sltu", 0x2C: "dadd", 0x2D: "daddu",
                0x2E: "dsub", 0x2F: "dsubu",
            }
            return Instruction(
                vaddr, word, mnem_map[funct], f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "ALU_32_64", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x34:
            code = (word >> 6) & 0x3FF
            return Instruction(
                vaddr, word, "teq", f"{GPR_NAMES[rs]}, {GPR_NAMES[rt]}, 0x{code:x}",
                "TRAP", True, op, rs, rt, rd, shamt, funct
            )
        if funct in (0x38, 0x3A, 0x3B, 0x3C, 0x3E, 0x3F):
            s_map = {
                0x38: "dsll", 0x3A: "dsrl", 0x3B: "dsra",
                0x3C: "dsll32", 0x3E: "dsrl32", 0x3F: "dsra32",
            }
            return Instruction(
                vaddr, word, s_map[funct], f"{GPR_NAMES[rd]}, {GPR_NAMES[rt]}, {shamt}",
                "SHIFT_32_64", True, op, rs, rt, rd, shamt, funct
            )

    # REGIMM (op == 0x01)
    if op == 0x01:
        target = (vaddr + 4 + (simm << 2)) & 0xFFFFFFFF
        regimm_map = {
            0x00: ("bltz", False, False),
            0x01: ("bgez", False, False),
            0x02: ("bltzl", True, False),
            0x03: ("bgezl", True, False),
            0x10: ("bltzal", False, True),
            0x11: ("bgezal", False, True),
            0x12: ("bltzall", True, True),
            0x13: ("bgezall", True, True),
        }
        if rt in regimm_map:
            mnem, likely, is_call_flag = regimm_map[rt]
            return Instruction(
                vaddr, word, mnem, f"{GPR_NAMES[rs]}, 0x{target:08x}",
                "CONTROL_FLOW", True, op, rs, rt, rd, shamt, funct, simm, uimm,
                target_vaddr=target, has_delay_slot=True, is_branch=True,
                is_branch_likely=likely, is_call=is_call_flag
            )

    # Direct Jump / Call (J / JAL)
    if op in (0x02, 0x03):
        target = ((vaddr + 4) & 0xF0000000) | (jidx << 2)
        mnem = "j" if op == 0x02 else "jal"
        return Instruction(
            vaddr, word, mnem, f"0x{target:08x}",
            "CONTROL_FLOW", True, op, rs, rt, rd, shamt, funct, simm, uimm,
            target_vaddr=target, has_delay_slot=True, is_jump=True, is_call=(op == 0x03)
        )

    # Standard Conditional Branches & Branch-Likely
    branch_ops = {
        0x04: ("beq", False), 0x05: ("bne", False), 0x06: ("blez", False), 0x07: ("bgtz", False),
        0x14: ("beql", True), 0x15: ("bnel", True), 0x16: ("blezl", True), 0x17: ("bgtzl", True),
    }
    if op in branch_ops:
        mnem, likely = branch_ops[op]
        target = (vaddr + 4 + (simm << 2)) & 0xFFFFFFFF
        ops_str = (
            f"{GPR_NAMES[rs]}, {GPR_NAMES[rt]}, 0x{target:08x}"
            if op in (0x04, 0x05, 0x14, 0x15)
            else f"{GPR_NAMES[rs]}, 0x{target:08x}"
        )
        return Instruction(
            vaddr, word, mnem, ops_str,
            "CONTROL_FLOW", True, op, rs, rt, rd, shamt, funct, simm, uimm,
            target_vaddr=target, has_delay_slot=True, is_branch=True, is_branch_likely=likely
        )

    # Immediate ALU
    imm_alu = {
        0x08: ("addi", True), 0x09: ("addiu", True), 0x0A: ("slti", True), 0x0B: ("sltiu", True),
        0x0C: ("andi", False), 0x0D: ("ori", False), 0x0E: ("xori", False),
        0x18: ("daddi", True), 0x19: ("daddiu", True),
    }
    if op in imm_alu:
        mnem, is_signed = imm_alu[op]
        imm_str = str(simm) if is_signed else f"0x{uimm:04x}"
        return Instruction(
            vaddr, word, mnem, f"{GPR_NAMES[rt]}, {GPR_NAMES[rs]}, {imm_str}",
            "ALU_32_64", True, op, rs, rt, rd, shamt, funct, simm, uimm
        )

    if op == 0x0F:
        return Instruction(
            vaddr, word, "lui", f"{GPR_NAMES[rt]}, 0x{uimm:04x}",
            "ALU_32_64", True, op, rs, rt, rd, shamt, funct, simm, uimm
        )

    # COP0 System Control (op == 0x10) - Milestone 2.1 Item 3
    if op == 0x10:
        if word == 0x42000038:
            return Instruction(
                vaddr, word, "ei", "",
                "COP0_SYSTEM", True, op, rs, rt, rd, shamt, funct
            )
        if word == 0x42000039:
            return Instruction(
                vaddr, word, "di", "",
                "COP0_SYSTEM", True, op, rs, rt, rd, shamt, funct
            )
        if rs == 0x00 and shamt == 0 and funct == 0:
            c0_name = COP0_REG_NAMES.get(rd, f"${rd}")
            return Instruction(
                vaddr, word, "mfc0", f"{GPR_NAMES[rt]}, {c0_name}",
                "COP0_SYSTEM", True, op, rs, rt, rd, shamt, funct
            )
        if rs == 0x04 and shamt == 0 and funct == 0:
            c0_name = COP0_REG_NAMES.get(rd, f"${rd}")
            return Instruction(
                vaddr, word, "mtc0", f"{GPR_NAMES[rt]}, {c0_name}",
                "COP0_SYSTEM", True, op, rs, rt, rd, shamt, funct
            )

    # R5900 MMI / Pipeline 1 Scalar & SIMD (op == 0x1C) - Milestone 2.1 Item 3
    if op == 0x1C:
        if funct == 0x09 and shamt == 0x0E:  # pcpyld rd, rs, rt (MMI2)
            return Instruction(
                vaddr, word, "pcpyld", f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "R5900_MMI", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x00:
            return Instruction(
                vaddr, word, "madd", f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "R5900_MMI", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x01:
            return Instruction(
                vaddr, word, "maddu", f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "R5900_MMI", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x10:
            return Instruction(
                vaddr, word, "mfhi1", f"{GPR_NAMES[rd]}",
                "R5900_MMI", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x11:
            return Instruction(
                vaddr, word, "mthi1", f"{GPR_NAMES[rs]}",
                "R5900_MMI", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x12:
            return Instruction(
                vaddr, word, "mflo1", f"{GPR_NAMES[rd]}",
                "R5900_MMI", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x13:
            return Instruction(
                vaddr, word, "mtlo1", f"{GPR_NAMES[rs]}",
                "R5900_MMI", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x18:
            return Instruction(
                vaddr, word, "mult1", f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "R5900_MMI", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x19:
            return Instruction(
                vaddr, word, "multu1", f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "R5900_MMI", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x1A:
            return Instruction(
                vaddr, word, "div1", f"{GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "R5900_MMI", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x1B:
            return Instruction(
                vaddr, word, "divu1", f"{GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "R5900_MMI", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x20:
            return Instruction(
                vaddr, word, "madd1", f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "R5900_MMI", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x21:
            return Instruction(
                vaddr, word, "maddu1", f"{GPR_NAMES[rd]}, {GPR_NAMES[rs]}, {GPR_NAMES[rt]}",
                "R5900_MMI", True, op, rs, rt, rd, shamt, funct
            )
        if funct == 0x30 and shamt == 0x00:
            return Instruction(
                vaddr, word, "pmfhl.lw", f"{GPR_NAMES[rd]}",
                "R5900_MMI", True, op, rs, rt, rd, shamt, funct
            )

    # Loads & Stores (including R5900 128-bit LQ/SQ and MIPS III 64-bit LDL/LDR/SDL/SDR)
    mem_ops = {
        0x1A: "ldl",  0x1B: "ldr",
        0x1E: "lq",   0x1F: "sq",
        0x20: "lb",   0x21: "lh",   0x22: "lwl",  0x23: "lw",
        0x24: "lbu",  0x25: "lhu",  0x26: "lwr",  0x27: "lwu",
        0x28: "sb",   0x29: "sh",   0x2A: "swl",  0x2B: "sw",
        0x2C: "sdl",  0x2D: "sdr",  0x2E: "swr",
        0x37: "ld",   0x3F: "sd",
    }
    if op in mem_ops:
        mnem = mem_ops[op]
        fam = "R5900_QUADWORD_MEM" if op in (0x1E, 0x1F) else "LOAD_STORE"
        return Instruction(
            vaddr, word, mnem, f"{GPR_NAMES[rt]}, {simm}({GPR_NAMES[rs]})",
            fam, True, op, rs, rt, rd, shamt, funct, simm, uimm
        )

    # CACHE instruction (op == 0x2F) - Milestone 2.1 Item 3
    if op == 0x2F:
        return Instruction(
            vaddr, word, "cache", f"0x{rt:02x}, {simm}({GPR_NAMES[rs]})",
            "CACHE_OP", True, op, rs, rt, rd, shamt, funct, simm, uimm
        )

    return Instruction(
        vaddr, word, "UNDECODED", f"0x{word:08x}",
        f"UNSUPPORTED_OP_0x{op:02x}", False, op, rs, rt, rd, shamt, funct, simm, uimm
    )


class IndirectAnalyzer:
    """
    Milestone 2.1 Item 1: Static Indirect Call & Jump Resolver
    ----------------------------------------------------------
    Analyzes every indirect control-flow site (jalr and jr where rs != $ra)
    inside a function and classifies it into:
      1. JUMP_TABLE: .rodata switch table (with stack-spilled base pointer tracking)
      2. CONST_LUI_ADDIU: $t9 loaded via constant lui + addiu pair
      3. STATIC_DATA_PTR: $t9 loaded via lui + lw from initialized .data / .ctors word
      4. UNRESOLVED: dynamic struct callback, function pointer argument, or runtime array
         -> becomes a declared INDIRECT Blocker with exact site address, raw hex, and reason.
    """

    def __init__(
        self,
        elf: Elf32Parser,
        func_by_vaddr: Dict[int, Dict[str, object]],
        rodata_range: Tuple[int, int],
        data_ranges: List[Tuple[str, int, int]],
    ):
        self.elf = elf
        self.func_by_vaddr = func_by_vaddr
        self.rodata_range = rodata_range
        self.data_ranges = data_ranges

    def _in_rodata(self, addr: int) -> bool:
        lo, hi = self.rodata_range
        return lo <= addr < hi

    def _in_data_section(self, addr: int) -> Optional[str]:
        for name, lo, hi in self.data_ranges:
            if lo <= addr <= hi - 4:
                return name
        return None

    def analyze_site(
        self,
        insns: List[Instruction],
        idx: int,
        func_name: str,
        f_start: int,
        f_end: int,
    ) -> IndirectResolution:
        ins = insns[idx]
        target_reg = ins.rs

        if ins.mnemonic == "jr" and target_reg != 31:
            jt_res = self._try_resolve_jump_table(insns, idx, func_name, f_start, f_end)
            if jt_res is not None:
                return jt_res

        window_start = max(0, idx - 32)
        for j in range(idx - 1, window_start - 1, -1):
            prev = insns[j]
            # Pattern A: addiu $t9, $src, lo  preceded by  lui $src, hi
            if prev.mnemonic in ("addiu", "ori", "daddiu") and prev.rt == target_reg:
                src_reg = prev.rs
                lo_val = prev.simm if prev.mnemonic != "ori" else prev.uimm
                for m in range(j - 1, max(-1, j - 16), -1):
                    p2 = insns[m]
                    if p2.mnemonic == "lui" and p2.rt == src_reg:
                        const_addr = ((p2.uimm << 16) + lo_val) & 0xFFFFFFFF
                        if const_addr == 0:
                            return IndirectResolution(
                                vaddr=ins.vaddr,
                                raw_word=ins.word,
                                func_name=func_name,
                                mnemonic=f"{ins.mnemonic} {ins.operands}",
                                kind="CONST_LUI_ADDIU",
                                resolved=True,
                                target_vaddr=0,
                                target_name="NULL_WEAK_SYMBOL",
                                reason="Resolved constant 0x00000000 (guarded weak symbol in CRT)",
                            )
                        if const_addr in self.func_by_vaddr:
                            t_name = str(self.func_by_vaddr[const_addr]["c_name"])
                            return IndirectResolution(
                                vaddr=ins.vaddr,
                                raw_word=ins.word,
                                func_name=func_name,
                                mnemonic=f"{ins.mnemonic} {ins.operands}",
                                kind="CONST_LUI_ADDIU",
                                resolved=True,
                                target_vaddr=const_addr,
                                target_name=t_name,
                                reason=f"Resolved constant lui+addiu pair -> 0x{const_addr:08x} ({t_name})",
                            )
                        break
                break

            # Pattern B: lw $t9, offset($base)
            if prev.mnemonic in ("lw", "lwu", "ld") and prev.rt == target_reg:
                base_reg = prev.rs
                offset = prev.simm
                for m in range(j - 1, max(-1, j - 24), -1):
                    p2 = insns[m]
                    if p2.mnemonic == "lui" and p2.rt == base_reg:
                        ptr_vaddr = ((p2.uimm << 16) + offset) & 0xFFFFFFFF
                        sec_name = self._in_data_section(ptr_vaddr)
                        if sec_name is not None:
                            loaded_val = self.elf.read_u32_at_vaddr(ptr_vaddr)
                            if loaded_val is not None and loaded_val in self.func_by_vaddr:
                                t_name = str(self.func_by_vaddr[loaded_val]["c_name"])
                                return IndirectResolution(
                                    vaddr=ins.vaddr,
                                    raw_word=ins.word,
                                    func_name=func_name,
                                    mnemonic=f"{ins.mnemonic} {ins.operands}",
                                    kind="STATIC_DATA_PTR",
                                    resolved=True,
                                    target_vaddr=loaded_val,
                                    target_name=t_name,
                                    data_ptr_vaddr=ptr_vaddr,
                                    reason=(
                                        f"Resolved static pointer load from {sec_name}@0x{ptr_vaddr:08x} "
                                        f"-> 0x{loaded_val:08x} ({t_name})"
                                    ),
                                )
                        break
                    if p2.mnemonic in ("addiu", "daddiu") and p2.rt == base_reg:
                        sub_base = p2.rs
                        sub_lo = p2.simm
                        for n in range(m - 1, max(-1, m - 16), -1):
                            p3 = insns[n]
                            if p3.mnemonic == "lui" and p3.rt == sub_base:
                                ptr_vaddr = ((p3.uimm << 16) + sub_lo + offset) & 0xFFFFFFFF
                                sec_name = self._in_data_section(ptr_vaddr)
                                if sec_name is not None:
                                    loaded_val = self.elf.read_u32_at_vaddr(ptr_vaddr)
                                    if loaded_val is not None and loaded_val in self.func_by_vaddr:
                                        t_name = str(self.func_by_vaddr[loaded_val]["c_name"])
                                        return IndirectResolution(
                                            vaddr=ins.vaddr,
                                            raw_word=ins.word,
                                            func_name=func_name,
                                            mnemonic=f"{ins.mnemonic} {ins.operands}",
                                            kind="STATIC_DATA_PTR",
                                            resolved=True,
                                            target_vaddr=loaded_val,
                                            target_name=t_name,
                                            data_ptr_vaddr=ptr_vaddr,
                                            reason=(
                                                f"Resolved static table pointer from {sec_name}@0x{ptr_vaddr:08x} "
                                                f"-> 0x{loaded_val:08x} ({t_name})"
                                            ),
                                        )
                                break
                        break

                reason = self._classify_unresolved_load(insns, j, prev, func_name)
                return IndirectResolution(
                    vaddr=ins.vaddr,
                    raw_word=ins.word,
                    func_name=func_name,
                    mnemonic=f"{ins.mnemonic} {ins.operands}",
                    kind="UNRESOLVED",
                    resolved=False,
                    reason=reason,
                )

            # Pattern C: $t9 copied from another register
            if prev.mnemonic in ("or", "addu", "daddu") and prev.rd == target_reg and prev.rt == 0:
                src_reg = prev.rs
                reason = self._classify_register_origin(insns, j, src_reg, func_name)
                return IndirectResolution(
                    vaddr=ins.vaddr,
                    raw_word=ins.word,
                    func_name=func_name,
                    mnemonic=f"{ins.mnemonic} {ins.operands}",
                    kind="UNRESOLVED",
                    resolved=False,
                    reason=reason,
                )

        return IndirectResolution(
            vaddr=ins.vaddr,
            raw_word=ins.word,
            func_name=func_name,
            mnemonic=f"{ins.mnemonic} {ins.operands}",
            kind="UNRESOLVED",
            resolved=False,
            reason=f"Dynamic register target {GPR_NAMES[target_reg]} in {func_name} (not statically constant)",
        )

    def _classify_unresolved_load(
        self, insns: List[Instruction], load_idx: int, load_ins: Instruction, func_name: str
    ) -> str:
        (void_insns, void_idx) = (insns, load_idx)
        base_name = GPR_NAMES[load_ins.rs]
        off = load_ins.simm
        if func_name in ("__sfvwrite_r", "_fclose_r", "__sflush_r", "_fwalk_sglue", "_reclaim_reent"):
            return (
                f"Dynamic newlib FILE/__sFILE virtual I/O callback ({load_ins.mnemonic} "
                f"{GPR_NAMES[load_ins.rt]}, {off}({base_name}) in {func_name})"
            )
        if func_name in ("_close", "_read", "_write", "_fstat", "_lseek"):
            return (
                f"Dynamic ps2sdk fio/device driver operations table callback ({load_ins.mnemonic} "
                f"{GPR_NAMES[load_ins.rt]}, {off}({base_name}) in {func_name})"
            )
        if func_name in ("_raise_r", "__sigtramp_r", "raise", "__sigtramp"):
            return (
                f"Dynamic signal handler table lookup ({load_ins.mnemonic} "
                f"{GPR_NAMES[load_ins.rt]}, {off}({base_name}) in {func_name})"
            )
        if func_name in ("exit", "__call_exitprocs"):
            return (
                f"Dynamic atexit/__atexit handler list callback ({load_ins.mnemonic} "
                f"{GPR_NAMES[load_ins.rt]}, {off}({base_name}) in {func_name})"
            )
        if func_name in ("_request_end", "_SifCmdIntHandler"):
            return (
                f"Dynamic SIF RPC/Cmd completion callback pointer ({load_ins.mnemonic} "
                f"{GPR_NAMES[load_ins.rt]}, {off}({base_name}) in {func_name})"
            )
        if func_name in ("AlarmHandler", "TimerHandler_callback"):
            return (
                f"Dynamic kernel alarm/timer user callback pointer ({load_ins.mnemonic} "
                f"{GPR_NAMES[load_ins.rt]}, {off}({base_name}) in {func_name})"
            )
        if func_name == "__ssvfiscanf_r":
            return (
                f"Dynamic ctype/scanner helper pointer from struct ({load_ins.mnemonic} "
                f"{GPR_NAMES[load_ins.rt]}, {off}({base_name}) in {func_name})"
            )
        if func_name == "__do_global_dtors_aux":
            return (
                f"Mutable .dtors destructor array walk ({load_ins.mnemonic} "
                f"{GPR_NAMES[load_ins.rt]}, {off}({base_name}) in {func_name})"
            )
        return (
            f"Dynamic memory-loaded function pointer ({load_ins.mnemonic} "
            f"{GPR_NAMES[load_ins.rt]}, {off}({base_name}) in {func_name})"
        )

    def _classify_register_origin(
        self, insns: List[Instruction], move_idx: int, src_reg: int, func_name: str
    ) -> str:
        (void_insns, void_idx) = (insns, move_idx)
        if func_name == "_fwalk_sglue":
            return (
                f"Function pointer argument passed in register ($a1 -> {GPR_NAMES[src_reg]} -> $t9 "
                f"in {func_name})"
            )
        if func_name == "exit":
            return (
                f"Indirect call through _reent->_atexit callback pointer ({GPR_NAMES[src_reg]} -> $t9 "
                f"in {func_name})"
            )
        return f"Dynamic register-carried function pointer ({GPR_NAMES[src_reg]} -> $t9 in {func_name})"

    def _try_resolve_jump_table(
        self,
        insns: List[Instruction],
        idx: int,
        func_name: str,
        f_start: int,
        f_end: int,
    ) -> Optional[IndirectResolution]:
        ins = insns[idx]
        bound: Optional[int] = None
        table_base: Optional[int] = None
        spilled_slot: Optional[Tuple[int, int]] = None

        hi_vals: Dict[int, int] = {}
        for j in range(max(0, idx - 18), idx):
            cur = insns[j]
            if cur.mnemonic == "sltiu":
                bound = cur.uimm
            elif cur.mnemonic == "lui":
                hi_vals[cur.rt] = cur.uimm << 16
            elif cur.mnemonic in ("addiu", "daddiu") and cur.rs in hi_vals:
                cand = (hi_vals[cur.rs] + cur.simm) & 0xFFFFFFFF
                if self._in_rodata(cand):
                    table_base = cand
            elif cur.mnemonic in ("lw", "lwu") and cur.rs in (29, 30):
                spilled_slot = (cur.rs, cur.simm)

        if table_base is None and spilled_slot is not None:
            slot_reg, slot_off = spilled_slot
            f_hi: Dict[int, int] = {}
            f_reg_val: Dict[int, int] = {}
            for j in range(0, idx):
                cur = insns[j]
                if cur.mnemonic == "lui":
                    f_hi[cur.rt] = cur.uimm << 16
                elif cur.mnemonic in ("addiu", "daddiu") and cur.rs in f_hi:
                    f_reg_val[cur.rt] = (f_hi[cur.rs] + cur.simm) & 0xFFFFFFFF
                elif cur.mnemonic == "sw" and cur.rs == slot_reg and cur.simm == slot_off:
                    if cur.rt in f_reg_val and self._in_rodata(f_reg_val[cur.rt]):
                        table_base = f_reg_val[cur.rt]
                        break

        if table_base is None or bound is None or bound <= 0 or bound > 512:
            return None

        entries: List[int] = []
        for k in range(bound):
            entry_vaddr = table_base + k * 4
            target = self.elf.read_u32_at_vaddr(entry_vaddr)
            if target is None or not (f_start <= target < f_end) or (target & 3) != 0:
                return None
            entries.append(target)

        uniq_count = len(set(entries))
        return IndirectResolution(
            vaddr=ins.vaddr,
            raw_word=ins.word,
            func_name=func_name,
            mnemonic=f"{ins.mnemonic} {ins.operands}",
            kind="JUMP_TABLE",
            resolved=True,
            jump_table_base=table_base,
            jump_table_entries=entries,
            reason=(
                f"Resolved .rodata jump table at 0x{table_base:08x} "
                f"({len(entries)} slots, {uniq_count} unique labels in {func_name})"
            ),
        )


class LifterM21:
    def __init__(self, elf: Elf32Parser):
        self.elf = elf
        self.text_sec = elf.get_section(".text")
        if not self.text_sec:
            raise ValueError("No .text section found in ELF")
        self.text_vaddr = int(self.text_sec["sh_addr"])
        self.text_offset = int(self.text_sec["sh_offset"])
        self.text_size = int(self.text_sec["sh_size"])
        self.text_end = self.text_vaddr + self.text_size

        rodata_sec = elf.get_section(".rodata")
        if rodata_sec:
            self.rodata_range = (
                int(rodata_sec["sh_addr"]),
                int(rodata_sec["sh_addr"]) + int(rodata_sec["sh_size"]),
            )
        else:
            self.rodata_range = (0, 0)

        self.data_ranges: List[Tuple[str, int, int]] = []
        for sname in (".data", ".sdata", ".rodata", ".ctors", ".dtors"):
            sec = elf.get_section(sname)
            if sec and int(sec["sh_size"]) > 0:
                self.data_ranges.append(
                    (sname, int(sec["sh_addr"]), int(sec["sh_addr"]) + int(sec["sh_size"]))
                )

        self.func_by_vaddr: Dict[int, Dict[str, object]] = {}
        sorted_funcs = sorted(self.elf.functions, key=lambda x: int(x["st_value"]))
        for idx, fn in enumerate(sorted_funcs):
            fv = int(fn["st_value"])
            fsize = int(fn["st_size"])
            next_fv = int(sorted_funcs[idx + 1]["st_value"]) if (idx + 1 < len(sorted_funcs)) else self.text_end
            end_vaddr = max(fv + fsize, next_fv)
            if end_vaddr > self.text_end:
                end_vaddr = self.text_end
            fname = str(fn["name"])
            self.func_by_vaddr[fv] = {
                "name": fname,
                "c_name": c_func_name(fname, fv),
                "vaddr": fv,
                "size": end_vaddr - fv,
                "sym_size": fsize,
            }

        self.indirect_analyzer = IndirectAnalyzer(
            self.elf, self.func_by_vaddr, self.rodata_range, self.data_ranges
        )
        self.indirect_resolutions: Dict[int, IndirectResolution] = {}
        self.blockers: List[BlockerEntry] = []
        self.family_counts: Dict[str, int] = {}
        self.mnemonic_counts: Dict[str, int] = {}
        self.syscalls_found: List[Dict[str, object]] = []
        self.total_instructions: int = 0
        self.lifted_instructions: int = 0

    def decode_all_functions(self) -> Dict[int, List[Instruction]]:
        func_insns: Dict[int, List[Instruction]] = {}
        for fv in sorted(self.func_by_vaddr.keys()):
            fmeta = self.func_by_vaddr[fv]
            fsize = int(fmeta["size"])
            fname = str(fmeta["name"])
            insns: List[Instruction] = []
            for off in range(0, fsize, 4):
                vaddr = fv + off
                raw_off = self.text_offset + (vaddr - self.text_vaddr)
                word = struct.unpack("<I", self.elf.raw[raw_off:raw_off + 4])[0]
                ins = decode_r5900(word, vaddr)
                insns.append(ins)
                self.total_instructions += 1
                self.family_counts[ins.family] = self.family_counts.get(ins.family, 0) + 1
                self.mnemonic_counts[ins.mnemonic] = self.mnemonic_counts.get(ins.mnemonic, 0) + 1

                if not ins.decoded:
                    self.blockers.append(
                        BlockerEntry(
                            vaddr=vaddr,
                            vaddr_hex=f"0x{vaddr:08x}",
                            raw_hex=f"0x{word:08x}",
                            func_name=fname,
                            category="UNLIFTED_INSN",
                            mnemonic=ins.mnemonic,
                            reason=f"Unrecognized opcode/funct in family {ins.family}",
                        )
                    )

            f_end = fv + fsize
            for idx, ins in enumerate(insns):
                if ins.mnemonic == "jalr" or (ins.mnemonic == "jr" and ins.rs != 31):
                    res = self.indirect_analyzer.analyze_site(insns, idx, fname, fv, f_end)
                    self.indirect_resolutions[ins.vaddr] = res
                    if not res.resolved:
                        self.blockers.append(
                            BlockerEntry(
                                vaddr=ins.vaddr,
                                vaddr_hex=f"0x{ins.vaddr:08x}",
                                raw_hex=f"0x{ins.word:08x}",
                                func_name=fname,
                                category="INDIRECT",
                                mnemonic=res.mnemonic,
                                reason=res.reason,
                            )
                        )
                elif ins.is_syscall:
                    sys_num: Optional[int] = None
                    for back in range(idx - 1, max(-1, idx - 5), -1):
                        prev = insns[back]
                        if prev.mnemonic == "addiu" and prev.rt == 3 and prev.rs == 0:
                            sys_num = prev.simm
                            break
                        if prev.mnemonic == "ori" and prev.rt == 3 and prev.rs == 0:
                            sys_num = prev.uimm
                            break
                    abs_num = abs(sys_num) if sys_num is not None else -1
                    base_name = PS2_SYSCALL_TABLE.get(abs_num, f"UnknownSyscall_{abs_num}")
                    if sys_num is not None and sys_num < 0 and not base_name.startswith("i") and not base_name.startswith("_i"):
                        sys_name = f"i{base_name}"
                    else:
                        sys_name = base_name
                    self.syscalls_found.append({
                        "vaddr": f"0x{ins.vaddr:08x}",
                        "func": fname,
                        "raw_num": sys_num,
                        "hex_abs": f"0x{abs_num:02x}" if abs_num >= 0 else "dynamic",
                        "name": sys_name,
                    })

            func_insns[fv] = insns

        self.lifted_instructions = self.total_instructions - len(self.blockers)
        return func_insns

    def _lift_single_non_cf(self, ins: Instruction) -> str:
        """Lifts a single non-control-flow instruction into a C statement."""
        m = ins.mnemonic
        rd, rs, rt, shamt, simm, uimm = ins.rd, ins.rs, ins.rt, ins.shamt, ins.simm, ins.uimm

        if m == "nop" or (rd == 0 and m in (
            "sll", "srl", "sra", "sllv", "srlv", "srav",
            "dsll", "dsrl", "dsra", "dsll32", "dsrl32", "dsra32",
            "dsllv", "dsrlv", "dsrav",
            "add", "addu", "sub", "subu", "and", "or", "xor", "nor",
            "slt", "sltu", "dadd", "daddu", "dsub", "dsubu",
            "movz", "movn", "mfhi", "mflo", "mfhi1", "mflo1", "pmfhl.lw", "pcpyld"
        )):
            return "/* nop / write to $zero */"

        if rt == 0 and m in (
            "addi", "addiu", "slti", "sltiu", "andi", "ori", "xori",
            "daddi", "daddiu", "lui",
            "lb", "lh", "lw", "lbu", "lhu", "lwu", "ld", "lq",
            "lwl", "lwr", "ldl", "ldr", "mfc0"
        ):
            return "/* write to $zero ignored */"

        # Shifts
        if m == "sll":
            return f"ctx->gpr[{rd}].s64[0] = (int64_t)(int32_t)(ctx->gpr[{rt}].u32[0] << {shamt});"
        if m == "srl":
            return f"ctx->gpr[{rd}].s64[0] = (int64_t)(int32_t)(ctx->gpr[{rt}].u32[0] >> {shamt});"
        if m == "sra":
            return f"ctx->gpr[{rd}].s64[0] = (int64_t)(int32_t)(ctx->gpr[{rt}].s32[0] >> {shamt});"
        if m == "sllv":
            return f"ctx->gpr[{rd}].s64[0] = (int64_t)(int32_t)(ctx->gpr[{rt}].u32[0] << (ctx->gpr[{rs}].u32[0] & 0x1Fu));"
        if m == "srlv":
            return f"ctx->gpr[{rd}].s64[0] = (int64_t)(int32_t)(ctx->gpr[{rt}].u32[0] >> (ctx->gpr[{rs}].u32[0] & 0x1Fu));"
        if m == "srav":
            return f"ctx->gpr[{rd}].s64[0] = (int64_t)(int32_t)(ctx->gpr[{rt}].s32[0] >> (ctx->gpr[{rs}].u32[0] & 0x1Fu));"
        if m == "dsll":
            return f"ctx->gpr[{rd}].u64[0] = ctx->gpr[{rt}].u64[0] << {shamt};"
        if m == "dsrl":
            return f"ctx->gpr[{rd}].u64[0] = ctx->gpr[{rt}].u64[0] >> {shamt};"
        if m == "dsra":
            return f"ctx->gpr[{rd}].s64[0] = ctx->gpr[{rt}].s64[0] >> {shamt};"
        if m == "dsll32":
            return f"ctx->gpr[{rd}].u64[0] = ctx->gpr[{rt}].u64[0] << {shamt + 32};"
        if m == "dsrl32":
            return f"ctx->gpr[{rd}].u64[0] = ctx->gpr[{rt}].u64[0] >> {shamt + 32};"
        if m == "dsra32":
            return f"ctx->gpr[{rd}].s64[0] = ctx->gpr[{rt}].s64[0] >> {shamt + 32};"
        if m == "dsllv":
            return f"ctx->gpr[{rd}].u64[0] = ctx->gpr[{rt}].u64[0] << (ctx->gpr[{rs}].u32[0] & 0x3Fu);"
        if m == "dsrlv":
            return f"ctx->gpr[{rd}].u64[0] = ctx->gpr[{rt}].u64[0] >> (ctx->gpr[{rs}].u32[0] & 0x3Fu);"
        if m == "dsrav":
            return f"ctx->gpr[{rd}].s64[0] = ctx->gpr[{rt}].s64[0] >> (ctx->gpr[{rs}].u32[0] & 0x3Fu);"

        # Conditional moves
        if m == "movz":
            return f"if (ctx->gpr[{rt}].u64[0] == 0ULL) {{ ctx->gpr[{rd}].u64[0] = ctx->gpr[{rs}].u64[0]; }}"
        if m == "movn":
            return f"if (ctx->gpr[{rt}].u64[0] != 0ULL) {{ ctx->gpr[{rd}].u64[0] = ctx->gpr[{rs}].u64[0]; }}"

        # Multiply / Divide
        if m == "mfhi":
            return f"ctx->gpr[{rd}].u64[0] = ctx->hi.u64[0];"
        if m == "mflo":
            return f"ctx->gpr[{rd}].u64[0] = ctx->lo.u64[0];"
        if m == "mthi":
            return f"ctx->hi.u64[0] = ctx->gpr[{rs}].u64[0];"
        if m == "mtlo":
            return f"ctx->lo.u64[0] = ctx->gpr[{rs}].u64[0];"
        if m == "mult":
            rd_assign = f" ctx->gpr[{rd}].s64[0] = (int64_t)(int32_t)(uint32_t)_prod;" if rd != 0 else ""
            return (
                f"{{ int64_t _prod = (int64_t)ctx->gpr[{rs}].s32[0] * (int64_t)ctx->gpr[{rt}].s32[0]; "
                f"ctx->lo.s64[0] = (int64_t)(int32_t)(uint32_t)_prod; "
                f"ctx->hi.s64[0] = (int64_t)(int32_t)(uint32_t)((uint64_t)_prod >> 32);{rd_assign} }}"
            )
        if m == "multu":
            rd_assign = f" ctx->gpr[{rd}].s64[0] = (int64_t)(int32_t)(uint32_t)_prod;" if rd != 0 else ""
            return (
                f"{{ uint64_t _prod = (uint64_t)ctx->gpr[{rs}].u32[0] * (uint64_t)ctx->gpr[{rt}].u32[0]; "
                f"ctx->lo.s64[0] = (int64_t)(int32_t)(uint32_t)_prod; "
                f"ctx->hi.s64[0] = (int64_t)(int32_t)(uint32_t)(_prod >> 32);{rd_assign} }}"
            )
        if m == "div":
            return (
                f"if (ctx->gpr[{rt}].s32[0] != 0) {{ "
                f"if (ctx->gpr[{rs}].u32[0] == 0x80000000u && ctx->gpr[{rt}].s32[0] == -1) {{ "
                f"ctx->lo.s64[0] = (int64_t)(int32_t)0x80000000u; ctx->hi.s64[0] = 0; "
                f"}} else {{ "
                f"ctx->lo.s64[0] = (int64_t)(ctx->gpr[{rs}].s32[0] / ctx->gpr[{rt}].s32[0]); "
                f"ctx->hi.s64[0] = (int64_t)(ctx->gpr[{rs}].s32[0] % ctx->gpr[{rt}].s32[0]); "
                f"}} }}"
            )
        if m == "divu":
            return (
                f"if (ctx->gpr[{rt}].u32[0] != 0u) {{ "
                f"ctx->lo.s64[0] = (int64_t)(int32_t)(ctx->gpr[{rs}].u32[0] / ctx->gpr[{rt}].u32[0]); "
                f"ctx->hi.s64[0] = (int64_t)(int32_t)(ctx->gpr[{rs}].u32[0] % ctx->gpr[{rt}].u32[0]); "
                f"}}"
            )

        # R5900 MMI instructions (pcpyld in hello_kernel_min.elf; madd & pmfhl.lw in hello_real.elf)
        if m == "pcpyld":
            return (
                f"{{ uint64_t __lo = ctx->gpr[{rt}].u64[0]; "
                f"uint64_t __hi = ctx->gpr[{rs}].u64[0]; "
                f"ctx->gpr[{rd}].u64[0] = __lo; ctx->gpr[{rd}].u64[1] = __hi; }}"
            )
        if m == "madd":
            rd_assign = f" ctx->gpr[{rd}].s64[0] = (int64_t)(int32_t)(uint32_t)_acc;" if rd != 0 else ""
            return (
                f"{{ int64_t _acc = (int64_t)(((uint64_t)ctx->hi.u32[0] << 32) | (uint64_t)ctx->lo.u32[0]) "
                f"+ (int64_t)ctx->gpr[{rs}].s32[0] * (int64_t)ctx->gpr[{rt}].s32[0]; "
                f"ctx->lo.s64[0] = (int64_t)(int32_t)(uint32_t)_acc; "
                f"ctx->hi.s64[0] = (int64_t)(int32_t)(uint32_t)((uint64_t)_acc >> 32);{rd_assign} }}"
            )
        if m == "maddu":
            rd_assign = f" ctx->gpr[{rd}].s64[0] = (int64_t)(int32_t)(uint32_t)_acc;" if rd != 0 else ""
            return (
                f"{{ uint64_t _acc = (((uint64_t)ctx->hi.u32[0] << 32) | (uint64_t)ctx->lo.u32[0]) "
                f"+ (uint64_t)ctx->gpr[{rs}].u32[0] * (uint64_t)ctx->gpr[{rt}].u32[0]; "
                f"ctx->lo.s64[0] = (int64_t)(int32_t)(uint32_t)_acc; "
                f"ctx->hi.s64[0] = (int64_t)(int32_t)(uint32_t)(_acc >> 32);{rd_assign} }}"
            )
        if m == "pmfhl.lw":
            return (
                f"ctx->gpr[{rd}].u32[0] = ctx->lo.u32[0]; "
                f"ctx->gpr[{rd}].u32[1] = ctx->hi.u32[0]; "
                f"ctx->gpr[{rd}].u32[2] = ctx->lo.u32[2]; "
                f"ctx->gpr[{rd}].u32[3] = ctx->hi.u32[2];"
            )
        if m == "mfhi1":
            return f"ctx->gpr[{rd}].u64[0] = ctx->hi.u64[1];"
        if m == "mflo1":
            return f"ctx->gpr[{rd}].u64[0] = ctx->lo.u64[1];"
        if m == "mthi1":
            return f"ctx->hi.u64[1] = ctx->gpr[{rs}].u64[0];"
        if m == "mtlo1":
            return f"ctx->lo.u64[1] = ctx->gpr[{rs}].u64[0];"

        # Register ALU
        if m in ("add", "addu"):
            return f"ctx->gpr[{rd}].s64[0] = (int64_t)(int32_t)(ctx->gpr[{rs}].u32[0] + ctx->gpr[{rt}].u32[0]);"
        if m in ("sub", "subu"):
            return f"ctx->gpr[{rd}].s64[0] = (int64_t)(int32_t)(ctx->gpr[{rs}].u32[0] - ctx->gpr[{rt}].u32[0]);"
        if m in ("dadd", "daddu"):
            return f"ctx->gpr[{rd}].u64[0] = ctx->gpr[{rs}].u64[0] + ctx->gpr[{rt}].u64[0];"
        if m in ("dsub", "dsubu"):
            return f"ctx->gpr[{rd}].u64[0] = ctx->gpr[{rs}].u64[0] - ctx->gpr[{rt}].u64[0];"
        if m == "and":
            return f"ctx->gpr[{rd}].u64[0] = ctx->gpr[{rs}].u64[0] & ctx->gpr[{rt}].u64[0];"
        if m == "or":
            return f"ctx->gpr[{rd}].u64[0] = ctx->gpr[{rs}].u64[0] | ctx->gpr[{rt}].u64[0];"
        if m == "xor":
            return f"ctx->gpr[{rd}].u64[0] = ctx->gpr[{rs}].u64[0] ^ ctx->gpr[{rt}].u64[0];"
        if m == "nor":
            return f"ctx->gpr[{rd}].u64[0] = ~(ctx->gpr[{rs}].u64[0] | ctx->gpr[{rt}].u64[0]);"
        if m == "slt":
            return f"ctx->gpr[{rd}].u64[0] = (ctx->gpr[{rs}].s64[0] < ctx->gpr[{rt}].s64[0]) ? 1ULL : 0ULL;"
        if m == "sltu":
            return f"ctx->gpr[{rd}].u64[0] = (ctx->gpr[{rs}].u64[0] < ctx->gpr[{rt}].u64[0]) ? 1ULL : 0ULL;"

        # Immediate ALU
        if m in ("addi", "addiu"):
            return f"ctx->gpr[{rt}].s64[0] = (int64_t)(int32_t)(ctx->gpr[{rs}].u32[0] + (uint32_t)({simm}));"
        if m in ("daddi", "daddiu"):
            return f"ctx->gpr[{rt}].u64[0] = ctx->gpr[{rs}].u64[0] + (uint64_t)(int64_t)({simm});"
        if m == "slti":
            return f"ctx->gpr[{rt}].u64[0] = (ctx->gpr[{rs}].s64[0] < (int64_t)({simm})) ? 1ULL : 0ULL;"
        if m == "sltiu":
            return f"ctx->gpr[{rt}].u64[0] = (ctx->gpr[{rs}].u64[0] < (uint64_t)(int64_t)({simm})) ? 1ULL : 0ULL;"
        if m == "andi":
            return f"ctx->gpr[{rt}].u64[0] = ctx->gpr[{rs}].u64[0] & 0x{uimm:04x}ULL;"
        if m == "ori":
            return f"ctx->gpr[{rt}].u64[0] = ctx->gpr[{rs}].u64[0] | 0x{uimm:04x}ULL;"
        if m == "xori":
            return f"ctx->gpr[{rt}].u64[0] = ctx->gpr[{rs}].u64[0] ^ 0x{uimm:04x}ULL;"
        if m == "lui":
            val32 = (uimm << 16) & 0xFFFFFFFF
            return f"ctx->gpr[{rt}].s64[0] = (int64_t)(int32_t)0x{val32:08x}u;"

        # Memory loads & stores (including $gp-relative .sdata and 128-bit LQ/SQ)
        addr_expr = f"(ctx->gpr[{rs}].u32[0] + (uint32_t)({simm}))"
        if m == "lb":
            return f"ctx->gpr[{rt}].s64[0] = (int64_t)ps2_mem_read_s8(ctx, {addr_expr});"
        if m == "lbu":
            return f"ctx->gpr[{rt}].u64[0] = (uint64_t)ps2_mem_read8(ctx, {addr_expr});"
        if m == "lh":
            return f"ctx->gpr[{rt}].s64[0] = (int64_t)ps2_mem_read_s16(ctx, {addr_expr});"
        if m == "lhu":
            return f"ctx->gpr[{rt}].u64[0] = (uint64_t)ps2_mem_read16(ctx, {addr_expr});"
        if m == "lw":
            return f"ctx->gpr[{rt}].s64[0] = (int64_t)ps2_mem_read_s32(ctx, {addr_expr});"
        if m == "lwu":
            return f"ctx->gpr[{rt}].u64[0] = (uint64_t)ps2_mem_read32(ctx, {addr_expr});"
        if m == "ld":
            return f"ctx->gpr[{rt}].u64[0] = ps2_mem_read64(ctx, {addr_expr});"
        if m == "lq":
            return f"ctx->gpr[{rt}] = ps2_mem_read128(ctx, {addr_expr});"

        if m == "sb":
            return f"ps2_mem_write8(ctx, {addr_expr}, (uint8_t)ctx->gpr[{rt}].u32[0]);"
        if m == "sh":
            return f"ps2_mem_write16(ctx, {addr_expr}, (uint16_t)ctx->gpr[{rt}].u32[0]);"
        if m == "sw":
            return f"ps2_mem_write32(ctx, {addr_expr}, ctx->gpr[{rt}].u32[0]);"
        if m == "sd":
            return f"ps2_mem_write64(ctx, {addr_expr}, ctx->gpr[{rt}].u64[0]);"
        if m == "sq":
            return f"ps2_mem_write128(ctx, {addr_expr}, ctx->gpr[{rt}]);"

        # Unaligned loads & stores
        if m == "lwl":
            return f"ctx->gpr[{rt}].s64[0] = ps2_mem_lwl(ctx, {addr_expr}, ctx->gpr[{rt}].u64[0]);"
        if m == "lwr":
            return f"ctx->gpr[{rt}].s64[0] = ps2_mem_lwr(ctx, {addr_expr}, ctx->gpr[{rt}].u64[0]);"
        if m == "swl":
            return f"ps2_mem_swl(ctx, {addr_expr}, ctx->gpr[{rt}].u32[0]);"
        if m == "swr":
            return f"ps2_mem_swr(ctx, {addr_expr}, ctx->gpr[{rt}].u32[0]);"
        if m == "ldl":
            return f"ctx->gpr[{rt}].u64[0] = ps2_mem_ldl(ctx, {addr_expr}, ctx->gpr[{rt}].u64[0]);"
        if m == "ldr":
            return f"ctx->gpr[{rt}].u64[0] = ps2_mem_ldr(ctx, {addr_expr}, ctx->gpr[{rt}].u64[0]);"
        if m == "sdl":
            return f"ps2_mem_sdl(ctx, {addr_expr}, ctx->gpr[{rt}].u64[0]);"
        if m == "sdr":
            return f"ps2_mem_sdr(ctx, {addr_expr}, ctx->gpr[{rt}].u64[0]);"

        # Exotic families (Milestone 2.1 Item 3: COP0, CACHE, SYNC, TRAP)
        if m == "mfc0":
            return f"ctx->gpr[{rt}].s64[0] = ps2_cop0_mfc0(ctx, {rd}u);"
        if m == "mtc0":
            return f"ps2_cop0_mtc0(ctx, {rd}u, ctx->gpr[{rt}].u32[0]);"
        if m == "ei":
            return "ps2_cop0_ei(ctx);"
        if m == "di":
            return "ps2_cop0_di(ctx);"
        if m == "cache":
            return f"ps2_cache_op(ctx, 0x{rt:02x}u, {addr_expr});"
        if m in ("sync.l", "sync.p"):
            return f"ps2_sync_barrier(ctx, 0x{shamt:x}u);"
        if m == "teq":
            code = (ins.word >> 6) & 0x3FF
            return f"ps2_trap_eq(ctx, 0x{ins.vaddr:08x}u, ctx->gpr[{rs}].s64[0], ctx->gpr[{rt}].s64[0], 0x{code:x}u);"
        if m == "break":
            return f"ps2_trap_eq(ctx, 0x{ins.vaddr:08x}u, 0, 0, 0xFFFFu);"

        if m == "syscall":
            return f"ps2_syscall_dispatch(ctx, 0x{ins.vaddr:08x}u); if (ctx->halted) return;"

        # Robustness Law fallback (Item 2): never crash on an unlifted instruction
        return f"ps2_indirect_dispatch(ctx, 0x{ins.vaddr:08x}u, 0u, 0, \"UNLIFTED_INSN_{m}\");"

    def _branch_cond_expr(self, ins: Instruction, rs_var: str, rt_var: str) -> str:
        m = ins.mnemonic
        if m in ("beq", "beql"):
            return f"({rs_var} == {rt_var})"
        if m in ("bne", "bnel"):
            return f"({rs_var} != {rt_var})"
        if m in ("blez", "blezl"):
            return f"((int64_t){rs_var} <= 0)"
        if m in ("bgtz", "bgtzl"):
            return f"((int64_t){rs_var} > 0)"
        if m in ("bltz", "bltzl", "bltzal", "bltzall"):
            return f"((int64_t){rs_var} < 0)"
        if m in ("bgez", "bgezl", "bgezal", "bgezall"):
            return f"((int64_t){rs_var} >= 0)"
        raise ValueError(f"Unknown branch mnemonic: {m}")

    def emit_function_c(self, fv: int, insns: List[Instruction]) -> List[str]:
        fmeta = self.func_by_vaddr[fv]
        fname = str(fmeta["name"])
        cname = str(fmeta["c_name"])
        fsize = int(fmeta["size"])
        fend = fv + fsize

        # Collect ONLY intra-function branch/jump/jump-table target addresses that are actually used
        insn_addrs: Set[int] = {ins.vaddr for ins in insns}
        labels: Set[int] = set()
        for ins in insns:
            if (ins.is_branch or ins.mnemonic in ("j", "jal")) and ins.target_vaddr is not None:
                if (fv <= ins.target_vaddr < fend) and (ins.target_vaddr not in self.func_by_vaddr or ins.mnemonic != "jal"):
                    if ins.target_vaddr in insn_addrs:
                        labels.add(ins.target_vaddr)
            res = self.indirect_resolutions.get(ins.vaddr)
            if res and res.kind == "JUMP_TABLE" and res.jump_table_entries:
                for t_addr in res.jump_table_entries:
                    if fv <= t_addr < fend and t_addr in insn_addrs:
                        labels.add(t_addr)

        lines: List[str] = []
        lines.append(f"/* Function: {fname} @ 0x{fv:08x} - 0x{fend:08x} ({len(insns)} insns) */")
        lines.append(f"void {cname}(ps2_cpu_ctx_t *ctx) {{")
        lines.append("    (void)ctx;")

        i = 0
        n = len(insns)
        while i < n:
            ins = insns[i]
            if ins.vaddr in labels:
                lines.append(f"L_{ins.vaddr:08x}:;")

            if ins.has_delay_slot:
                has_intra_ds = (i + 1) < n
                ds_ins = insns[i + 1] if has_intra_ds else Instruction(ins.vaddr + 4, 0, "nop", "", "NOP", True)
                ds_stmt = self._lift_single_non_cf(ds_ins)
                ds_has_label = has_intra_ds and (ds_ins.vaddr in labels)

                lines.append(
                    f"    /* 0x{ins.vaddr:08x}: 0x{ins.word:08x}  {ins.mnemonic} {ins.operands} "
                    f"| DS 0x{ds_ins.vaddr:08x}: {ds_ins.mnemonic} {ds_ins.operands} */"
                )
                lines.append(f"    ps2_step_pc(ctx, 0x{ins.vaddr:08x}u, {2 if has_intra_ds else 1}u); if (ctx->halted) return;")

                if ins.is_branch:
                    rs_var = f"_br_rs_{ins.vaddr:08x}"
                    rt_var = f"_br_rt_{ins.vaddr:08x}"
                    lines.append(f"    uint64_t {rs_var} = ctx->gpr[{ins.rs}].u64[0];")
                    if ins.mnemonic in ("beq", "bne", "beql", "bnel"):
                        lines.append(f"    uint64_t {rt_var} = ctx->gpr[{ins.rt}].u64[0];")
                    if ins.is_call:
                        lines.append(f"    ctx->gpr[31].s64[0] = (int64_t)(int32_t)0x{ins.vaddr + 8:08x}u;")

                    cond = self._branch_cond_expr(ins, rs_var, rt_var)
                    t_vaddr = ins.target_vaddr or 0
                    if fv <= t_vaddr < fend and t_vaddr in insn_addrs:
                        jump_stmt = f"goto L_{t_vaddr:08x};"
                    elif t_vaddr in self.func_by_vaddr:
                        tcname = str(self.func_by_vaddr[t_vaddr]["c_name"])
                        jump_stmt = f"{tcname}(ctx); return;"
                    else:
                        jump_stmt = (
                            f"ps2_indirect_dispatch(ctx, 0x{ins.vaddr:08x}u, 0x{t_vaddr:08x}u, 0, "
                            f"\"OUT_OF_RANGE_BRANCH\"); return;"
                        )

                    if ins.is_branch_likely:
                        lines.append(f"    if ({cond}) {{")
                        lines.append(f"        {ds_stmt}")
                        lines.append(f"        {jump_stmt}")
                        lines.append("    }")
                        if ds_has_label:
                            lines.append(f"    goto L_{ds_ins.vaddr + 4:08x}_after_ds;")
                            lines.append(f"L_{ds_ins.vaddr:08x}:;")
                            lines.append(f"    ps2_step_pc(ctx, 0x{ds_ins.vaddr:08x}u, 1u); if (ctx->halted) return; {ds_stmt}")
                            lines.append(f"L_{ds_ins.vaddr + 4:08x}_after_ds:;")
                    else:
                        if ds_has_label:
                            lines.append(f"    if ({cond}) {{")
                            lines.append(f"        {ds_stmt}")
                            lines.append(f"        {jump_stmt}")
                            lines.append("    }")
                            lines.append(f"L_{ds_ins.vaddr:08x}:;")
                            lines.append(f"    {ds_stmt}")
                        else:
                            lines.append(f"    {ds_stmt}")
                            lines.append(f"    if ({cond}) {{ {jump_stmt} }}")

                elif ins.mnemonic == "jal":
                    t_vaddr = ins.target_vaddr or 0
                    lines.append(f"    {ds_stmt}")
                    lines.append(f"    ctx->gpr[31].s64[0] = (int64_t)(int32_t)0x{ins.vaddr + 8:08x}u;")
                    if t_vaddr == 0:
                        lines.append(f"    ps2_null_weak_call_trap(ctx, 0x{ins.vaddr:08x}u);")
                    elif t_vaddr in self.func_by_vaddr:
                        tcname = str(self.func_by_vaddr[t_vaddr]["c_name"])
                        lines.append(f"    {tcname}(ctx);")
                        lines.append("    if (ctx->halted) return;")
                    elif fv <= t_vaddr < fend and t_vaddr in insn_addrs:
                        lines.append(f"    goto L_{t_vaddr:08x};")
                    else:
                        lines.append(
                            f"    ps2_indirect_dispatch(ctx, 0x{ins.vaddr:08x}u, 0x{t_vaddr:08x}u, 1, "
                            f"\"UNMAPPED_DIRECT_JAL\");"
                        )

                elif ins.mnemonic == "j":
                    t_vaddr = ins.target_vaddr or 0
                    lines.append(f"    {ds_stmt}")
                    if t_vaddr == 0:
                        lines.append(f"    ps2_null_weak_call_trap(ctx, 0x{ins.vaddr:08x}u); return;")
                    elif fv <= t_vaddr < fend and t_vaddr in insn_addrs:
                        lines.append(f"    goto L_{t_vaddr:08x};")
                    elif t_vaddr in self.func_by_vaddr:
                        tcname = str(self.func_by_vaddr[t_vaddr]["c_name"])
                        lines.append(f"    {tcname}(ctx); return;")
                    else:
                        lines.append(
                            f"    ps2_indirect_dispatch(ctx, 0x{ins.vaddr:08x}u, 0x{t_vaddr:08x}u, 0, "
                            f"\"UNMAPPED_DIRECT_J\"); return;"
                        )

                elif ins.mnemonic == "jr" and ins.rs == 31:
                    lines.append(f"    {ds_stmt}")
                    lines.append("    return;")

                elif ins.mnemonic == "jalr" or (ins.mnemonic == "jr" and ins.rs != 31):
                    tgt_var = f"_ind_tgt_{ins.vaddr:08x}"
                    lines.append(f"    uint32_t {tgt_var} = ctx->gpr[{ins.rs}].u32[0];")
                    lines.append(f"    (void){tgt_var};")
                    lines.append(f"    {ds_stmt}")
                    if ins.mnemonic == "jalr" and ins.rd != 0:
                        lines.append(f"    ctx->gpr[{ins.rd}].s64[0] = (int64_t)(int32_t)0x{ins.vaddr + 8:08x}u;")

                    res = self.indirect_resolutions.get(ins.vaddr)
                    is_call_int = 1 if ins.mnemonic == "jalr" else 0

                    if res and res.resolved:
                        if res.kind == "JUMP_TABLE" and res.jump_table_entries:
                            lines.append(f"    /* Statically resolved .rodata jump table @ 0x{res.jump_table_base:08x} */")
                            lines.append(f"    switch ({tgt_var}) {{")
                            for u_target in sorted(set(res.jump_table_entries)):
                                lines.append(f"        case 0x{u_target:08x}u: goto L_{u_target:08x};")
                            lines.append(
                                f"        default: ps2_indirect_dispatch(ctx, 0x{ins.vaddr:08x}u, {tgt_var}, 0, "
                                f"\"JUMP_TABLE_OUT_OF_BOUNDS\"); return;"
                            )
                            lines.append("    }")
                        elif res.kind == "CONST_LUI_ADDIU":
                            if res.target_vaddr == 0:
                                lines.append(f"    /* Statically resolved weak NULL target @ 0x{ins.vaddr:08x} */")
                                lines.append(f"    ps2_null_weak_call_trap(ctx, 0x{ins.vaddr:08x}u);")
                                if not ins.is_call:
                                    lines.append("    return;")
                            else:
                                lines.append(f"    /* Statically resolved constant $t9 -> {res.target_name} (0x{res.target_vaddr:08x}) */")
                                lines.append(f"    {res.target_name}(ctx);")
                                if ins.is_call:
                                    lines.append("    if (ctx->halted) return;")
                                else:
                                    lines.append("    return;")
                        elif res.kind == "STATIC_DATA_PTR":
                            lines.append(
                                f"    /* Statically resolved initial pointer @ 0x{res.data_ptr_vaddr:08x} "
                                f"-> {res.target_name} (0x{res.target_vaddr:08x}) */"
                            )
                            lines.append(f"    if ({tgt_var} == 0x{res.target_vaddr:08x}u) {{")
                            lines.append(f"        {res.target_name}(ctx);")
                            lines.append("    } else {")
                            c_reason = res.reason.replace('"', "'")
                            lines.append(
                                f"        ps2_indirect_dispatch(ctx, 0x{ins.vaddr:08x}u, {tgt_var}, {is_call_int}, \"{c_reason}\");"
                            )
                            lines.append("    }")
                            if ins.is_call:
                                lines.append("    if (ctx->halted) return;")
                            else:
                                lines.append("    return;")
                    else:
                        c_reason = (res.reason if res else "Unresolved indirect target").replace('"', "'")
                        lines.append(
                            f"    /* [BLOCKER:INDIRECT] 0x{ins.vaddr:08x} (0x{ins.word:08x}): {c_reason} */"
                        )
                        lines.append(
                            f"    ps2_indirect_dispatch(ctx, 0x{ins.vaddr:08x}u, {tgt_var}, {is_call_int}, \"{c_reason}\");"
                        )
                        if ins.is_call:
                            lines.append("    if (ctx->halted) return;")
                        else:
                            lines.append("    return;")

                i += 2 if has_intra_ds else 1
                continue

            stmt = self._lift_single_non_cf(ins)
            lines.append(f"    /* 0x{ins.vaddr:08x}: 0x{ins.word:08x}  {ins.mnemonic} {ins.operands} */")
            lines.append(f"    ps2_step_pc(ctx, 0x{ins.vaddr:08x}u, 1u); if (ctx->halted) return; {stmt}")
            i += 1

        lines.append("}")
        lines.append("")
        return lines

    def emit_c_files(self, h_path: str, c_path: str) -> Tuple[str, str]:
        os.makedirs(os.path.dirname(os.path.abspath(h_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(c_path)), exist_ok=True)

        func_insns = self.decode_all_functions()
        entry_vaddr = int(self.elf.header["e_entry"])
        entry_cname = (
            str(self.func_by_vaddr[entry_vaddr]["c_name"])
            if entry_vaddr in self.func_by_vaddr
            else str(self.func_by_vaddr[sorted(self.func_by_vaddr.keys())[0]]["c_name"])
        )
        h_basename = os.path.basename(h_path)
        guard_macro = sanitize_c_ident(h_basename.upper())

        # 1. Write Header (.h)
        h_lines: List[str] = [
            f"/* Auto-generated by ps2_lifter_m2.py v{LIFTER_VERSION} from {os.path.basename(self.elf.path)} */",
            f"/* Input ELF SHA-256: {self.elf.sha256} */",
            f"#ifndef {guard_macro}",
            f"#define {guard_macro}",
            "",
            '#include "ps2_runtime.h"',
            "",
            "#ifdef __cplusplus",
            'extern "C" {',
            "#endif",
            "",
            f"#define PS2_LIFTED_ENTRY_VADDR 0x{entry_vaddr:08x}u",
            f"#define PS2_LIFTED_GP_VALUE    0x{self.elf.gp_value:08x}u",
            "",
            "int  ps2_init_guest_memory(ps2_cpu_ctx_t *ctx);",
            "int  ps2_load_embedded_hello_kernel_min(ps2_cpu_ctx_t *ctx);",
            "void ps2_entry(ps2_cpu_ctx_t *ctx);",
            "",
        ]
        for fv in sorted(self.func_by_vaddr.keys()):
            cname = str(self.func_by_vaddr[fv]["c_name"])
            h_lines.append(f"void {cname}(ps2_cpu_ctx_t *ctx);")
        h_lines += [
            "",
            "#ifdef __cplusplus",
            "}",
            "#endif",
            "",
            f"#endif /* {guard_macro} */",
            "",
        ]
        with open(h_path, "w", encoding="utf-8") as f:
            f.write("\n".join(h_lines))

        # 2. Write Implementation (.c) including PT_LOAD Guest Memory Image (Item 4)
        c_lines: List[str] = [
            f"/* Auto-generated by ps2_lifter_m2.py v{LIFTER_VERSION} from {os.path.basename(self.elf.path)} */",
            f"/* Input ELF SHA-256: {self.elf.sha256} */",
            f'#include "{h_basename}"',
            "",
            "/* ==========================================================================",
            " * Milestone 2.1 Item 4: Embedded Guest Memory Image (PT_LOAD Segments)",
            " * ========================================================================== */",
        ]

        pt_load_descs: List[str] = []
        for p in self.elf.phdrs:
            if p["p_type"] != 1 or p["p_memsz"] == 0:
                continue
            idx = p["index"]
            pv = p["p_vaddr"]
            pf = p["p_filesz"]
            pm = p["p_memsz"]
            pflags = p["p_flags"]
            poff = p["p_offset"]
            arr_name = f"k_pt_load_seg_{idx}"
            if pf > 0:
                seg_bytes = self.elf.raw[poff:poff + pf]
                c_lines.append(
                    f"/* PT_LOAD[{idx}]: vaddr=0x{pv:08x}, filesz=0x{pf:x} ({pf} bytes), memsz=0x{pm:x} ({pm} bytes) */"
                )
                c_lines.append(f"static const uint8_t {arr_name}[{pf}] = {{")
                for row_start in range(0, pf, 16):
                    chunk = seg_bytes[row_start:row_start + 16]
                    hex_row = ", ".join(f"0x{b:02x}" for b in chunk)
                    c_lines.append(f"    {hex_row},")
                c_lines.append("};")
                c_lines.append("")
                pt_load_descs.append(
                    f"    {{ 0x{pv:08x}u, 0x{pm:08x}u, 0x{pf:08x}u, 0x{pflags:x}u, {arr_name} }}"
                )
            else:
                pt_load_descs.append(
                    f"    {{ 0x{pv:08x}u, 0x{pm:08x}u, 0u, 0x{pflags:x}u, NULL }}"
                )

        c_lines.append("static const ps2_pt_load_seg_t k_pt_load_segments[] = {")
        c_lines.append(",\n".join(pt_load_descs))
        c_lines.append("};")
        c_lines.append("")

        c_lines.append("/* ==========================================================================")
        c_lines.append(" * Milestone 2.1 Item 1: Runtime Indirect Function Dispatch Table")
        c_lines.append(" * ========================================================================== */")
        c_lines.append(f"static const ps2_indirect_entry_t k_indirect_dispatch_table[{len(self.func_by_vaddr)}] = {{")
        for fv in sorted(self.func_by_vaddr.keys()):
            fmeta = self.func_by_vaddr[fv]
            c_lines.append(f'    {{ 0x{fv:08x}u, "{fmeta["name"]}", {fmeta["c_name"]} }},')
        c_lines.append("};")
        c_lines.append("")

        c_lines.append("int ps2_init_guest_memory(ps2_cpu_ctx_t *ctx) {")
        c_lines.append(
            f"    int rc = ps2_load_pt_segments(ctx, k_pt_load_segments, {len(pt_load_descs)}u);"
        )
        c_lines.append("    if (rc != 0) return rc;")
        c_lines.append(
            f"    ps2_register_indirect_table(ctx, k_indirect_dispatch_table, {len(self.func_by_vaddr)}u);"
        )
        if self.elf.gp_value != 0:
            c_lines.append(
                f"    ctx->gpr[28].s64[0] = (int64_t)(int32_t)0x{self.elf.gp_value:08x}u; /* Initial $gp */"
            )
        c_lines.append(f"    ctx->pc = 0x{entry_vaddr:08x}u;")
        c_lines.append("    return 0;")
        c_lines.append("}")
        c_lines.append("")
        c_lines.append("int ps2_load_embedded_hello_kernel_min(ps2_cpu_ctx_t *ctx) {")
        c_lines.append("    return ps2_init_guest_memory(ctx);")
        c_lines.append("}")
        c_lines.append("")

        for fv in sorted(self.func_by_vaddr.keys()):
            c_lines.extend(self.emit_function_c(fv, func_insns[fv]))

        c_lines.extend([
            "void ps2_entry(ps2_cpu_ctx_t *ctx) {",
            "    if (ctx->indirect_table == NULL) {",
            "        (void)ps2_init_guest_memory(ctx);",
            "    }",
            f"    ctx->pc = 0x{entry_vaddr:08x}u;",
            f"    {entry_cname}(ctx);",
            "}",
            "",
        ])

        with open(c_path, "w", encoding="utf-8") as f:
            f.write("\n".join(c_lines))

        return h_path, c_path

    def build_report_dict(self) -> Dict[str, object]:
        resolved_list = [
            dataclasses.asdict(r) for r in sorted(self.indirect_resolutions.values(), key=lambda x: x.vaddr)
            if r.resolved
        ]
        unresolved_list = [
            dataclasses.asdict(r) for r in sorted(self.indirect_resolutions.values(), key=lambda x: x.vaddr)
            if not r.resolved
        ]
        resolved_by_kind: Dict[str, int] = {}
        for r in self.indirect_resolutions.values():
            if r.resolved:
                resolved_by_kind[r.kind] = resolved_by_kind.get(r.kind, 0) + 1

        blocker_by_cat: Dict[str, int] = {}
        for b in self.blockers:
            blocker_by_cat[b.category] = blocker_by_cat.get(b.category, 0) + 1

        pct = (self.lifted_instructions / self.total_instructions * 100.0) if self.total_instructions else 0.0
        status = "FULL_SUCCESS" if len(self.blockers) == 0 else "COMPLETED_WITH_BLOCKERS"

        return {
            "lifter_version": LIFTER_VERSION,
            "status": status,
            "input_file": os.path.basename(self.elf.path),
            "input_sha256": self.elf.sha256,
            "input_size_bytes": self.elf.size_bytes,
            "entry_point": f"0x{self.elf.header['e_entry']:08x}",
            "gp_value": f"0x{self.elf.gp_value:08x}",
            "flags": f"0x{self.elf.header['e_flags']:08x}",
            "functions_count": len(self.func_by_vaddr),
            "total_instructions": self.total_instructions,
            "lifted_instructions": self.lifted_instructions,
            "blockers_count": len(self.blockers),
            "lift_coverage_percent": round(pct, 2),
            "blocker_categories": blocker_by_cat,
            "indirect_summary": {
                "total_indirect_sites": len(self.indirect_resolutions),
                "statically_resolved_count": len(resolved_list),
                "declared_indirect_blockers_count": len(unresolved_list),
                "resolved_by_kind": resolved_by_kind,
            },
            "family_counts": self.family_counts,
            "mnemonic_counts": self.mnemonic_counts,
            "syscalls_detected_count": len(self.syscalls_found),
            "syscalls_detected": self.syscalls_found,
            "statically_resolved_indirect_sites": resolved_list,
            "blockers": [dataclasses.asdict(b) for b in self.blockers],
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PS2 R5900 Static Lifter - Milestone 2.1 (ps2_lifter_m2.py)"
    )
    parser.add_argument("elf_path", help="Path to input PS2 ELF32 binary")
    parser.add_argument("--out-h", default=None, help="Output C header path")
    parser.add_argument("--out-c", default=None, help="Output C source path")
    parser.add_argument("--report-json", default=None, help="Output JSON report path")
    parser.add_argument("--out-dir", default=".", help="Directory for generated C/H files (when --out-h/--out-c not set)")
    parser.add_argument("--prefix", default="lifted_hello_kernel_min", help="Filename prefix (when --out-h/--out-c not set)")
    parser.add_argument("--json-out", default=None, help="Alias for --report-json")
    args = parser.parse_args()

    h_path = args.out_h if args.out_h else os.path.join(args.out_dir, f"{args.prefix}.h")
    c_path = args.out_c if args.out_c else os.path.join(args.out_dir, f"{args.prefix}.c")
    json_path = args.report_json if args.report_json else args.json_out

    try:
        elf = Elf32Parser(args.elf_path)
        lifter = LifterM21(elf)
        h_path, c_path = lifter.emit_c_files(h_path, c_path)
        report = lifter.build_report_dict()
    except Exception as exc:
        print(f"[PS2-LIFTER-M2.1] STRUCTURAL ERROR reading/parsing ELF: {exc}", file=sys.stderr)
        return 1

    if json_path:
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(report, jf, indent=2, ensure_ascii=False)

    ind = report["indirect_summary"]
    print("======================================================================")
    print(f"PS2 Static Lifter v{LIFTER_VERSION} — Lift & Blocker Summary")
    print("======================================================================")
    print(f"Input ELF         : {report['input_file']} ({report['input_size_bytes']} bytes)")
    print(f"SHA-256           : {report['input_sha256']}")
    print(f"Entry / Initial GP: {report['entry_point']} / {report['gp_value']}")
    print(f"Functions Lifted  : {report['functions_count']}")
    print(
        f"Instructions      : {report['lifted_instructions']} / {report['total_instructions']} "
        f"({report['lift_coverage_percent']:.2f}%)"
    )
    print(f"Blockers Count    : {report['blockers_count']} {report['blocker_categories']}")
    print(
        f"Indirect Sites    : {ind['total_indirect_sites']} total -> "
        f"{ind['statically_resolved_count']} resolved {ind['resolved_by_kind']}, "
        f"{ind['declared_indirect_blockers_count']} declared INDIRECT blockers"
    )
    print(f"Syscalls Mapped   : {report['syscalls_detected_count']}")
    print(f"Generated C Files : {h_path}, {c_path}")
    print(f"Status            : {report['status']}")
    print("======================================================================")

    return 0 if report["blockers_count"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
