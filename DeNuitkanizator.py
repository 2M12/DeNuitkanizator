#!/usr/bin/env python3
import sys
import os
import io
import re
import struct
import marshal
import types
import zlib
import logging
import hashlib
import datetime
import shutil
import math
import string
import json
import urllib.request
import urllib.error
from pathlib import Path
from collections import Counter, deque, OrderedDict

try:
    import pefile
except ImportError:
    print("FATAL: pefile not installed. Run: pip install pefile")
    sys.exit(1)

try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM, X86_OP_INVALID
except ImportError:
    capstone = None
    Cs = None
    CS_ARCH_X86 = None
    CS_MODE_32 = None
    CS_MODE_64 = None
    X86_OP_REG = None
    X86_OP_IMM = None
    X86_OP_MEM = None
    X86_OP_INVALID = None

try:
    import zstandard as zstd

    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

try:
    import lzma

    HAS_LZMA = True
except ImportError:
    HAS_LZMA = False

try:
    import lz4.frame

    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False

from colorama import init, Fore, Back, Style

init(autoreset=True)

VERSION = "1.6"
REPO = "github.com/2M12/DeNuitkanizator"
GITHUB_API = "https://api.github.com/repos/2M12/DeNuitkanizator/releases/latest"

PYTHON_MAGICS = {
    b'\x42\x0d\x0d\x0a': "3.7",
    b'\x55\x0d\x0d\x0a': "3.8",
    b'\x61\x0d\x0d\x0a': "3.9",
    b'\x6f\x0d\x0d\x0a': "3.10",
    b'\xa7\x0d\x0d\x0a': "3.11",
    b'\xcb\x0d\x0d\x0a': "3.12",
    b'\xf3\x0d\x0d\x0a': "3.13",
}

NUITKA_SIGNATURES = [
    b'Nuitka', b'nuitka', b'__nuitka_', b'nuitka_version',
    b'Nuitka_Onefile', b'Nuitka-Scons', b'__compiled__', b'frozen_modules',
]

PYINSTALLER_SIGNATURES = [
    b'pyinstaller', b'PyInstaller', b'MEI', b'PYZ-00.pyz',
]

CX_FREEZE_SIGNATURES = [
    b'cx_Freeze', b'cx-freeze',
]

ANTI_DEBUG_APIS = [
    b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent',
    b'NtQueryInformationProcess', b'NtSetInformationThread',
    b'OutputDebugStringA', b'GetTickCount', b'QueryPerformanceCounter', b'rdtsc',
]

ANTI_DEBUG_PATTERNS = [
    b'\x64\xa1\x30\x00\x00\x00',
    b'\x0f\x31',
    b'\xcd\x02',
    b'\xcd\x03',
]

PYOBJECT_FILE_PREFIXES = ['PyList_', 'PyObject_', 'PyModule_', 'PyUnicode_']

regsSize = [
    [['rax', 'eax', 'ax', 'al', 'ah'], {1: 'al', 2: 'ax', 4: 'eax', 8: 'rax'}],
    [['rbx', 'ebx', 'bx', 'bl', 'bh'], {1: 'bl', 2: 'bx', 4: 'ebx', 8: 'rbx'}],
    [['rcx', 'ecx', 'cx', 'cl', 'ch'], {1: 'cl', 2: 'cx', 4: 'ecx', 8: 'rcx'}],
    [['rdx', 'edx', 'dx', 'dl', 'dh'], {1: 'dl', 2: 'dx', 4: 'edx', 8: 'rdx'}],
    [['rbp', 'ebp', 'bp', 'bpl', 'bph'], {1: 'bpl', 2: 'bp', 4: 'ebp', 8: 'rbp'}],
    [['rsp', 'esp', 'sp', 'spl', 'sph'], {1: 'spl', 2: 'sp', 4: 'esp', 8: 'rsp'}],
    [['rsi', 'esi', 'si', 'sil', 'sih'], {1: 'sil', 2: 'si', 4: 'esi', 8: 'rsi'}],
    [['rdi', 'edi', 'di', 'dil', 'dih'], {1: 'dil', 2: 'di', 4: 'edi', 8: 'rdi'}],
    [['r8', 'r8d', 'r8w', 'r8b', ''], {1: 'r8b', 2: 'r8w', 4: 'r8d', 8: 'r8'}],
    [['r9', 'r9d', 'r9w', 'r9b', ''], {1: 'r9b', 2: 'r9w', 4: 'r9d', 8: 'r9'}],
    [['r10', 'r10d', 'r10w', 'r10b', ''], {1: 'r10b', 2: 'r10w', 4: 'r10d', 8: 'r10'}],
    [['r11', 'r11d', 'r11w', 'r11b', ''], {1: 'r11b', 2: 'r11w', 4: 'r11d', 8: 'r11'}],
    [['r12', 'r12d', 'r12w', 'r12b', ''], {1: 'r12b', 2: 'r12w', 4: 'r12d', 8: 'r12'}],
    [['r13', 'r13d', 'r13w', 'r13b', ''], {1: 'r13b', 2: 'r13w', 4: 'r13d', 8: 'r13'}],
    [['r14', 'r14d', 'r14w', 'r14b', ''], {1: 'r14b', 2: 'r14w', 4: 'r14d', 8: 'r14'}],
    [['r15', 'r15d', 'r15w', 'r15b', ''], {1: 'r15b', 2: 'r15w', 4: 'r15d', 8: 'r15'}],
]

XMM_REGS = ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7',
            'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15']

YMM_REGS = ['ymm0', 'ymm1', 'ymm2', 'ymm3', 'ymm4', 'ymm5', 'ymm6', 'ymm7',
            'ymm8', 'ymm9', 'ymm10', 'ymm11', 'ymm12', 'ymm13', 'ymm14', 'ymm15']

ENVIRONMENT_H = '''#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

#define MEMORY_SIZE 0x1000000

bool of = 0, sf = 0, zf = 0, af = 0, pf = 0, cf = 0;

union {
    uint64_t tmp64;
    uint32_t tmp32;
    uint16_t tmp16;
    uint8_t tmp8;
} tmp;

union {
    double d[2];
    float f[4];
    uint64_t u64[2];
    uint32_t u32[4];
    uint16_t u16[8];
    uint8_t u8[16];
} xmm[16];

union {
    double d[4];
    float f[8];
    uint64_t u64[4];
    uint32_t u32[8];
    uint16_t u16[16];
    uint8_t u8[32];
} ymm[16];

#define tmp8 tmp.tmp8
#define tmp16 tmp.tmp16
#define tmp32 tmp.tmp32
#define tmp64 tmp.tmp64

#define MEMORY(T, O) (*((T*)&memory[O]))

#define TMP8(x, op, y)   tmp8  = ((uint8_t)x)  op ((uint8_t)y)
#define TMP16(x, op, y)  tmp16 = ((uint16_t)x) op ((uint16_t)y)
#define TMP32(x, op, y)  tmp32 = ((uint32_t)x) op ((uint32_t)y)
#define TMP64(x, op, y)  tmp64 = ((uint64_t)x) op ((uint64_t)y)

#define SET_ZF(size) zf = !tmp##size
#define SET_CF_ADD(size, op1)  cf = tmp##size < op1
#define SET_CF_SUB(op1, op2)   cf = op1 < op2
#define SET_AF_0(op1, op2) af = ((op1 ^ op2) ^ tmp8) & 0x10
#define SET_AF_INC(size) af = (tmp##size & 0xf) == 0
#define SET_AF_DEC(size) af = (tmp##size & 0xf) == 0xf
#define SET_OF_SUB(op1, op2, size, mask) of = (((((op1) ^ (op2)) & ((op1) ^ (tmp##size))) & (mask)) != 0)
#define SET_OF_ADD(op1, op2, result, mask) of = (((((op1) ^ (result)) & ((op2) ^ (result))) & (mask)) != 0)
#define SET_OF_INC_DEC_NEG(size, mask) of = (tmp##size == mask)
#define SET_SF(size) sf = (tmp##size >> ((size)-1)) & 1
#define SET_PF() pf = __builtin_parity(tmp8)

#define PUSH64(v) do { rsp -= 8; MEMORY(uint64_t, rsp) = v; } while(0)
#define PUSH32(v) do { esp -= 4; MEMORY(uint32_t, esp) = v; } while(0)
#define POP64() (rsp += 8, MEMORY(uint64_t, rsp-8))
#define POP32() (esp += 4, MEMORY(uint32_t, esp-4))

#define BSR(v, dst) do { dst = 63 - __builtin_clzll(v); } while(0)
#define BSF(v, dst) do { dst = __builtin_ctzll(v); } while(0)
#define BT(v, b) ((v >> (b % 64)) & 1)
#define BTS(v, b) v |= (1ULL << (b % 64))
#define BTR(v, b) v &= ~(1ULL << (b % 64))
#define BTC(v, b) v ^= (1ULL << (b % 64))

typedef struct { uint64_t lo; int64_t hi; } i128_t;

uint8_t memory[MEMORY_SIZE] = {0};

struct {
    union { struct { uint8_t al; uint8_t ah; } __attribute__((packed)); uint16_t ax; uint32_t eax; uint64_t rax; } __attribute__((packed));
    union { struct { uint8_t bl; uint8_t bh; } __attribute__((packed)); uint16_t bx; uint32_t ebx; uint64_t rbx; } __attribute__((packed));
    union { struct { uint8_t cl; uint8_t ch; } __attribute__((packed)); uint16_t cx; uint32_t ecx; uint64_t rcx; } __attribute__((packed));
    union { struct { uint8_t dl; uint8_t dh; } __attribute__((packed)); uint16_t dx; uint32_t edx; uint64_t rdx; } __attribute__((packed));
    union { struct { uint8_t bpl; uint8_t bph; } __attribute__((packed)); uint16_t bp; uint32_t ebp; uint64_t rbp; } __attribute__((packed));
    union { struct { uint8_t spl; uint8_t sph; } __attribute__((packed)); uint16_t sp; uint32_t esp; uint64_t rsp; } __attribute__((packed));
    union { struct { uint8_t sil; uint8_t sih; } __attribute__((packed)); uint16_t si; uint32_t esi; uint64_t rsi; } __attribute__((packed));
    union { struct { uint8_t dil; uint8_t dih; } __attribute__((packed)); uint16_t di; uint32_t edi; uint64_t rdi; } __attribute__((packed));
} __attribute__((packed)) regs;

#define rax regs.rax
#define eax regs.eax
#define  ax regs.ax
#define  al regs.al
#define  ah regs.ah
#define rbx regs.rbx
#define ebx regs.ebx
#define  bx regs.bx
#define  bl regs.bl
#define  bh regs.bh
#define rcx regs.rcx
#define ecx regs.ecx
#define  cx regs.cx
#define  cl regs.cl
#define  ch regs.ch
#define rdx regs.rdx
#define edx regs.edx
#define  dx regs.dx
#define  dl regs.dl
#define  dh regs.dh
#define rbp regs.rbp
#define ebp regs.ebp
#define  bp regs.bp
#define rsp regs.rsp
#define esp regs.esp
#define  sp regs.sp
#define rsi regs.rsi
#define esi regs.esi
#define  si regs.si
#define rdi regs.rdi
#define edi regs.edi
#define  di regs.di
'''

cTemplate = '''#include "environment.h"

void func() {
%s}

int main() {
}
'''

YARA_TEMPLATE = """rule DeNuitkanizator_AutoGen_{timestamp}
{{
    meta:
        description = "Auto-generated rule for {filename}"
        author = "DeNuitkanizator v{VERSION}"
        date = "{date}"
        packager = "{packager}"
        sha256 = "{sha256}"
    strings:
{strings}
    condition:
        {condition}
}}
"""

BANNER = f"""{Fore.YELLOW}
  _____       _   _       _ _   _               _          _             
 |  __ \\     | \\ | |     (_) | | |             (_)        | |            
 | |  | | ___|  \\| |_   _ _| |_| | ____ _ _ __  _ ______ _| |_ ___  _ __ 
 | |  | |/ _ \\ . ` | | | | | __| |/ / _` | '_ \\| |_  / _` | __/ _ \\| '__|
 | |__| |  __/ |\\  | |_| | | |_|   < (_| | | | | |/ / (_| | || (_) | |   
 |_____/ \\___|_| \\_|\\__,_|_|\\__|_|\\_\\__,_|_| |_|_/___\\__,_|\\__\\___/|_|   
                                                                         {Style.RESET_ALL}"""


def check_for_updates():
    try:
        req = urllib.request.Request(GITHUB_API, headers={"User-Agent": "DeNuitkanizator"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            latest_version = data.get("tag_name", "").lstrip("v")
            if latest_version and latest_version != VERSION:
                return "update", latest_version
            return "latest", VERSION
    except Exception:
        return "offline", None


class Logger:
    def __init__(self, log_path):
        self.log_file = open(log_path, 'w', encoding='utf-8')
        self.start_time = datetime.datetime.now()

    def info(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"{Back.CYAN}{Fore.BLACK} INFO {Style.RESET_ALL} [{ts}] {msg}")
        self.log_file.write(f"[INFO] [{ts}] {msg}\n")
        self.log_file.flush()

    def warning(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"{Back.YELLOW}{Fore.BLACK} WARNING {Style.RESET_ALL} [{ts}] {msg}")
        self.log_file.write(f"[WARNING] [{ts}] {msg}\n")
        self.log_file.flush()

    def fatal(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"{Back.RED}{Fore.WHITE} FATAL {Style.RESET_ALL} [{ts}] {msg}")
        self.log_file.write(f"[FATAL] [{ts}] {msg}\n")
        self.log_file.flush()

    def done(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"\n{Back.GREEN}{Fore.BLACK} DONE {Style.RESET_ALL} [{ts}] {msg}")
        self.log_file.write(f"[DONE] [{ts}] {msg}\n")
        self.log_file.flush()

    def elapsed(self):
        return (datetime.datetime.now() - self.start_time).total_seconds()

    def close(self):
        self.log_file.close()


class NuitkaDumper:
    def __init__(self, filepath):
        self.filepath = Path(filepath).resolve()
        self.data = None
        self.pe = None
        self.detected_packager = None
        self.detected_nuitka = False
        self.detected_pyinstaller = False
        self.detected_cx_freeze = False
        self.detected_python = None
        self.found_bytecodes = []
        self.found_frozen_modules = []
        self.output_dir = None
        self.logger = None
        self.all_sections_data = b''
        self.extracted_strings = []
        self.extracted_modules = set()
        self.extracted_ips = set()
        self.extracted_urls = set()
        self.extracted_paths = set()
        self.extracted_emails = set()
        self.rsrc_entropy = 0.0
        self.rsrc_data = b''
        self.overlay_data = b''
        self.rsrc_start = 0
        self.rsrc_end = 0
        self.section_ranges = {}
        self.update_status = None
        self.update_version = None
        self.iat_addresses = {}
        self.import_name_by_address = {}
        self.pyobj_count = 0
        self.has_pyobject_files = False
        self.pyinstaller_confirmed = False
        self.pyinstaller_archive = None
        self.python_type_objects = {}
        self.virtual_image = b''
        self.image_base = 0
        self.exec_ranges = []
        self.pseudo_mode = 'clean'
        self.clean_stats = {}

    def run(self):
        self._show_banner()
        target = self._prompt_path()
        self._prompt_mode()
        self._init_output(target)
        self._dump_all()
        self._write_summary()
        self.logger.done("EXIT CODE: 0 (Success). Check output files! :)")
        self.logger.close()

    def _show_banner(self):
        print(BANNER)
        print(f"{Back.CYAN}{Fore.BLACK} INFO {Style.RESET_ALL} Created by 2M12 on Python 3.11")
        print(f"{Back.CYAN}{Fore.BLACK} INFO {Style.RESET_ALL} This is version {VERSION}", end=" ")
        self.update_status, self.update_version = check_for_updates()
        if self.update_status == "update":
            print(f"{Back.YELLOW}{Fore.BLACK} (New Update Available: v{self.update_version}){Style.RESET_ALL}")
        elif self.update_status == "latest":
            print(f"{Back.GREEN}{Fore.BLACK} (Latest version){Style.RESET_ALL}")
        else:
            print(f"{Back.RED}{Fore.WHITE} (Offline Mode){Style.RESET_ALL}")
        print(f"{Back.CYAN}{Fore.BLACK} INFO {Style.RESET_ALL} Repository: {REPO}")
        print(
            f"{Back.CYAN}{Fore.BLACK} INFO {Style.RESET_ALL} Please read the instructions in the repository before using the program.")
        print(
            f"{Back.YELLOW}{Fore.BLACK} WARNING {Style.RESET_ALL} By using this tool, you agree to the terms in EULA.md (check Repository)")
        print(
            f"{Back.YELLOW}{Fore.BLACK} WARNING {Style.RESET_ALL} YARA rules, packager detection and ASM->C translation are W.I.P. Expect improvements in future updates.")
        print()

    def _prompt_path(self):
        border = f"{Fore.CYAN}╔═════════════════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}"
        prompt = f"{Fore.CYAN}║{Style.RESET_ALL} Enter path .exe file:                                                       {Fore.CYAN}║{Style.RESET_ALL}"
        bottom = f"{Fore.CYAN}╚═════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}"
        print(border)
        print(prompt)
        print(bottom)
        path = input("> ").strip().strip('"')
        os.system('cls' if os.name == 'nt' else 'clear')
        return path

    def _prompt_mode(self):
        border = f"{Fore.CYAN}╔═════════════════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}"
        bottom = f"{Fore.CYAN}╚═════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}"
        line1 = f"{Fore.CYAN}║{Style.RESET_ALL} Select pseudocode mode:                                                     {Fore.CYAN}║{Style.RESET_ALL}"
        line2 = f"{Fore.CYAN}║{Style.RESET_ALL}   [1] Clean    - readable pseudo-C (IR + CFG + if/while/switch)             {Fore.CYAN}║{Style.RESET_ALL}"
        line3 = f"{Fore.CYAN}║{Style.RESET_ALL}   [2] Standard - direct CPU emulation in C (previous behaviour)             {Fore.CYAN}║{Style.RESET_ALL}"
        print(border)
        print(line1)
        print(line2)
        print(line3)
        print(bottom)
        choice = input("> ").strip().lower()
        os.system('cls' if os.name == 'nt' else 'clear')
        if choice in ('2', 'standard', 'std', 's', 'emu', 'emulation'):
            self.pseudo_mode = 'standard'
            print(f"{Back.CYAN}{Fore.BLACK} INFO {Style.RESET_ALL} Pseudocode mode: Standard (CPU emulation)")
        else:
            self.pseudo_mode = 'clean'
            print(f"{Back.CYAN}{Fore.BLACK} INFO {Style.RESET_ALL} Pseudocode mode: Clean (IR + CFG structuring)")

    def _init_output(self, target):
        target_path = Path(target)
        if not target_path.exists():
            self._fatal_error(1)
        if not target_path.is_file():
            self._fatal_error(1)
        self.filepath = target_path.resolve()
        self.data = target_path.read_bytes()
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = target_path.stem
        self.output_dir = Path.cwd() / "DeNuitkanizator_Output" / f"{base_name}_{ts}"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.output_dir / f"{base_name}_{ts}.log"
        self.logger = Logger(str(log_path))
        self.logger.info(f"Output directory: {self.output_dir}")
        self.logger.info(f"Target file: {target_path}")
        self.logger.info(f"File size: {len(self.data):,} bytes")
        if not HAS_ZSTD:
            self.logger.warning("zstandard not installed. Install: pip install zstandard")
        if not HAS_LZ4:
            self.logger.warning("lz4 not installed. Install: pip install lz4")
        if not HAS_LZMA:
            self.logger.warning("lzma not available. This should be built-in, check your Python installation.")
        try:
            self.pe = pefile.PE(data=self.data)
            self.logger.info("PE file detected")
            self._build_iat_map()
            for section in self.pe.sections:
                try:
                    section_data = section.get_data()
                    self.all_sections_data += section_data
                    name = section.Name.decode('utf-8', errors='replace').strip('\x00')
                    start = section.PointerToRawData
                    end = start + section.SizeOfRawData
                    self.section_ranges[name] = (start, end)
                    if name == '.rsrc':
                        self.rsrc_data = section_data
                        self.rsrc_entropy = self._calc_entropy(section_data)
                        self.rsrc_start = start
                        self.rsrc_end = end
                except:
                    pass
            self._build_virtual_image()
        except Exception:
            self.logger.info("Not a valid PE file, continuing with raw data")
            self.all_sections_data = self.data

    def _build_virtual_image(self):
        """Build an in-memory image of the loaded PE so VA reads match runtime layout."""
        self.virtual_image = b''
        self.exec_ranges = []
        if not self.pe:
            return
        try:
            self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
            size = self.pe.OPTIONAL_HEADER.SizeOfImage
            if size <= 0 or size > 0x40000000:
                size = max(len(self.data), 0x1000)
            image = bytearray(size)
            for section in self.pe.sections:
                try:
                    raw = section.get_data()
                    rva = section.VirtualAddress
                    if rva < 0 or rva + len(raw) > len(image):
                        continue
                    image[rva:rva + len(raw)] = raw
                    if self._is_executable_section(section):
                        vstart = self.image_base + rva
                        vend = vstart + max(section.Misc_VirtualSize, len(raw))
                        self.exec_ranges.append((vstart, vend))
                except Exception:
                    continue
            self.exec_ranges.sort()
            self.virtual_image = bytes(image)
        except Exception:
            self.virtual_image = b''
            self.exec_ranges = []

    def read_va(self, va, size):
        """Read up to `size` bytes from the loaded image at virtual address `va`."""
        if not self.virtual_image:
            return b''
        off = va - self.image_base
        if off < 0 or off >= len(self.virtual_image):
            return b''
        return self.virtual_image[off:off + size]

    def va_to_offset(self, va):
        """Convert a virtual address to a raw file offset (or None)."""
        if not self.pe:
            return None
        try:
            return self.pe.get_offset_from_rva(va - self.image_base)
        except Exception:
            return None

    def is_executable_va(self, va):
        for start, end in self.exec_ranges:
            if start <= va < end:
                return True
        return False

    def _build_iat_map(self):
        self.iat_addresses = {}
        self.import_name_by_address = {}
        if not self.pe:
            return
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='replace')
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='replace')
                        else:
                            func_name = f"ord_{imp.ordinal}"
                        full_name = f"{dll_name}:{func_name}"
                        if imp.address:
                            self.import_name_by_address[imp.address] = full_name
                            self.iat_addresses[imp.address] = full_name
                        if imp.thunk_rva:
                            self.import_name_by_address[imp.thunk_rva + self.pe.OPTIONAL_HEADER.ImageBase] = full_name
        except:
            pass

    def _is_in_section(self, offset, section_name):
        if section_name in self.section_ranges:
            start, end = self.section_ranges[section_name]
            return start <= offset < end
        return False

    def _is_executable_section(self, section):
        return (section.Characteristics & 0x20000000) != 0

    def _imm_target(self, insn):
        """Static immediate branch/call target, or None."""
        if not insn.operands:
            return None
        op = insn.operands[0]
        if op.type == X86_OP_IMM:
            return op.imm & 0xFFFFFFFFFFFFFFFF
        return None

    def _get_arch_mode(self):
        if not self.pe:
            return CS_MODE_64
        machine = self.pe.FILE_HEADER.Machine
        if machine == 0x8664:
            return CS_MODE_64
        elif machine == 0x014c:
            return CS_MODE_32
        return CS_MODE_64

    def _dump_all(self):
        self._create_dirs()
        self._detect_packager()
        self._check_pyobject_files()
        self._dump_sections()
        self._dump_overlay()
        self._dump_resources()
        self._extract_all_strings()
        self._aggressive_bytecode_search()
        self._extract_pyinstaller_archive()
        self._extract_with_pydumpck()
        self._extract_zip_bytecode()
        self._extract_single_file_bytecode()
        self._extract_frozen_modules()
        self._extract_nuitka_constants()
        self._extract_source_paths()
        self._extract_variable_names()
        self._extract_python_object_headers()
        self._extract_nuitka_memory_structures()
        self._extract_payloads()
        self._dump_info()
        self._dump_hashes()
        self._dump_entropy()
        self._dump_disasm()
        self._dump_disasm_full()
        self._dump_pseudocode()
        self._dump_disasm_functions()
        self._dump_xrefs()
        self._dump_import_xrefs()
        self._dump_call_graph()
        self._dump_analysis()
        self._dump_suspicious()
        self._dump_compressed_blocks()
        self._dump_yara_rules()
        self._dump_string_files()
        self._write_log_copy()

    def _create_dirs(self):
        dirs = [
            "Dumps/sections", "Dumps/resources/icons", "Dumps/resources/manifests",
            "Dumps/resources/version_info", "Dumps/resources/bitmaps",
            "Dumps/resources/other",
            "Dumps/bytecode/3.7", "Dumps/bytecode/3.8", "Dumps/bytecode/3.9",
            "Dumps/bytecode/3.10", "Dumps/bytecode/3.11",
            "Dumps/bytecode/3.12", "Dumps/bytecode/3.13",
            "Dumps/memory/py_objects", "Dumps/memory/nuitka_structs",
            "Dumps/frozen_modules", "Dumps/payloads", "Dumps/Pyinstaller",
            "Strings/suspicious", "Info", "Disasm/xrefs", "Disasm/full", "Disasm/functions", "Disasm/code",
            "Analysis",
            "Suspicious/encrypted_blocks", "Suspicious/compressed_blocks",
            "Suspicious/obfuscated_code", "Suspicious/anti_debug",
            "Suspicious/packed_sections",
            "Recovered/source/incomplete", "Recovered/bytecode_decoded",
            "Recovered/bytecode_zip",
            "Recovered/pyinstaller/scripts", "Recovered/pyinstaller/modules",
            "Recovered/pyinstaller/pyz", "Recovered/pyinstaller/data",
            "Disasm/pseudocode/functions",
            "Recovered/configs",
        ]
        for d in dirs:
            (self.output_dir / d).mkdir(parents=True, exist_ok=True)

    def _check_pyobject_files(self):
        pyobj_dir = self.output_dir / "Dumps" / "memory" / "py_objects"
        if not pyobj_dir.exists():
            self.has_pyobject_files = False
            return
        for prefix in PYOBJECT_FILE_PREFIXES:
            matching = list(pyobj_dir.glob(f"{prefix}*.bin"))
            if matching:
                self.has_pyobject_files = True
                return
        self.has_pyobject_files = False

    def _pyinstaller_parse_archive(self):
        if self.pyinstaller_archive is not None:
            return self.pyinstaller_archive or None
        data = self.data or b''
        magic = self.PYI_MAGIC
        cookie_len = struct.calcsize(self.PYI_COOKIE)
        toc_hdr = struct.calcsize(self.PYI_TOC_ENTRY)
        best = None
        pos = data.find(magic)
        while pos >= 0:
            if pos + cookie_len <= len(data):
                try:
                    got_magic, pkg_len, toc_off, toc_len, pyver, pylib = \
                        struct.unpack_from(self.PYI_COOKIE, data, pos)
                except Exception:
                    got_magic = None
                if got_magic == magic and pylib.rstrip(b'\x00') and toc_len >= toc_hdr:
                    end = pos + cookie_len
                    start = end - pkg_len
                    toc_start = start + toc_off
                    toc_end = toc_start + toc_len
                    if 0 <= start < pos and end <= len(data) and \
                            start <= toc_start < toc_end <= end <= len(data):
                        entries = []
                        cursor = toc_start
                        valid = True
                        while cursor + toc_hdr <= toc_end:
                            try:
                                entry_len, offset, clen, ulen, cflag, typecode = \
                                    struct.unpack_from(self.PYI_TOC_ENTRY, data, cursor)
                            except Exception:
                                valid = False
                                break
                            if entry_len < toc_hdr or cursor + entry_len > toc_end:
                                valid = False
                                break
                            raw_name = data[cursor + toc_hdr:cursor + entry_len].rstrip(b'\x00')
                            try:
                                name = raw_name.decode('utf-8')
                            except Exception:
                                valid = False
                                break
                            if not name or not typecode or len(name) > 1024 or \
                                    any(ord(ch) < 0x20 for ch in name):
                                valid = False
                                break
                            if offset < 0 or clen < 0 or start + offset + clen > toc_start:
                                valid = False
                                break
                            entries.append((name, offset, clen, ulen, cflag, typecode))
                            cursor += entry_len
                        if valid and entries:
                            info = {
                                'cookie_offset': pos,
                                'start': start,
                                'end': end,
                                'toc_offset': toc_start,
                                'toc_length': toc_len,
                                'python_version': pyver,
                                'python_lib': pylib.rstrip(b'\x00').decode('utf-8', 'replace'),
                                'entries': entries,
                            }
                            if best is None or len(entries) > len(best['entries']):
                                best = info
            pos = data.find(magic, pos + 1)
        self.pyinstaller_archive = best or False
        return best

    def _detect_packager(self):
        self.logger.info("Detecting packager...")
        pyi_info = self._pyinstaller_parse_archive()
        if pyi_info:
            self.pyinstaller_confirmed = True
        nuitka_hits = 0
        for sig in NUITKA_SIGNATURES:
            if sig in self.data:
                nuitka_hits += 1
        pyinstaller_hits = 0
        for sig in PYINSTALLER_SIGNATURES:
            if sig in self.data:
                pyinstaller_hits += 1
        cx_freeze_hits = 0
        for sig in CX_FREEZE_SIGNATURES:
            if sig in self.data:
                cx_freeze_hits += 1
        has_python_dlls = False
        if self.pe and hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='replace').lower()
                if 'python' in dll_name:
                    has_python_dlls = True
                    break
        if self.pyinstaller_confirmed:
            pyver = self._pyinstaller_python_version(pyi_info['python_version'])
            self.detected_packager = f"PyInstaller (CArchive verified, Python {pyver})"
            self.detected_pyinstaller = True
            self.detected_python = pyver
            self.logger.info(
                f"  Detected: PyInstaller - valid CArchive cookie at 0x{pyi_info['cookie_offset']:x}, "
                f"{len(pyi_info['entries'])} TOC entries, Python {pyver} ({pyi_info['python_lib']})")
        elif nuitka_hits >= 1:
            self.detected_packager = "Nuitka"
            self.detected_nuitka = True
            self.logger.info(f"  Detected: Nuitka ({nuitka_hits} signatures matched)")
        elif self.rsrc_entropy > 7.9 and len(self.rsrc_data) > 100000:
            self.detected_packager = "Nuitka (detected by .rsrc entropy)"
            self.detected_nuitka = True
            self.logger.info(
                f"  Detected: Nuitka (high entropy .rsrc: {self.rsrc_entropy:.2f}/8.0, size: {len(self.rsrc_data):,} bytes)")
        elif pyinstaller_hits >= 1 and (has_python_dlls or self.has_pyobject_files):
            self.detected_packager = "PyInstaller"
            self.detected_pyinstaller = True
            self.logger.info(
                f"  Detected: PyInstaller ({pyinstaller_hits} signatures matched, Python DLL: {has_python_dlls}, PyObject files: {self.has_pyobject_files})")
        elif cx_freeze_hits >= 1:
            self.detected_packager = "cx_Freeze"
            self.detected_cx_freeze = True
            self.logger.info(f"  Detected: cx_Freeze ({cx_freeze_hits} signatures matched)")
        elif pyinstaller_hits >= 1:
            self.detected_packager = "PyInstaller (low confidence)"
            self.detected_pyinstaller = True
            self.logger.warning(
                f"  Detected: PyInstaller (signatures matched but no valid CArchive cookie)")
        else:
            self.detected_packager = "Unknown (native or other)"
            self.logger.info("  Packager not identified")

    def _dump_sections(self):
        if not self.pe:
            return
        self.logger.info("Dumping sections...")
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='replace').strip('\x00').strip()
            if not name:
                name = f"section_{hex(section.VirtualAddress)}"
            fname = self.output_dir / "Dumps" / "sections" / f"{name}.bin"
            try:
                data = section.get_data()
                fname.write_bytes(data)
                self.logger.info(f"  Section {name}: {len(data):,} bytes")
            except Exception as e:
                self.logger.warning(f"  Failed to dump section {name}: {e}")

    def _dump_overlay(self):
        if not self.pe:
            return
        self.logger.info("Dumping overlay...")
        overlay = self._overlay_bytes()
        self.overlay_data = overlay
        if overlay:
            fname = self.output_dir / "Dumps" / "overlay.bin"
            fname.write_bytes(overlay)
            self.logger.info(f"  Overlay: {len(overlay):,} bytes")
        else:
            self.logger.info("  No overlay found")

    def _dump_resources(self):
        if not self.pe:
            return
        self.logger.info("Dumping resources...")
        res_root = self.output_dir / "Dumps" / "resources"
        count = 0
        leaves = []
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for type_entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if not hasattr(type_entry, 'directory') or type_entry.directory is None:
                        continue
                    for name_entry in type_entry.directory.entries:
                        if not hasattr(name_entry, 'directory') or name_entry.directory is None:
                            continue
                        for lang_entry in name_entry.directory.entries:
                            if hasattr(lang_entry, 'data') and lang_entry.data is not None:
                                leaves.append((type_entry, name_entry, lang_entry))
        except Exception as exc:
            self.logger.warning(f"  Failed to enumerate resources: {exc}")
        if not leaves:
            self.logger.info("  Resources extracted: 0")
            return

        # collect raw payloads
        icon_images = {}
        for type_entry, name_entry, lang_entry in leaves:
            if type_entry.id != 3:
                continue
            try:
                icon_images[name_entry.id] = self.pe.get_data(
                    lang_entry.data.struct.OffsetToData, lang_entry.data.struct.Size)
            except Exception:
                continue

        for type_entry, name_entry, lang_entry in leaves:
            try:
                data = self.pe.get_data(
                    lang_entry.data.struct.OffsetToData, lang_entry.data.struct.Size)
            except Exception:
                continue
            if not data:
                continue
            type_id = self._resource_type_key(type_entry)
            res_name = self._resource_name(name_entry, fallback=f"id{type_id}")
            lang = lang_entry.id
            base_name = re.sub(r'[^A-Za-z0-9._-]+', '_', str(res_name)) or f"res_{type_id}"
            try:
                if type_id == 3:                       # RT_ICON
                    dest = res_root / "icons"
                    dest.mkdir(parents=True, exist_ok=True)
                    (dest / f"icon_{base_name}_{lang}.ico").write_bytes(
                        self._ico_from_images([data]))
                    (dest / f"icon_{base_name}_{lang}.dib").write_bytes(data)
                    count += 1
                elif type_id == 14:                    # RT_GROUP_ICON
                    dest = res_root / "icons"
                    dest.mkdir(parents=True, exist_ok=True)
                    images = self._group_icon_images(data, icon_images)
                    if images:
                        (dest / f"group_{base_name}_{lang}.ico").write_bytes(
                            self._ico_from_images(images))
                        count += 1
                    (dest / f"group_{base_name}_{lang}.bin").write_bytes(data)
                    count += 1
                elif type_id == 24:                    # RT_MANIFEST
                    dest = res_root / "manifests"
                    dest.mkdir(parents=True, exist_ok=True)
                    (dest / f"manifest_{base_name}_{lang}.xml").write_bytes(data)
                    count += 1
                elif type_id == 16:                    # RT_VERSION
                    dest = res_root / "version_info"
                    dest.mkdir(parents=True, exist_ok=True)
                    (dest / f"version_{base_name}_{lang}.bin").write_bytes(data)
                    text = self._parse_version_info(data)
                    if text:
                        (dest / f"version_{base_name}_{lang}.txt").write_text(
                            text + "\n", encoding='utf-8')
                    count += 1
                elif type_id == 2:                     # RT_BITMAP
                    dest = res_root / "bitmaps"
                    dest.mkdir(parents=True, exist_ok=True)
                    bmp = self._dib_to_bmp(data)
                    if bmp:
                        (dest / f"bitmap_{base_name}_{lang}.bmp").write_bytes(bmp)
                    (dest / f"bitmap_{base_name}_{lang}.dib").write_bytes(data)
                    count += 1
                elif type_id == 6:                     # RT_STRING
                    dest = res_root / "other"
                    dest.mkdir(parents=True, exist_ok=True)
                    (dest / f"strings_{base_name}_{lang}.txt").write_text(
                        self._parse_string_table(data, name_entry.id),
                        encoding='utf-8')
                    count += 1
                else:
                    dest = res_root / "other" / f"type_{type_id}"
                    dest.mkdir(parents=True, exist_ok=True)
                    (dest / f"{base_name}_{lang}.bin").write_bytes(data)
                    count += 1
            except Exception as exc:
                self.logger.warning(f"  Resource {type_id}/{res_name}/{lang}: {exc}")
        self._write_resource_index(leaves)
        self.logger.info(f"  Resources extracted: {count}")

    @staticmethod
    def _resource_type_key(type_entry):
        """Return the RT_* integer id, or the name for custom resource types."""
        try:
            if type_entry.id is not None:
                return type_entry.id
            name = type_entry.name
            if name is not None:
                text = name.decode('utf-16-le', 'replace') if isinstance(name, bytes) else str(name)
                text = text.strip('\x00')
                if text:
                    return re.sub(r'[^A-Za-z0-9._-]+', '_', text)
        except Exception:
            pass
        return 'unknown'

    @staticmethod
    def _resource_name(entry, fallback='resource'):
        try:
            if entry.name is not None:
                if isinstance(entry.name, bytes):
                    name = entry.name.decode('utf-16-le', 'replace')
                else:
                    name = str(entry.name)
                name = name.strip('\x00')
                if name:
                    return name
            if entry.id is not None:
                return f"id{entry.id}"
        except Exception:
            pass
        return fallback

    def _write_resource_index(self, leaves):
        lines = ["type\tname\tlanguage\tsize"]
        for type_entry, name_entry, lang_entry in leaves:
            try:
                size = lang_entry.data.struct.Size
            except Exception:
                size = 0
            lines.append(f"{self._resource_type_key(type_entry)}\t"
                         f"{self._resource_name(name_entry)}\t"
                         f"{lang_entry.id}\t{size}")
        res_root = self.output_dir / "Dumps" / "resources"
        res_root.mkdir(parents=True, exist_ok=True)
        (res_root / "resource_index.txt").write_text(
            "\n".join(lines) + "\n", encoding='utf-8')

    @staticmethod
    def _dib_to_bmp(dib):
        """Prepend a BITMAPFILEHEADER to an RT_BITMAP DIB payload."""
        if len(dib) < 40:
            return None
        try:
            header_size = struct.unpack_from('<I', dib, 0)[0]
            if header_size < 40 or header_size > len(dib):
                return None
            bit_count = struct.unpack_from('<H', dib, 14)[0]
            clr_used = struct.unpack_from('<I', dib, 32)[0]
            palette = 0
            if bit_count <= 8:
                palette = (clr_used or (1 << bit_count)) * 4
            offset = 14 + header_size + palette
            file_size = 14 + len(dib)
            header = b'BM' + struct.pack('<IHHI', file_size, 0, 0, offset)
            return header + dib
        except Exception:
            return None

    @staticmethod
    def _ico_from_images(images):
        """Build an .ico container from RT_ICON DIB/PNG payloads."""
        images = [img for img in images if img]
        if not images:
            return b''
        entries = []
        offset = 6 + 16 * len(images)
        for data in images:
            width = height = 0
            bit_count = 32
            if data[:8] == b'\x89PNG\r\n\x1a\n' and len(data) >= 24:
                width = struct.unpack('>I', data[16:20])[0]
                height = struct.unpack('>I', data[20:24])[0]
                bit_count = 32
            elif len(data) >= 16:
                bi_width, bi_height = struct.unpack_from('<ii', data, 4)
                bit_count = struct.unpack_from('<H', data, 14)[0] or 32
                width, height = abs(bi_width), abs(bi_height) // 2
            entries.append(struct.pack(
                '<BBBBHHII',
                width & 0xFF if width < 256 else 0,
                height & 0xFF if height < 256 else 0,
                0, 0, 1, bit_count, len(data), offset))
            offset += len(data)
        return struct.pack('<HHH', 0, 1, len(images)) + b''.join(entries) + b''.join(images)

    @staticmethod
    def _group_icon_images(group_data, icon_images):
        """Parse RT_GROUP_ICON and return the referenced RT_ICON payloads."""
        if len(group_data) < 6:
            return []
        try:
            _reserved, _type, count = struct.unpack_from('<HHH', group_data, 0)
            if count <= 0 or count > 64 or 6 + count * 14 > len(group_data):
                return []
            result = []
            for i in range(count):
                entry = group_data[6 + i * 14:6 + (i + 1) * 14]
                n_id = struct.unpack_from('<H', entry, 12)[0]
                image = icon_images.get(n_id)
                if image:
                    result.append(image)
            return result
        except Exception:
            return []

    @staticmethod
    def _parse_string_table(data, name_id):
        lines = []
        offset = 0
        base_id = (name_id - 1) * 16 if name_id and name_id > 0 else 0
        for i in range(16):
            if offset + 2 > len(data):
                break
            length = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            raw = data[offset:offset + length * 2]
            offset += length * 2
            if length:
                text = raw.decode('utf-16-le', 'replace')
                if text.strip():
                    lines.append(f"{(base_id + i) if base_id else i}\t{text}")
        return "\n".join(lines) + ("\n" if lines else "")

    @staticmethod
    def _parse_version_info(data):
        """Parse VS_VERSIONINFO into a readable key=value listing."""
        def align4(value):
            return (value + 3) & ~3

        def parse_block(buf, off, end):
            if off + 6 > end:
                return None
            try:
                length, value_len, value_type = struct.unpack_from('<HHH', buf, off)
            except Exception:
                return None
            if length < 6 or off + length > end:
                return None
            key_end = off + 6
            while key_end + 1 < off + length and buf[key_end:key_end + 2] != b'\x00\x00':
                key_end += 2
            key = buf[off + 6:key_end].decode('utf-16-le', 'replace')
            if key_end + 2 > off + length:
                return None
            pos = align4(key_end + 2)
            value_bytes = value_len * 2 if value_type == 1 else value_len
            value = buf[pos:min(pos + value_bytes, off + length)]
            children = []
            child_pos = align4(pos + value_bytes)
            while child_pos + 6 <= off + length:
                child = parse_block(buf, child_pos, off + length)
                if not child:
                    break
                children.append(child)
                child_pos = align4(child_pos + child['length'])
            return {
                'key': key, 'length': length, 'value_len': value_len,
                'value_type': value_type, 'value': value, 'children': children,
            }

        try:
            root = parse_block(data, 0, len(data))
        except Exception:
            root = None
        if not root:
            return None
        lines = ["# VS_VERSIONINFO"]
        fixed_blocks = [root]
        fixed_blocks.extend(child for child in root['children']
                            if child['key'] == 'VS_FIXEDFILEINFO')
        for block in fixed_blocks:
            if len(block['value']) < 52:
                continue
            fixed = struct.unpack('<13I', block['value'][:52])
            if fixed[0] != 0xFEEF04BD:
                continue
            ms, ls = fixed[2], fixed[3]
            pms, pls = fixed[4], fixed[5]
            lines.append(f"FixedFileVersion = "
                         f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}")
            lines.append(f"FixedProductVersion = "
                         f"{pms >> 16}.{pms & 0xFFFF}.{pls >> 16}.{pls & 0xFFFF}")
        def walk(node):
            for child in node['children']:
                if child['value_type'] == 1 and child['value']:
                    text = child['value'].decode('utf-16-le', 'replace').rstrip('\x00')
                    if child['key'] and child['key'] not in ('VS_VERSION_INFO',):
                        lines.append(f"{child['key']} = {text}")
                walk(child)
        walk(root)
        return "\n".join(lines) if len(lines) > 1 else None


    def _is_garbage_string(self, s):
        if len(s) < 4:
            return True
        printable_count = sum(1 for c in s if c in string.printable)
        ratio = printable_count / len(s) if len(s) > 0 else 0
        if ratio < 0.5:
            return True
        garbage_chars = set('!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~')
        alpha_count = sum(1 for c in s if c.isalpha())
        garbage_count = sum(1 for c in s if c in garbage_chars)
        if alpha_count == 0 and garbage_count > len(s) * 0.6:
            return True
        if len(s) >= 6 and garbage_count > len(s) * 0.8:
            return True
        return False

    def _extract_all_strings(self):
        self.logger.info("Extracting all readable strings...")
        strings = []
        self._string_offsets = {}
        for match in re.finditer(b'[\x20-\x7e]{4,}', self.data):
            try:
                s = match.group().decode('ascii', errors='replace')
                if not self._is_garbage_string(s):
                    strings.append(s)
                    offset = match.start()
                    if s not in self._string_offsets:
                        self._string_offsets[s] = []
                    self._string_offsets[s].append(offset)
            except:
                pass
        self.extracted_strings = list(set(strings))
        self.logger.info(f"  Total unique ASCII strings (filtered): {len(self.extracted_strings)}")

    def _dump_string_files(self):
        strings_dir = self.output_dir / "Strings"
        ascii4 = []
        ascii8 = []
        utf16le = []
        for s in self.extracted_strings:
            if len(s) >= 4:
                ascii4.append(s)
            if len(s) >= 8:
                ascii8.append(s)
        for match in re.finditer(b'(?:[\x20-\x7e]\x00){4,}', self.data):
            raw = match.group()
            try:
                s = raw.decode('utf-16-le', errors='replace')
                if s.strip() and not self._is_garbage_string(s):
                    utf16le.append(s)
            except:
                pass
        self._write_list(strings_dir / "all_ascii_4.txt", sorted(set(ascii4)))
        self._write_list(strings_dir / "all_ascii_8.txt", sorted(set(ascii8)))
        self._write_list(strings_dir / "all_utf16le.txt", sorted(set(utf16le)))
        self._write_list(strings_dir / "all_utf8.txt", sorted(set(ascii8)))
        self._write_list(strings_dir / "paths.txt", sorted(self.extracted_paths))
        self._write_list(strings_dir / "urls.txt", sorted(self.extracted_urls))
        self._write_list(strings_dir / "emails.txt", sorted(self.extracted_emails))
        self._write_list(strings_dir / "ips.txt", sorted(self.extracted_ips))
        self._write_list(strings_dir / "unique.txt", sorted(set(ascii4)))

    def _scan_data_for_patterns(self, data):
        path_pattern = re.compile(rb'(?:[A-Za-z]:\\|/|\./|\.\./)[\x20-\x7e\\/]{4,}')
        for match in path_pattern.finditer(data):
            try:
                p = match.group().decode('ascii', errors='replace')
                if p and len(p) > 5 and all(c in string.printable for c in p):
                    self.extracted_paths.add(p)
            except:
                pass
        url_pattern = re.compile(rb'https?://[\x20-\x7e]{4,}')
        for match in url_pattern.finditer(data):
            try:
                u = match.group().decode('ascii', errors='replace')
                self.extracted_urls.add(u)
            except:
                pass
        email_pattern = re.compile(rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
        for match in email_pattern.finditer(data):
            try:
                e = match.group().decode('ascii', errors='replace')
                self.extracted_emails.add(e)
            except:
                pass
        ip_pattern = re.compile(rb'(?:\d{1,3}\.){3}\d{1,3}')
        for match in ip_pattern.finditer(data):
            try:
                ip = match.group().decode('ascii')
                parts = ip.split('.')
                if all(0 <= int(p) <= 255 for p in parts):
                    self.extracted_ips.add(ip)
            except:
                pass
        for match in re.finditer(b'[\x20-\x7e]{4,}', data):
            try:
                s = match.group().decode('ascii', errors='replace')
                if not self._is_garbage_string(s):
                    self.extracted_strings.append(s)
            except:
                pass
        module_pattern = re.compile(rb'([A-Za-z0-9_/\\]+\.py)\x00')
        for match in module_pattern.finditer(data):
            try:
                mod = match.group(1).decode('ascii', errors='replace')
                if 3 < len(mod) < 200:
                    self.extracted_modules.add(mod)
            except:
                pass
        for magic, ver_name in PYTHON_MAGICS.items():
            offset = data.find(magic)
            if offset != -1:
                self.logger.info(f"    Found {ver_name} magic in decompressed data")
                bytecode_dir = self.output_dir / "Dumps" / "bytecode" / ver_name
                fname = bytecode_dir / f"decompressed_magic_{offset:08x}.bin"
                fname.write_bytes(data[max(0, offset - 16):offset + 65536])
                self.found_bytecodes.append((ver_name, offset, "decompressed"))

    def _aggressive_bytecode_search(self):
        self.logger.info("Aggressive bytecode/magic search...")
        bytecode_dir = self.output_dir / "Dumps" / "bytecode"
        for magic, ver_name in PYTHON_MAGICS.items():
            for section in self.pe.sections:
                try:
                    name = section.Name.decode('utf-8', errors='replace').strip('\x00')
                    region_data = section.get_data()
                    offset = 0
                    while True:
                        offset = region_data.find(magic, offset)
                        if offset == -1:
                            break
                        self._dump_magic_context(region_data, offset, ver_name, bytecode_dir, name)
                        if offset + 12 <= len(region_data):
                            self._try_marshal_load(region_data, offset, ver_name, bytecode_dir)
                        offset += max(len(magic), 1)
                except:
                    pass
        self.logger.info(f"  Bytecode candidates saved: {len(self.found_bytecodes)}")

    def _dump_magic_context(self, data, offset, ver_name, bytecode_dir, region_name):
        chunk_size = 65536
        start = max(0, offset - 256)
        end = min(len(data), offset + chunk_size)
        chunk = data[start:end]
        safe_region = region_name.replace('/', '_').replace('\\', '_')
        fname = bytecode_dir / ver_name / f"magic_context_{safe_region}_{offset:08x}.bin"
        fname.write_bytes(chunk)
        self.found_bytecodes.append((ver_name, offset, f"magic_context_{safe_region}"))

    def _try_marshal_load(self, data, offset, ver_name, bytecode_dir):
        """Validate a marshal code object and save a loadable .pyc."""
        for skip in (16, 12, 8, 0):
            test_offset = offset + skip
            if test_offset + 4 > len(data):
                continue
            chunk = data[test_offset:test_offset + 4 * 1024 * 1024]
            stream = io.BytesIO(chunk)
            try:
                obj = marshal.load(stream)
            except Exception:
                continue
            if not isinstance(obj, types.CodeType):
                continue
            consumed = stream.tell()
            body = chunk[:consumed]
            magic = self._pyc_magic_for(ver_name)
            fname = bytecode_dir / ver_name / \
                f"bytecode_{ver_name.replace('.', '')}_{offset:08x}_skip{skip}.pyc"
            try:
                fname.write_bytes(magic + b'\x00' * 12 + body)
            except Exception:
                continue
            self.found_bytecodes.append((ver_name, offset, f"marshal_skip{skip}"))
            self.logger.info(
                f"  [BYTECODE] {ver_name} code object at 0x{offset:08x} "
                f"(header skip {skip}, {consumed} bytes marshal)")
            return True
        return False

    # PyInstaller CArchive

    PYI_MAGIC = b'MEI\x0c\x0b\x0a\x0b\x0e'
    PYI_COOKIE = '!8sIIII64s'
    PYI_TOC_ENTRY = '!IIIIBc'

    def _pyinstaller_dirs(self):
        base = self.output_dir / "Recovered" / "pyinstaller"
        dirs = {
            'base': base,
            'scripts': base / "scripts",
            'modules': base / "modules",
            'pyz': base / "pyz",
            'data': base / "data",
        }
        for d in dirs.values():
            d.mkdir(parents=True, exist_ok=True)
        return dirs

    def _extract_pyinstaller_archive(self):
        """Extract every entry of a verified PyInstaller CArchive."""
        info = self._pyinstaller_parse_archive()
        if not info:
            if self.PYI_MAGIC in self.data:
                self.logger.warning("  PyInstaller magic found, but the CArchive cookie is invalid")
            return
        self.logger.info("Extracting PyInstaller CArchive...")
        dirs = self._pyinstaller_dirs()
        pyver = self._pyinstaller_python_version(info['python_version'])
        self.logger.info(
            f"  CArchive start=0x{info['start']:x}, {len(info['entries'])} entries, "
            f"Python {pyver} ({info['python_lib']})")
        written = self._write_pyinstaller_toc(
            info['entries'], info['start'], info['toc_offset'], dirs, pyver)
        manifest = [
            f"# PyInstaller CArchive",
            f"cookie_offset=0x{info['cookie_offset']:x}",
            f"archive_start=0x{info['start']:x}",
            f"archive_end=0x{info['end']:x}",
            f"toc_offset=0x{info['toc_offset']:x}",
            f"toc_length={info['toc_length']}",
            f"python_version={pyver}",
            f"python_library={info['python_lib']}",
            "",
            "name\toffset\tcompressed_size\tuncompressed_size\tcompression\ttypecode",
        ]
        for name, offset, clen, ulen, cflag, typecode in info['entries']:
            manifest.append(
                f"{name}\t0x{offset:x}\t{clen}\t{ulen}\t{cflag}\t{typecode.decode('latin-1')}")
        try:
            (dirs['base'] / "manifest.txt").write_text(
                "\n".join(manifest) + "\n", encoding='utf-8')
        except Exception:
            pass
        self.logger.info(f"  PyInstaller entries extracted: {written}")

    @staticmethod
    def _pyinstaller_python_version(raw):
        mapping = {37: '3.7', 38: '3.8', 39: '3.9', 310: '3.10', 311: '3.11',
                   312: '3.12', 313: '3.13'}
        if raw in mapping:
            return mapping[raw]
        digits = str(raw)
        if len(digits) >= 2:
            return f'{digits[0]}.{digits[1:]}'
        return str(raw)

    def _write_pyinstaller_toc(self, toc, archive_start, toc_offset, dirs, pyver):
        written = 0
        for name, offset, clen, ulen, cflag, typecode in toc:
            data_start = archive_start + offset
            if offset < 0 or clen < 0 or data_start + clen > archive_start + toc_offset:
                continue
            raw = self.data[data_start:data_start + clen]
            try:
                if cflag:
                    payload = zlib.decompress(raw)
                else:
                    payload = raw
            except Exception:
                continue
            if not payload:
                continue
            safe = re.sub(r'[^A-Za-z0-9._-]+', '_', name.replace('/', '_').replace('\\', '_')).strip('._')
            if not safe:
                safe = f'entry_{data_start:x}'
            try:
                if typecode in (b's', b'm'):
                    target = dirs['scripts'] if typecode == b's' else dirs['modules']
                    fname = target / f'{safe}.pyc'
                    fname.write_bytes(self._pyc_with_header(payload, pyver))
                    written += 1
                elif typecode == b'z':
                    fname = dirs['base'] / (safe if safe.endswith('.pyz') else f'{safe}.pyz')
                    fname.write_bytes(payload)
                    written += 1
                    written += self._extract_pyz(payload, dirs['pyz'])
                else:
                    fname = dirs['data'] / (safe if '.' in safe else f'{safe}.bin')
                    fname.write_bytes(payload)
                    written += 1
            except Exception:
                continue
        if written:
            self.logger.info(f"    extracted {written} archive entries")
        return written

    @staticmethod
    def _pyc_magic_for(ver_name):
        for magic, version in PYTHON_MAGICS.items():
            if version == ver_name:
                return magic
        return b'\x42\x0d\x0d\x0a'

    @classmethod
    def _pyc_with_header(cls, code_bytes, pyver=None):
        """Turn headerless marshal data into a loadable .pyc for `pyver`."""
        for known in PYTHON_MAGICS:
            if code_bytes.startswith(known):
                return code_bytes
        magic = cls._pyc_magic_for(pyver) if pyver else b'\xa7\x0d\x0d\x0a'
        return magic + b'\x00' * 12 + code_bytes

    def _extract_pyz(self, payload, out_dir):
        """Extract modules from a PYZ archive (zlib + marshalled TOC)."""
        try:
            if payload[:4] != b'PYZ\x00' or len(payload) < 12:
                return 0
            pyc_magic = payload[4:8]
            if pyc_magic not in PYTHON_MAGICS:
                pyc_magic = b'\xa7\x0d\x0d\x0a'
            toc_offset = struct.unpack('!i', payload[8:12])[0]
            if toc_offset <= 0 or toc_offset >= len(payload):
                return 0
            toc_blob = payload[toc_offset:]
            try:
                toc = marshal.load(io.BytesIO(toc_blob))
            except Exception:
                toc = marshal.loads(zlib.decompress(toc_blob))
            if not isinstance(toc, dict):
                if isinstance(toc, list):
                    toc = dict(toc)
                else:
                    return 0
            written = 0
            for name, entry in toc.items():
                try:
                    typecode, offset, length = entry
                except Exception:
                    continue
                if typecode == 1 or offset < 0 or length <= 0 or offset + length > len(payload):
                    continue
                blob = payload[offset:offset + length]
                try:
                    blob = zlib.decompress(blob)
                except Exception:
                    continue
                if not isinstance(blob, (bytes, bytearray)):
                    continue
                safe = re.sub(r'[^A-Za-z0-9._-]+', '_',
                              str(name).replace('/', '_').replace('\\', '_')).strip('._')
                fname = out_dir / f'{safe}.pyc'
                fname.write_bytes(pyc_magic + b'\x00' * 12 + blob)
                written += 1
            if written:
                self.logger.info(f"    PYZ: {written} modules recovered")
            return written
        except Exception:
            return 0

    def _extract_with_pydumpck(self):
        if not self.pyinstaller_confirmed:
            return
        try:
            from pydumpck.py_common_dump import CommonDump
        except Exception as exc:
            self.logger.warning(f"  pydumpck is not available ({exc}); using built-in extractor only")
            return
        out_dir = self.output_dir / "Dumps" / "Pyinstaller"
        out_dir.mkdir(parents=True, exist_ok=True)
        self.logger.info("Extracting PyInstaller contents with pydumpck...")
        root_handlers = list(logging.root.handlers)
        levels = {}
        for name in ('pydumpck', 'sgtpyutils', 'PyInstaller'):
            log = logging.getLogger(name)
            levels[name] = log.level
            log.setLevel(logging.ERROR)
        plugin = []
        try:
            from pydumpck.pyc_checker import lib_pycdc
            if lib_pycdc.get_bin_path() and os.path.isfile(
                    lib_pycdc.get_bin_path() + ('.exe' if os.name == 'nt' else '')):
                plugin = ['pycdc']
        except Exception:
            plugin = []
        old_cwd = os.getcwd()
        try:
            dumper = CommonDump()
            dumper.main(
                target_file=str(self.filepath),
                output_directory=str(out_dir),
                thread=min(8, (os.cpu_count() or 4)),
                timeout=20,
                target_file_type='pe',
                session_timeout=900,
                plugin=plugin,
                decompile_file=None,
                struct_headers=None,
            )
        except SystemExit as exc:
            self.logger.warning(f"  pydumpck stopped: {exc}")
        except Exception as exc:
            self.logger.warning(f"  pydumpck failed: {exc}")
        finally:
            os.chdir(old_cwd)
            logging.root.handlers[:] = root_handlers
            for name, level in levels.items():
                logging.getLogger(name).setLevel(level)
        count = sum(len(files) for _root, _dirs, files in os.walk(out_dir))
        self.logger.info(f"  pydumpck: {count} files in Dumps/Pyinstaller")

    def _extract_zip_bytecode(self):
        """Extract .pyc files from a ZIP payload appended to the executable."""
        try:
            import zipfile
            if not zipfile.is_zipfile(str(self.filepath)):
                return
        except Exception:
            return
        self.logger.info("ZIP payload detected (cx_Freeze / zipapp), extracting bytecode...")
        out_dir = self.output_dir / "Recovered" / "bytecode_zip"
        out_dir.mkdir(parents=True, exist_ok=True)
        count = 0
        try:
            import zipfile
            with zipfile.ZipFile(str(self.filepath)) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    name = info.filename
                    if not (name.endswith('.pyc') or name.endswith('.py') or
                            name.endswith('.pyd') or name.endswith('.so')):
                        continue
                    safe = name.replace('/', '_').replace('\\', '_')
                    try:
                        blob = zf.read(info)
                    except Exception:
                        continue
                    (out_dir / safe).write_bytes(blob)
                    count += 1
        except Exception as exc:
            self.logger.warning(f"  ZIP extraction failed: {exc}")
        if count:
            self.logger.info(f"  ZIP entries extracted: {count}")

    def _extract_single_file_bytecode(self):
        """Recover marshalled code objects from zlib streams in the image."""
        out_dir = self.output_dir / "Recovered" / "bytecode_decoded"
        out_dir.mkdir(parents=True, exist_ok=True)
        found = 0
        attempts = 0
        for match in re.finditer(rb'\x78[\x01\x5e\x9c\xda]', self.data):
            start = match.start()
            attempts += 1
            if attempts > 200000:
                break
            try:
                dec = zlib.decompressobj()
                blob = dec.decompress(self.data[start:start + 2 * 1024 * 1024])
            except Exception:
                continue
            if not blob or len(blob) < 16:
                continue
            stream = io.BytesIO(blob)
            try:
                obj = marshal.load(stream)
            except Exception:
                continue
            if not isinstance(obj, types.CodeType):
                continue
            body = blob[:stream.tell()]
            fname = out_dir / f'marshal_{start:08x}.pyc'
            try:
                fname.write_bytes(self._pyc_with_header(body))
                found += 1
            except Exception:
                continue
            if found >= 5000:
                break
        if found:
            self.logger.info(f"  zlib+marshal streams recovered: {found}")

    def _extract_frozen_modules(self):
        self.logger.info("Searching for frozen module names...")
        frozen_dir = self.output_dir / "Dumps" / "frozen_modules"
        patterns = [
            rb'([A-Za-z0-9_/\\]+\.py)\x00',
            rb'__frozen__([A-Za-z0-9_]+)',
            rb'frozen_module_([A-Za-z0-9_]+)',
            rb'module_([a-z_]+)_frozen',
        ]
        found_modules = set()
        for data_source in [self.data, self.rsrc_data]:
            if not data_source:
                continue
            for pattern in patterns:
                for match in re.finditer(pattern, data_source):
                    try:
                        mod_name = match.group(1).decode('ascii', errors='replace')
                        mod_offset = match.start()
                        if 3 < len(mod_name) < 200:
                            found_modules.add((mod_name, mod_offset))
                    except:
                        pass
        for mod_name, mod_offset in found_modules:
            mod_end = min(mod_offset + 512, len(self.data))
            chunk = self.data[mod_offset:mod_end]
            safe_name = mod_name.replace('/', '_').replace('\\', '_').replace('.', '_')
            fname = frozen_dir / f"{safe_name}_{mod_offset:08x}.bin"
            fname.write_bytes(chunk)
        self.found_frozen_modules = list(found_modules)
        self.logger.info(f"  Frozen module candidates: {len(found_modules)}")

    def _extract_nuitka_constants(self):
        self.logger.info("Extracting Nuitka constant tables...")
        const_patterns = [
            rb'(?:PyObject\*|PyConst|constant_)[\x20-\x7e]{0,50}',
            rb'__constant_table_[\x20-\x7e]{0,50}',
        ]
        constants = []
        for pattern in const_patterns:
            for match in re.finditer(pattern, self.data):
                try:
                    val = match.group().decode('ascii', errors='replace')
                    constants.append(val)
                except:
                    pass
        self._write_list(self.output_dir / "Analysis" / "constants.txt", constants[:10000])

    def _extract_python_object_headers(self):
        """Carve PyObject/PyTypeObject records from the image and embedded DLLs.

        CPython exports and type-name tables keep strings such as
        ``PyObject_GetAttr`` or ``PyTypeObject`` next to the object layout, so
        the surrounding bytes are useful as memory snapshots.
        """
        self.logger.info("Scanning for Python object headers...")
        pyobj_dir = self.output_dir / "Dumps" / "memory" / "py_objects"
        pyobj_dir.mkdir(parents=True, exist_ok=True)
        markers = (
            b'PyTypeObject', b'PyCodeObject', b'PyUnicodeObject',
            b'PyBytesObject', b'PyTupleObject', b'PyDictObject',
            b'PyListObject', b'PyModuleObject', b'PyLongObject',
            b'PyFrameObject', b'PyObject',
        )
        index = ["source\toffset\tva\tmarker\tpreview"]
        total = 0
        seen = set()
        for source, blob, offset_map in self._memory_sources():
            if not blob:
                continue
            hits = {}
            for marker in markers:
                pos = blob.find(marker)
                while pos >= 0:
                    hits.setdefault(pos, marker)
                    pos = blob.find(marker, pos + 1)
            for pos in sorted(hits):
                if total >= 6000:
                    break
                start = max(0, pos - 32)
                end = min(len(blob), pos + 224)
                chunk = blob[start:end]
                key = (source, start)
                if key in seen:
                    continue
                seen.add(key)
                va = offset_map(start) if offset_map else None
                stem = f"{source}_{pos:08x}"
                try:
                    (pyobj_dir / f"{stem}.bin").write_bytes(chunk)
                except Exception:
                    continue
                preview = re.sub(rb'[^\x20-\x7e]+', b'.', chunk[32:96])
                preview = preview.decode('ascii', 'replace')
                va_text = f"0x{va:x}" if va else "-"
                index.append(f"{source}\t0x{pos:x}\t{va_text}\t"
                             f"{hits[pos].decode('ascii')}\t{preview}")
                total += 1
        self.pyobj_count = total
        try:
            (pyobj_dir / "index.txt").write_text(
                "\n".join(index) + "\n", encoding='utf-8')
        except Exception:
            pass
        self.logger.info(f"  Python object headers extracted: {total}")

    def _memory_sources(self):
        """Yield (label, bytes, offset->VA mapper) for memory carving."""
        sources = []
        if self.data:
            sources.append(('image', self.data, self._offset_to_va))
        if self.rsrc_data:
            sources.append(('rsrc', self.rsrc_data, None))
        overlay = getattr(self, 'overlay_data', b'')
        if overlay:
            sources.append(('overlay', overlay, None))
        roots = []
        for candidate in (self.output_dir / "Dumps" / "Pyinstaller",
                          self.output_dir / "Recovered" / "pyinstaller"):
            if candidate.is_dir():
                roots.append(candidate)
        for root in roots:
            for path in list(root.rglob('*.dll')) + list(root.rglob('*.pyd')):
                try:
                    if path.stat().st_size > 64 * 1024 * 1024:
                        continue
                    blob = path.read_bytes()
                except Exception:
                    continue
                label = 'dll_' + re.sub(r'[^A-Za-z0-9._-]+', '_', path.stem)
                sources.append((label, blob, None))
        return sources

    def _extract_nuitka_memory_structures(self):
        self.logger.info("Scanning for Nuitka memory structures...")
        out_dir = self.output_dir / "Dumps" / "memory" / "nuitka_structs"
        out_dir.mkdir(parents=True, exist_ok=True)
        markers = (
            b'nuitka_version', b'__compiled__', b'__constants',
            b'constant_bin', b'modulecode', b'compiled_code',
            b'compiled_function', b'Nuitka', b'nuitka',
        )
        index = ["source\toffset\tva\tmarker\tsize\tpreview"]
        total = 0
        seen = set()
        for source, blob, offset_map in self._memory_sources():
            if not blob:
                continue
            hits = {}
            for marker in markers:
                pos = blob.find(marker)
                while pos >= 0:
                    hits.setdefault(pos, marker)
                    pos = blob.find(marker, pos + 1)
            for pos in sorted(hits):
                if total >= 4000:
                    break
                start = max(0, pos - 128)
                end = min(len(blob), pos + 896)
                chunk = blob[start:end]
                key = (source, start)
                if key in seen:
                    continue
                seen.add(key)
                va = offset_map(start) if offset_map else None
                stem = f"{source}_{pos:08x}"
                try:
                    (out_dir / f"{stem}.bin").write_bytes(chunk)
                except Exception:
                    continue
                preview = re.sub(rb'[^\x20-\x7e]+', b'.', chunk)
                va_text = f"0x{va:x}" if va else "-"
                index.append(f"{source}\t0x{pos:x}\t{va_text}\t"
                             f"{hits[pos].decode('ascii', 'replace')}\t"
                             f"{len(chunk)}\t{preview.decode('ascii', 'replace')[:120]}")
                total += 1
        try:
            (out_dir / "index.txt").write_text(
                "\n".join(index) + "\n", encoding='utf-8')
        except Exception:
            pass
        self.logger.info(f"  Nuitka structures extracted: {total}")

    def _extract_source_paths(self):
        self.logger.info("Extracting source file paths...")
        paths = set()
        path_regexes = [
            rb'([A-Za-z]:\\[A-Za-z0-9_\\/\-\. ]{5,200})',
            rb'(/[A-Za-z0-9_\\/\-\. ]{5,200})',
            rb'([A-Za-z0-9_/\\]{3,}\.py)',
        ]
        sections_to_scan = ['.rdata', '.data']
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='replace').strip('\x00')
            if name in sections_to_scan:
                try:
                    section_data = section.get_data()
                    for regex in path_regexes:
                        for match in re.finditer(regex, section_data):
                            try:
                                p = match.group(1).decode('ascii', errors='strict')
                                p = p.strip('\x00').strip()
                                if p and len(p) > 5 and all(c in string.printable for c in p):
                                    paths.add(p)
                            except:
                                pass
                except:
                    pass
        self.extracted_paths.update(paths)
        self._write_list(self.output_dir / "Analysis" / "source_paths.txt", sorted(paths))
        self.logger.info(f"  Source paths found: {len(paths)}")

    def _extract_variable_names(self):
        self.logger.info("Extracting variable/function names...")
        var_patterns = [rb'([a-z_][a-z0-9_]{3,50})\x00']
        names = set()
        sections_to_scan = ['.rdata', '.data']
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='replace').strip('\x00')
            if name in sections_to_scan:
                try:
                    section_data = section.get_data()
                    for pattern in var_patterns:
                        for match in re.finditer(pattern, section_data, re.IGNORECASE):
                            try:
                                vname = match.group(1).decode('ascii', errors='replace')
                                if vname.isidentifier() and not vname.startswith('__'):
                                    names.add(vname)
                            except:
                                pass
                except:
                    pass
        names = {n for n in names if not n.startswith('0') and len(n) < 100}
        self._write_list(self.output_dir / "Analysis" / "variable_names.txt", sorted(names)[:5000])
        self.logger.info(f"  Variable names extracted: {len(names)}")

    def _extract_nuitka_onefile_payload(self):
        self.logger.info("Searching for Nuitka OneFile payload...")
        payload_dir = self.output_dir / "Dumps" / "payloads"
        decompressed_count = 0
        if self.rsrc_data and len(self.rsrc_data) > 0:
            self.logger.info(
                f"  Scanning .rsrc section ({len(self.rsrc_data):,} bytes, entropy: {self.rsrc_entropy:.2f}/8.0)")
            if HAS_ZSTD:
                decompressed_count += self._try_zstd_decompress(self.rsrc_data, payload_dir)
            else:
                self.logger.warning("  zstandard not available, install: pip install zstandard")
            decompressed_count += self._try_zlib_decompress(self.rsrc_data, payload_dir, ".rsrc")
            if HAS_LZMA:
                decompressed_count += self._try_lzma_decompress(self.rsrc_data, payload_dir)
            if HAS_LZ4:
                decompressed_count += self._try_lz4_decompress(self.rsrc_data, payload_dir)
        if decompressed_count == 0:
            self.logger.info("  No payloads decompressed from .rsrc")
        else:
            self.logger.info(f"  Total payloads decompressed: {decompressed_count}")

    def _extract_payloads(self):
        """Recover compressed payloads from the overlay and the whole image."""
        self._extract_nuitka_onefile_payload()
        payload_dir = self.output_dir / "Dumps" / "payloads"
        payload_dir.mkdir(parents=True, exist_ok=True)
        overlay = self._overlay_bytes()
        total = 0
        if overlay and not self.pyinstaller_confirmed:
            self.logger.info(f"  Scanning overlay ({len(overlay):,} bytes) for payloads...")
            if HAS_ZSTD:
                total += self._try_zstd_decompress(overlay, payload_dir)
            total += self._try_gzip_decompress(overlay, payload_dir)
            total += self._try_zlib_decompress(overlay, payload_dir, "overlay")
            if HAS_LZMA:
                total += self._try_lzma_decompress(overlay, payload_dir)
            if HAS_LZ4:
                total += self._try_lz4_decompress(overlay, payload_dir)
        if self.detected_nuitka and self.data:

            if HAS_ZSTD:
                total += self._try_zstd_decompress(self.data, payload_dir)
            total += self._try_gzip_decompress(self.data, payload_dir)
        if total:
            self.logger.info(f"  Additional payloads decompressed: {total}")
        self._write_payload_index(payload_dir)

    def _overlay_bytes(self):
        if not self.pe or not self.pe.sections:
            return b''
        last = self.pe.sections[-1]
        end = last.PointerToRawData + last.SizeOfRawData
        return self.data[end:] if end < len(self.data) else b''

    def _write_payload_index(self, payload_dir):
        lines = ["file\tsize"]
        for path in sorted(payload_dir.rglob('*')):
            if path.is_file() and path.name != 'payload_index.txt':
                lines.append(f"{path.relative_to(payload_dir)}\t{path.stat().st_size}")
        try:
            (payload_dir / "payload_index.txt").write_text(
                "\n".join(lines) + "\n", encoding='utf-8')
        except Exception:
            pass

    def _try_gzip_decompress(self, data, payload_dir):
        count = 0
        offset = 0
        while True:
            offset = data.find(b'\x1f\x8b\x08', offset)
            if offset == -1:
                break
            chunk = data[offset:offset + 4 * 1024 * 1024]
            try:
                dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
                blob = dec.decompress(chunk)
            except Exception:
                offset += 3
                continue
            if blob and len(blob) > 1024:
                fname = payload_dir / f"gzip_decompressed_{offset:08x}.bin"
                try:
                    fname.write_bytes(blob)
                except Exception:
                    offset += 3
                    continue
                count += 1
                self.logger.info(
                    f"  [PAYLOAD GZIP] Decompressed {len(blob):,} bytes at 0x{offset:08x}")
                self._scan_data_for_patterns(blob)
            offset += 3
        return count

    def _try_zstd_decompress(self, data, payload_dir):
        zstd_magic = b'\x28\xb5\x2f\xfd'
        count = 0
        offset = 0
        tried = set()
        while True:
            offset = data.find(zstd_magic, offset)
            if offset == -1:
                break
            if offset in tried:
                offset += 4
                continue
            tried.add(offset)
            try:
                dctx = zstd.ZstdDecompressor()
                reader = dctx.stream_reader(data[offset:])
                blob = reader.read(64 * 1024 * 1024)
                reader.close()
                if len(blob) > 4096:
                    fname = payload_dir / f"zstd_decompressed_{offset:08x}.bin"
                    fname.write_bytes(blob)
                    count += 1
                    self.logger.info(
                        f"  [PAYLOAD ZSTD] Decompressed {len(blob):,} bytes at 0x{offset:08x}")
                    self._scan_data_for_patterns(blob)
            except Exception:
                pass
            offset += 4
        return count

    def _try_zlib_decompress(self, data, payload_dir, source_name):
        zlib_sigs = (b'\x78\x9c', b'\x78\x01', b'\x78\xda', b'\x78\x5e')
        count = 0
        attempts = 0
        for sig in zlib_sigs:
            offset = 0
            while True:
                offset = data.find(sig, offset)
                if offset == -1:
                    break
                attempts += 1
                if attempts > 20000:
                    return count
                chunk = data[offset:offset + 8 * 1024 * 1024]
                try:
                    dec = zlib.decompressobj()
                    decompressed = dec.decompress(chunk, 16 * 1024 * 1024)
                except Exception:
                    offset += len(sig)
                    continue
                if len(decompressed) > 4096:
                    try:
                        fname = payload_dir / \
                            f"zlib_decompressed_{source_name}_{offset:08x}.bin"
                        fname.write_bytes(decompressed)
                    except Exception:
                        offset += len(sig)
                        continue
                    count += 1
                    if count <= 8:
                        self.logger.info(
                            f"  [PAYLOAD ZLIB] Decompressed {len(decompressed):,} bytes at 0x{offset:08x}")
                    self._scan_data_for_patterns(decompressed)
                    consumed = len(chunk) - len(dec.unused_data)
                    offset += max(consumed, len(sig))
                else:
                    offset += len(sig)
        return count

    def _try_lzma_decompress(self, data, payload_dir):
        lzma_magic = b'\xfd7zXZ\x00'
        count = 0
        offset = 0
        tried = set()
        while True:
            offset = data.find(lzma_magic, offset)
            if offset == -1:
                break
            if offset in tried:
                offset += len(lzma_magic)
                continue
            tried.add(offset)
            for window in [65536, 131072, 262144, 524288, 1048576]:
                if offset + window > len(data):
                    continue
                chunk = data[offset:offset + window]
                try:
                    decompressed = lzma.decompress(chunk)
                    if len(decompressed) > 4096:
                        fname = payload_dir / f"lzma_decompressed_{offset:08x}.bin"
                        fname.write_bytes(decompressed)
                        count += 1
                        self.logger.info(f"  [PAYLOAD LZMA] Decompressed {len(decompressed):,} bytes at 0x{offset:08x}")
                        self._scan_data_for_patterns(decompressed)
                except:
                    pass
            offset += len(lzma_magic)
        return count

    def _try_lz4_decompress(self, data, payload_dir):
        lz4_magic = b'\x04\x22\x4d\x18'
        count = 0
        offset = 0
        tried = set()
        while True:
            offset = data.find(lz4_magic, offset)
            if offset == -1:
                break
            if offset in tried:
                offset += len(lz4_magic)
                continue
            tried.add(offset)
            for window in [65536, 131072, 262144, 524288, 1048576]:
                if offset + window > len(data):
                    continue
                chunk = data[offset:offset + window]
                try:
                    decompressed = lz4.frame.decompress(chunk)
                    if len(decompressed) > 4096:
                        fname = payload_dir / f"lz4_decompressed_{offset:08x}.bin"
                        fname.write_bytes(decompressed)
                        count += 1
                        self.logger.info(f"  [PAYLOAD LZ4] Decompressed {len(decompressed):,} bytes at 0x{offset:08x}")
                        self._scan_data_for_patterns(decompressed)
                except:
                    pass
            offset += len(lz4_magic)
        return count

    def _dump_info(self):
        self.logger.info("Collecting metadata...")
        info_dir = self.output_dir / "Info"
        gen_info = []
        if self.pe:
            gen_info.append(f"File type: PE (Portable Executable)")
            gen_info.append(f"Architecture: {'x64' if self.pe.FILE_HEADER.Machine == 0x8664 else 'x86'}")
            gen_info.append(f"Subsystem: {'GUI' if self.pe.OPTIONAL_HEADER.Subsystem == 2 else 'Console'}")
            gen_info.append(f"Entry point: 0x{self.pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}")
            gen_info.append(f"Image base: 0x{self.pe.OPTIONAL_HEADER.ImageBase:016x}")
            gen_info.append(f"Number of sections: {len(self.pe.sections)}")
        else:
            gen_info.append(f"File type: Raw binary")
        gen_info.append(f"File size: {len(self.data):,} bytes ({len(self.data) / 1024 / 1024:.2f} MB)")
        gen_info.append(f"Packager: {self.detected_packager or 'Unknown'}")
        pe_end = 0
        if self.pe:
            last = self.pe.sections[-1]
            pe_end = last.PointerToRawData + last.SizeOfRawData
        payload = len(self.data) - pe_end if pe_end > 0 else len(self.data)
        if payload == 0 and self.rsrc_data:
            payload = len(self.rsrc_data)
        gen_info.append(f"Payload size: {payload:,} bytes ({payload / 1024 / 1024:.2f} MB)")
        gen_info.append(f"Payload compression: {str(payload < len(self.data) * 0.95).lower()}")
        if len(self.data) > 0:
            ratio = payload / len(self.data) * 100 if payload > 0 else 0
            gen_info.append(f"Compression ratio: {ratio:.1f}%")
        gen_info.append(
            f"Timestamp: {datetime.datetime.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp) if self.pe else 'N/A'}")
        self._write_list(info_dir / "general.txt", gen_info)
        if self.pe:
            pe_hdr = self.pe.dump_info()
            (info_dir / "pe_header.txt").write_text(pe_hdr, encoding='utf-8')
            sec_info = []
            for sec in self.pe.sections:
                name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                ent = self._calc_entropy(sec.get_data()) if sec.SizeOfRawData > 0 else 0
                exec_flag = "EXEC" if self._is_executable_section(sec) else ""
                sec_info.append(
                    f"{name}: VA=0x{sec.VirtualAddress:08x} RawSize={sec.SizeOfRawData:,} VirtSize={sec.Misc_VirtualSize:,} Entropy={ent:.2f}/8.0 Rights=0x{sec.Characteristics:08x} {exec_flag}")
            self._write_list(info_dir / "sections.txt", sec_info)
            imports = []
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='replace')
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(f"{dll}: {imp.name.decode('utf-8', errors='replace')}")
            self._write_list(info_dir / "imports.txt", imports)
            python_imports = [i for i in imports if 'Py' in i or 'python' in i.lower()]
            self._write_list(info_dir / "imports_python.txt", python_imports)
            exports = []
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode('utf-8', errors='replace'))
            self._write_list(info_dir / "exports.txt", exports)
            compiler = "Unknown"
            if b'GCC' in self.data or b'MinGW' in self.data or b'gcc' in self.data:
                compiler = "MinGW GCC"
            elif b'MSVC' in self.data or b'cl.exe' in self.data:
                compiler = "MSVC"
            elif b'Clang' in self.data or b'LLVM' in self.data:
                compiler = "Clang/LLVM"
            prot = []
            if self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100:
                prot.append("DEP enabled")
            if self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
                prot.append("ASLR enabled")
            if self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0080:
                prot.append("High Entropy ASLR (64-bit)")
            if hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'):
                try:
                    if self.pe.DIRECTORY_ENTRY_SECURITY:
                        prot.append("Digitally signed")
                except:
                    pass
            self._write_list(info_dir / "protection.txt", prot)
        if self.detected_python:
            (info_dir / "python_version.txt").write_text(f"Python version: {self.detected_python}")
        if self.detected_nuitka:
            (info_dir / "nuitka_version.txt").write_text(f"Nuitka: detected\nPackager: {self.detected_packager}")
        if self.detected_pyinstaller:
            (info_dir / "pyinstaller_version.txt").write_text(
                f"PyInstaller: detected\nPackager: {self.detected_packager}")
        if self.detected_cx_freeze:
            (info_dir / "cx_freeze_version.txt").write_text(f"cx_Freeze: detected\nPackager: {self.detected_packager}")

    def _dump_hashes(self):
        self.logger.info("Calculating hashes...")
        hashes = []
        hashes.append(f"MD5:    {hashlib.md5(self.data).hexdigest()}")
        hashes.append(f"SHA1:   {hashlib.sha1(self.data).hexdigest()}")
        hashes.append(f"SHA256: {hashlib.sha256(self.data).hexdigest()}")
        self._write_list(self.output_dir / "Info" / "hashes.txt", hashes)

    def _dump_entropy(self):
        self.logger.info("Calculating entropy...")
        entropy_lines = []
        if self.pe:
            for sec in self.pe.sections:
                name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                try:
                    data = sec.get_data()
                    ent = self._calc_entropy(data)
                    entropy_lines.append(f"{name}: entropy={ent:.2f}/8.0 ({len(data):,} bytes)")
                except:
                    pass
        else:
            ent = self._calc_entropy(self.data)
            entropy_lines.append(f"Full file: entropy={ent:.2f}/8.0")
        self._write_list(self.output_dir / "Info" / "entropy.txt", entropy_lines)

    def _calc_entropy(self, data):
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _dump_disasm(self):
        if capstone is None:
            self.logger.warning("Capstone not installed. Skipping disassembly.")
            return
        if not self.pe:
            return
        self.logger.info("Disassembling entry point and code sections...")
        disasm_dir = self.output_dir / "Disasm"
        try:
            arch_mode = self._get_arch_mode()
            md = Cs(CS_ARCH_X86, arch_mode)
            md.detail = True
            md.skipdata = True
            ep_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_offset = self.pe.get_offset_from_rva(ep_rva)
            if ep_offset is None:
                ep_offset = self.pe.get_offset_from_rva(ep_rva - self.pe.OPTIONAL_HEADER.ImageBase)
            if ep_offset and ep_offset + 4096 <= len(self.data):
                code = self.data[ep_offset:ep_offset + 4096]
                lines = []
                for insn in md.disasm(code, ep_rva + self.pe.OPTIONAL_HEADER.ImageBase):
                    comment = self._get_insn_comment(insn, code)
                    lines.append(f"0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str:30s} {comment}")
                self._write_list(disasm_dir / "entry_point.asm", lines)
                self.logger.info(f"  Entry point: {len(lines)} instructions")
            for section in self.pe.sections:
                name = section.Name.decode('utf-8', errors='replace').strip('\x00')
                if b'.text' in section.Name or name == 'CODE':
                    try:
                        data = section.get_data()[:8192]
                        lines = []
                        for insn in md.disasm(data, section.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase):
                            comment = self._get_insn_comment(insn, data)
                            lines.append(f"0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str:30s} {comment}")
                        self._write_list(disasm_dir / f"section_{name}.asm", lines[:500])
                    except:
                        pass
        except Exception as e:
            self.logger.warning(f"  Disassembly failed: {e}")

    def _dump_disasm_full(self):
        if capstone is None:
            return
        if not self.pe:
            return
        self.logger.info("Full disassembly of all executable sections...")
        full_dir = self.output_dir / "Disasm" / "full"
        try:
            arch_mode = self._get_arch_mode()
            md = Cs(CS_ARCH_X86, arch_mode)
            md.detail = True
            md.skipdata = True
            for section in self.pe.sections:
                name = section.Name.decode('utf-8', errors='replace').strip('\x00')
                if self._is_executable_section(section):
                    try:
                        data = section.get_data()
                        lines = []
                        for insn in md.disasm(data, section.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase):
                            comment = self._get_insn_comment(insn, data)
                            lines.append(f"0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str:30s} {comment}")
                        fname = full_dir / f"{name}_full.asm"
                        self._write_list(fname, lines)
                        self.logger.info(f"  Section {name}: {len(lines)} instructions")
                    except Exception as e:
                        self.logger.warning(f"  Failed full disasm of {name}: {e}")
        except Exception as e:
            self.logger.warning(f"  Full disassembly failed: {e}")

    def _dump_pseudocode(self):
        if self.pseudo_mode == 'standard':
            self._dump_disasm_to_c()
        else:
            self._dump_clean_pseudocode()

    def _pseudo_strings(self):
        result = {}
        for text, offsets in getattr(self, '_string_offsets', {}).items():
            for off in offsets[:8]:
                va = self._offset_to_va(off)
                if va is not None:
                    result.setdefault(va, text)
        return result

    def _clean_function_roots(self, program):
        roots = []
        try:
            ep_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            if ep_rva:
                roots.append(self.image_base + ep_rva)
            for entry in getattr(self.pe, 'DIRECTORY_ENTRY_EXPORT', []).symbols:
                if entry.address:
                    roots.append(self.image_base + entry.address)
        except Exception:
            pass
        roots.extend(sorted(program.pdata_starts))
        return roots

    def _dump_clean_pseudocode(self):
        if capstone is None:
            return
        if not self.pe or not self.virtual_image:
            return
        self.logger.info("Generating Clean pseudocode (IR + CFG + structuring)...")
        out_dir = self.output_dir / "Disasm" / "pseudocode"
        func_dir = out_dir / "functions"
        func_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "environment.h").write_text(ENVIRONMENT_H, encoding='utf-8')

        is64 = self._get_arch_mode() == CS_MODE_64
        strings = self._pseudo_strings()
        program = CPseudoProgram(self.virtual_image, self.image_base, is64,
                                 dict(self.import_name_by_address), self.exec_ranges,
                                 strings, self.logger)
        program.load_pdata(self.pe)
        roots = self._clean_function_roots(program)
        program.discover(roots, max_functions=600, max_insns_per_func=60000)
        self.logger.info(f"  Functions discovered: {len(program.functions)}")

        combined = []
        combined.append(f'/* DeNuitkanizator v{VERSION} - Clean pseudocode')
        combined.append(' * Recursive-descent disassembly -> symbolic-flag IR -> basic blocks')
        combined.append(' * -> flag folding / stack recovery / copy propagation / peephole /')
        combined.append(' * DCE / ABI -> dominator based structuring (if, while, switch).')
        combined.append(' * Names follow IDA Pro conventions (sub_, loc_, var_, arg_, a1..a4).')
        combined.append(' */')
        combined.append('#include "environment.h"')
        combined.append('')

        stats = []
        total_blocks = 0
        structured = 0
        rendered = 0
        size = 0
        per_file = 0
        for addr, func in program.functions.items():
            func.strings = strings
            structurer = None
            try:
                text, structurer, _printer = render_function(func)
            except Exception as exc:
                text = f'// {func.name} @ 0x{addr:X}: rendering failed ({exc})\n'
            rendered += 1
            total_blocks += len(func.blocks)
            if structurer is not None and not structurer.failed:
                structured += 1
            flag = 'structured' if (structurer is not None and not structurer.failed) else 'goto-fallback'
            stats.append(f'0x{addr:016X} {func.name:24s} blocks={len(func.blocks):5d} '
                         f'insns={len(func.insns):7d} {flag}')
            if per_file < 250:
                fname = func_dir / f'{func.name}.c'
                try:
                    fname.write_text(text, encoding='utf-8')
                except Exception:
                    pass
                per_file += 1
            if size < 16 * 1024 * 1024:
                combined.append(text)
                size += len(text)

        (out_dir / "clean_pseudocode.c").write_text('\n'.join(combined), encoding='utf-8')
        (out_dir / "functions_index.txt").write_text('\n'.join(stats), encoding='utf-8')
        self.clean_stats = {
            'functions': rendered,
            'blocks': total_blocks,
            'structured': structured,
            'fallback': rendered - structured,
        }
        self.logger.info(f"  Clean pseudocode: {rendered} functions, {total_blocks} blocks, "
                         f"{structured} structured, {rendered - structured} goto fallbacks")

    def _dump_disasm_to_c(self):
        if capstone is None:
            return
        if not self.pe:
            return
        self.logger.info("Translating disassembly to C (recursive traversal)...")
        code_dir = self.output_dir / "Disasm" / "code"
        (code_dir / "environment.h").write_text(ENVIRONMENT_H, encoding='utf-8')
        arch_mode = self._get_arch_mode()
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='replace').strip('\x00')
            if not self._is_executable_section(section):
                continue
            try:
                data = section.get_data()
                md = Cs(CS_ARCH_X86, arch_mode)
                md.detail = True
                md.skipdata = True
                instructions = list(md.disasm(data, section.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase))
                cg = CGenerator(instructions, self.pe.OPTIONAL_HEADER.ImageBase if self.pe else 0, arch_mode,
                                self.import_name_by_address)
                c_code = cg.generate()
                c_code = cTemplate % c_code
                fname = code_dir / f"{name}_full.c"
                fname.write_text(c_code, encoding='utf-8')
                self.logger.info(f"  Section {name}: C translation written ({cg.stats})")
            except Exception as e:
                self.logger.warning(f"  C translation failed for {name}: {e}")

    def _dump_disasm_functions(self):
        if capstone is None:
            return
        if not self.pe:
            return
        self.logger.info("Extracting function boundaries...")
        func_dir = self.output_dir / "Disasm" / "functions"
        try:
            arch_mode = self._get_arch_mode()
            md = Cs(CS_ARCH_X86, arch_mode)
            md.detail = True
            md.skipdata = True
            function_starts = set()
            if self.pe:
                ep_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
                function_starts.add(ep_rva)
            for section in self.pe.sections:
                if not self._is_executable_section(section):
                    continue
                try:
                    data = section.get_data()
                    for insn in md.disasm(data, section.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase):
                        if insn.mnemonic == 'call':
                            try:
                                target = self._imm_target(insn)
                                if target > 0 and target < self.pe.OPTIONAL_HEADER.ImageBase + 0x10000000:
                                    function_starts.add(target)
                            except:
                                pass
                        if insn.mnemonic == 'jmp':
                            try:
                                target = self._imm_target(insn)
                                if target > 0 and target < self.pe.OPTIONAL_HEADER.ImageBase + 0x10000000:
                                    function_starts.add(target)
                            except:
                                pass
                except:
                    pass
            func_list = sorted(function_starts)
            self._write_list(func_dir / "function_addresses.txt", [f"0x{addr:016x}" for addr in func_list])
            self.logger.info(f"  Function candidates: {len(func_list)}")
        except Exception as e:
            self.logger.warning(f"  Function extraction failed: {e}")

    def _dump_call_graph(self):
        if capstone is None:
            return
        if not self.pe:
            return
        self.logger.info("Building call graph...")
        cg_dir = self.output_dir / "Disasm" / "xrefs"
        try:
            arch_mode = self._get_arch_mode()
            md = Cs(CS_ARCH_X86, arch_mode)
            md.detail = True
            md.skipdata = True
            call_graph = []
            for section in self.pe.sections:
                if not self._is_executable_section(section):
                    continue
                try:
                    data = section.get_data()
                    for insn in md.disasm(data, section.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase):
                        if insn.mnemonic == 'call':
                            try:
                                target = self._imm_target(insn)
                                if target > 0:
                                    call_graph.append(f"0x{insn.address:016x} -> 0x{target:016x}")
                            except:
                                pass
                except:
                    pass
            self._write_list(cg_dir / "call_graph.txt", call_graph[:10000])
            self.logger.info(f"  Call graph entries: {len(call_graph)}")
        except Exception as e:
            self.logger.warning(f"  Call graph failed: {e}")

    def _offset_to_va(self, file_offset):
        if not self.pe:
            return file_offset
        try:
            return self.image_base + self.pe.get_rva_from_offset(file_offset)
        except Exception:
            return None

    def _mem_effective_va(self, insn, op):
        """RIP-aware effective address of a memory operand (or None if not static)."""
        if op.type != X86_OP_MEM:
            return None
        base = op.mem.base
        index = op.mem.index
        disp = op.mem.disp
        if base and insn.reg_name(base).lower() in ('rip', 'eip'):
            return (insn.address + insn.size + disp) & 0xFFFFFFFFFFFFFFFF
        if not base and not index:
            return disp & 0xFFFFFFFFFFFFFFFF
        return None

    def _build_string_va_index(self):
        intervals = []
        for s, offsets in getattr(self, '_string_offsets', {}).items():
            for off in offsets:
                va = self._offset_to_va(off)
                if va is not None:
                    intervals.append((va, va + max(len(s), 1), s))
        intervals.sort(key=lambda x: x[0])
        return intervals

    def _dump_xrefs(self):
        if capstone is None:
            return
        if not self.pe:
            return
        if not getattr(self, '_string_offsets', None):
            return
        self.logger.info("Building cross-references (xrefs)...")
        xrefs_dir = self.output_dir / "Disasm" / "xrefs"
        try:
            import bisect
            arch_mode = self._get_arch_mode()
            md = Cs(CS_ARCH_X86, arch_mode)
            md.detail = True
            md.skipdata = True
            md.skipdata = True
            intervals = self._build_string_va_index()
            starts = [iv[0] for iv in intervals]
            all_xrefs = []
            seen = set()
            for section in self.pe.sections:
                if not self._is_executable_section(section):
                    continue
                try:
                    data = section.get_data()
                    base_va = self.image_base + section.VirtualAddress
                    for insn in md.disasm(data, base_va):
                        if insn.mnemonic not in ('lea', 'mov', 'push', 'cmp'):
                            continue
                        for operand in insn.operands:
                            va = self._mem_effective_va(insn, operand)
                            if va is None:
                                continue
                            idx = bisect.bisect_right(starts, va) - 1
                            if idx < 0:
                                continue
                            start, end, text = intervals[idx]
                            if start <= va < end:
                                key = (insn.address, start)
                                if key in seen:
                                    continue
                                seen.add(key)
                                delta = va - start
                                where = '' if delta == 0 else f' + {delta}'
                                all_xrefs.append(
                                    f'0x{insn.address:x}: {insn.mnemonic} {insn.op_str} -> STRING @ 0x{start + delta:x}{where}: "{text[:80]}"')
                except Exception:
                    continue
            self._write_list(xrefs_dir / "string_xrefs.txt", all_xrefs[:20000])
            self.logger.info(f"  String xrefs found: {len(all_xrefs)}")
        except Exception as e:
            self.logger.warning(f"  Xrefs failed: {e}")

    def _dump_import_xrefs(self):
        if capstone is None:
            return
        if not self.pe:
            return
        if not self.import_name_by_address:
            return
        self.logger.info("Building import cross-references...")
        xrefs_dir = self.output_dir / "Disasm" / "xrefs"
        try:
            arch_mode = self._get_arch_mode()
            md = Cs(CS_ARCH_X86, arch_mode)
            md.detail = True
            md.skipdata = True
            md.skipdata = True
            all_import_xrefs = []
            seen = set()
            for section in self.pe.sections:
                if not self._is_executable_section(section):
                    continue
                try:
                    data = section.get_data()
                    base_va = self.image_base + section.VirtualAddress
                    for insn in md.disasm(data, base_va):
                        if insn.mnemonic not in ('call', 'jmp'):
                            continue
                        if not insn.operands:
                            continue
                        op = insn.operands[0]
                        target_addr = None
                        if op.type == X86_OP_IMM:
                            target_addr = op.imm
                        else:
                            target_addr = self._mem_effective_va(insn, op)
                        if target_addr is None:
                            continue
                        name = self.import_name_by_address.get(target_addr)
                        if not name:
                            continue
                        key = (insn.address, target_addr)
                        if key in seen:
                            continue
                        seen.add(key)
                        all_import_xrefs.append(
                            f"0x{insn.address:016x}: {insn.mnemonic} -> {name}")
                except Exception:
                    continue
            self._write_list(xrefs_dir / "import_xrefs.txt", all_import_xrefs[:20000])
            self.logger.info(f"  Import xrefs found: {len(all_import_xrefs)}")
        except Exception as e:
            self.logger.warning(f"  Import xrefs failed: {e}")

    def _get_insn_comment(self, insn, code):
        comments = []
        raw = self.read_va(insn.address, 8) if self.virtual_image else b''
        if not raw and code:
            off = insn.address - self._code_base_for(insn, code)
            if 0 <= off < len(code):
                raw = code[off:off + 8]
        for anti_debug_pattern in ANTI_DEBUG_PATTERNS:
            if raw and raw[:len(anti_debug_pattern)] == anti_debug_pattern:
                comments.append("[ANTI-DEBUG]")
                break
        if insn.mnemonic == 'call':
            comments.append("[CALL]")
        elif insn.mnemonic in {'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jl', 'jge', 'jle'}:
            comments.append("[JMP]")
        elif insn.mnemonic == 'ret':
            comments.append("[RET]")
        return "; ".join(comments) if comments else ""

    def _code_base_for(self, insn, code):
        """Best-effort base VA of the buffer an instruction was decoded from."""
        if self.pe:
            base = self.pe.OPTIONAL_HEADER.ImageBase
            for section in self.pe.sections:
                try:
                    data = section.get_data()
                    if insn.address - base - section.VirtualAddress < len(data):
                        return base + section.VirtualAddress
                except Exception:
                    continue
        return 0

    def _dump_analysis(self):
        self.logger.info("Running analysis...")
        analysis_dir = self.output_dir / "Analysis"
        if self.found_bytecodes:
            bc_map = []
            for ver, offset, ctx in self.found_bytecodes:
                bc_map.append(f"{ver}: offset=0x{offset:08x} context={ctx}")
            self._write_list(analysis_dir / "bytecode_map.txt", bc_map)
            versions = Counter(v for v, _, _ in self.found_bytecodes)
            if versions:
                python_ver = versions.most_common(1)[0][0]
                self.detected_python = python_ver
                (analysis_dir / "python_version.txt").write_text(f"Python version: {python_ver}")
        if self.found_frozen_modules:
            frozen_list = [f"{name} @ 0x{offset:08x}" for name, offset in self.found_frozen_modules]
            self._write_list(analysis_dir / "frozen_modules.txt", frozen_list)
        if self.extracted_modules:
            self._write_list(analysis_dir / "module_list.txt", sorted(self.extracted_modules))

    def _dump_suspicious(self):
        self.logger.info("Scanning for suspicious patterns...")
        susp_dir = self.output_dir / "Suspicious"
        anti_debug_found = []
        for api in ANTI_DEBUG_APIS:
            if api in self.data:
                anti_debug_found.append(api.decode('ascii'))
        if anti_debug_found:
            self._write_list(susp_dir / "anti_debug" / "found.txt", anti_debug_found)
            self.logger.warning(f"  Anti-debug APIs: {len(anti_debug_found)} found")
        if self.pe:
            packed = []
            for sec in self.pe.sections:
                name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                if sec.SizeOfRawData > 0 and sec.Misc_VirtualSize > 0:
                    ratio = sec.Misc_VirtualSize / sec.SizeOfRawData
                    if ratio > 1.5 or ratio < 0.5:
                        packed.append(f"{name}: raw={sec.SizeOfRawData} virt={sec.Misc_VirtualSize} ratio={ratio:.2f}")
            if packed:
                self._write_list(susp_dir / "packed_sections" / "packed.txt", packed)
        high_entropy_blocks = []
        if self.pe:
            for sec in self.pe.sections:
                try:
                    data = sec.get_data()
                    ent = self._calc_entropy(data)
                    if ent > 7.0:
                        name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                        high_entropy_blocks.append(f"{name}: entropy={ent:.2f}/8.0 ({len(data):,} bytes)")
                except:
                    pass
        if high_entropy_blocks:
            self._write_list(susp_dir / "encrypted_blocks" / "high_entropy.txt", high_entropy_blocks)

    def _dump_compressed_blocks(self):
        self.logger.info("Scanning for compressed blocks in .rsrc only...")
        comp_dir = self.output_dir / "Suspicious" / "compressed_blocks"
        comp_signatures = {
            b'\x78\x9c': 'zlib_default', b'\x78\x01': 'zlib_none',
            b'\x78\xda': 'zlib_best', b'\x1f\x8b\x08': 'gzip',
            b'BZh': 'bzip2', b'\xfd7zXZ\x00': 'lzma',
            b'\x50\x4b\x03\x04': 'zip', b'\x04\x22\x4d\x18': 'lz4',
        }
        search_data = self.rsrc_data if self.rsrc_data else self.data
        found = []
        for sig, name in comp_signatures.items():
            offset = 0
            while True:
                offset = search_data.find(sig, offset)
                if offset == -1:
                    break
                if self.rsrc_data:
                    actual_offset = self.rsrc_start + offset
                    if not self._is_in_section(actual_offset, '.rsrc'):
                        offset += len(sig)
                        continue
                found.append(f"{name} at 0x{offset:08x}")
                try:
                    chunk = search_data[offset:offset + 65536]
                    fname = comp_dir / f"{name}_{offset:08x}.bin"
                    fname.write_bytes(chunk)
                except:
                    pass
                offset += len(sig)
        if found:
            self._write_list(comp_dir / "found.txt", found)
            self.logger.info(f"  Compressed blocks in .rsrc: {len(found)}")
        else:
            self.logger.info("  No compressed blocks found in .rsrc")

    def _dump_yara_rules(self):
        self.logger.info("Generating YARA rules...")
        analysis_dir = self.output_dir / "Analysis"
        try:
            selected_strings = []
            raw_strings_for_yara = []
            for s in sorted(set(self.extracted_strings)):
                if len(s) >= 6 and len(s) <= 128:
                    if any(c.isalpha() for c in s) and not all(c in string.printable for c in s):
                        continue
                    raw_strings_for_yara.append(s)
            raw_strings_for_yara = raw_strings_for_yara[:50]
            for i, s in enumerate(raw_strings_for_yara):
                escaped = s.replace('\\', '\\\\').replace('"', '\\"')
                selected_strings.append(f"        $str{i} = \"{escaped}\" ascii wide")
            strings_section = "\n".join(
                selected_strings) if selected_strings else "        $dummy = \"DeNuitkanizator_AutoGen\" ascii"
            condition = "any of them" if selected_strings else "$dummy"
            sha256_hash = hashlib.sha256(self.data).hexdigest()
            filename = self.filepath.name
            packager = self.detected_packager or "Unknown"
            date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            yara_rule = YARA_TEMPLATE.format(
                timestamp=datetime.datetime.now().strftime("%Y%m%d_%H%M%S"),
                filename=filename,
                VERSION=VERSION,
                date=date_str,
                packager=packager,
                sha256=sha256_hash,
                strings=strings_section,
                condition=condition,
            )
            (analysis_dir / "yara_rules.yar").write_text(yara_rule, encoding='utf-8')
            self.logger.info(f"  YARA rule generated with {len(selected_strings)} strings")
        except Exception as e:
            self.logger.warning(f"  YARA rule generation failed: {e}")

    def _write_log_copy(self):
        try:
            log_dest = self.output_dir / f"{self.output_dir.name}.log"
            if hasattr(self.logger, 'log_file') and self.logger.log_file.name != str(log_dest):
                shutil.copy(self.logger.log_file.name, log_dest)
        except:
            pass

    def _write_summary(self):
        self.logger.info("Writing summary...")
        summary = []
        summary.append("╔══════════════════════════════════════════════════════════╗")
        summary.append(f"║         DeNuitkanizator v{VERSION} - Analysis Report        ║")
        summary.append("╚══════════════════════════════════════════════════════════╝")
        summary.append("")
        summary.append(f"Target:         {self.filepath.name}")
        summary.append(f"Analysis date:  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary.append(f"Duration:       {self.logger.elapsed():.1f} sec")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" GENERAL")
        summary.append("─" * 54)
        if self.pe:
            summary.append(f"File type:              PE (Portable Executable)")
            summary.append(f"Architecture:           {'x64' if self.pe.FILE_HEADER.Machine == 0x8664 else 'x86'}")
        else:
            summary.append(f"File type:              Raw binary")
        summary.append(f"File size:              {len(self.data):,} bytes ({len(self.data) / 1024 / 1024:.2f} MB)")
        pe_end = 0
        if self.pe:
            last = self.pe.sections[-1]
            pe_end = last.PointerToRawData + last.SizeOfRawData
        payload = len(self.data) - pe_end if pe_end > 0 else len(self.data)
        if payload == 0 and self.rsrc_data:
            payload = len(self.rsrc_data)
        summary.append(f"Payload size:           {payload:,} bytes ({payload / 1024 / 1024:.2f} MB)")
        summary.append(f"Payload compression:    {str(payload < len(self.data) * 0.95).lower()}")
        if len(self.data) > 0:
            ratio = payload / len(self.data) * 100 if payload > 0 else 0
            summary.append(f"Compression ratio:      {ratio:.1f}%")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" HASHES")
        summary.append("─" * 54)
        summary.append(f"MD5:        {hashlib.md5(self.data).hexdigest()}")
        summary.append(f"SHA1:       {hashlib.sha1(self.data).hexdigest()}")
        summary.append(f"SHA256:     {hashlib.sha256(self.data).hexdigest()}")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" PACKER")
        summary.append("─" * 54)
        summary.append(f"Detected:               {self.detected_packager or 'Unknown'}")
        if self.detected_python:
            summary.append(f"Python:                 {self.detected_python}")
        compiler = "Unknown"
        if self.pe:
            if b'GCC' in self.data or b'MinGW' in self.data:
                compiler = "MinGW GCC"
            elif b'MSVC' in self.data:
                compiler = "MSVC"
        summary.append(f"Compiler:               {compiler}")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" BYTECODE / MAGIC")
        summary.append("─" * 54)
        total_bc = len(self.found_bytecodes)
        summary.append(f"Found:                  {total_bc} magic contexts")
        for ver in PYTHON_MAGICS.values():
            count = sum(1 for v, _, _ in self.found_bytecodes if v == ver)
            if count > 0:
                summary.append(f"  {ver}:                 {count} contexts")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" FROZEN MODULES")
        summary.append("─" * 54)
        summary.append(f"Found:                  {len(self.found_frozen_modules)} candidates")
        for name, _ in self.found_frozen_modules[:10]:
            summary.append(f"  {name}")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" STRINGS / MODULES")
        summary.append("─" * 54)
        summary.append(f"Total strings:          {len(set(self.extracted_strings))}")
        summary.append(f"Modules found:          {len(self.extracted_modules)}")
        summary.append(f"IPs found:              {len(self.extracted_ips)}")
        summary.append(f"URLs found:             {len(self.extracted_urls)}")
        summary.append(f"Paths found:            {len(self.extracted_paths)}")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" SECTIONS")
        summary.append("─" * 54)
        if self.pe:
            summary.append(f"{'Name':<12} {'Size':<12} {'Entropy'}")
            for sec in self.pe.sections:
                name = sec.Name.decode('utf-8', errors='replace').strip('\x00')[:11]
                try:
                    ent = self._calc_entropy(sec.get_data())
                except:
                    ent = 0.0
                summary.append(f"{name:<12} {sec.SizeOfRawData:>10,}  {ent:.1f}")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" DISASM")
        summary.append("─" * 54)
        if capstone:
            summary.append(f"Disassembler:           Capstone (active)")
            summary.append(f"Full disasm:            Disasm/full/")
            summary.append(f"C translation:          Disasm/code/ (recursive)")
            summary.append(f"Functions:              Disasm/functions/function_addresses.txt")
            summary.append(f"Call graph:             Disasm/xrefs/call_graph.txt")
            summary.append(f"String xrefs:           Disasm/xrefs/string_xrefs.txt")
            summary.append(f"Import xrefs:           Disasm/xrefs/import_xrefs.txt")
        else:
            summary.append(f"Disassembler:           Not available")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" COMPRESSION")
        summary.append("─" * 54)
        summary.append(f"zstd available:         {str(HAS_ZSTD).lower()}")
        summary.append(f"lz4 available:          {str(HAS_LZ4).lower()}")
        summary.append(f"lzma available:         {str(HAS_LZMA).lower()}")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" YARA")
        summary.append("─" * 54)
        summary.append(f"Rules generated:        Analysis/yara_rules.yar")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" WARNINGS")
        summary.append("─" * 54)
        if not self.detected_nuitka and not self.detected_pyinstaller and self.detected_packager and self.detected_packager != "Nuitka" and self.detected_packager != "PyInstaller" and "Nuitka" not in str(
                self.detected_packager) and "PyInstaller" not in str(self.detected_packager):
            summary.append(f"[WARNING] Unknown packer. Detected: {self.detected_packager}")
        if self.pe:
            for sec in self.pe.sections:
                try:
                    ent = self._calc_entropy(sec.get_data())
                    if ent > 7.5:
                        sec_name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                        summary.append(f"[WARNING] High entropy in {sec_name}")
                except:
                    pass
        if not HAS_ZSTD:
            summary.append("[WARNING] zstandard not installed. Install: pip install zstandard")
        if not HAS_LZ4:
            summary.append("[WARNING] lz4 not installed. Install: pip install lz4")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" OUTPUT")
        summary.append("─" * 54)
        summary.append(f"Full report:    {self.output_dir}")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" EXIT CODE: 0 (Success)")
        summary.append("─" * 54)
        (self.output_dir / "summary.txt").write_text("\n".join(summary), encoding='utf-8')

    def _write_list(self, path, items):
        if items:
            path.write_text("\n".join(sorted(set(items))), encoding='utf-8')

    def _fatal_error(self, code, msg=None):
        errors = {
            1: "File not found or inaccessible. Try to double-check the file path or whether the file exists.",
            2: "You are using an unsupported version of Python (only 3.7, 3.8, 3.9, 3.10, 3.11) or it is modified.",
            3: "Unpacking the .exe file compiled through Nuitka failed:",
            4: "An unknown error has occurred. Probably the .exe file is broken or the .exe file is built by a custom Nuitka fork, or the file is intentionally corrupted, but the program cannot read or unpack it.",
        }
        base = errors.get(code, "Unknown error")
        if code == 3 and msg:
            base = f"{base} {msg}"
        elif code == 2 and msg:
            base = f"{base} Detected: {msg}"
        print(f"\n{Back.RED}{Fore.WHITE} FATAL Error {code}. {base} {Style.RESET_ALL}")
        sys.exit(code)


class CGenerator:
    def __init__(self, instructions, image_base, arch_mode, import_names=None):
        self.instructions = instructions
        self.image_base = image_base
        self.arch_mode = arch_mode
        self.import_names = import_names or {}
        self.c_code = ''
        self.jump_places = set()
        self.translated = 0
        self.commented = 0
        self.visited = set()
        self.call_targets = set()
        self.insn_by_addr = {}
        self._build_index()
        self._build_jump_places()

    @property
    def stats(self):
        total = self.translated + self.commented
        pct = (self.translated / total * 100) if total > 0 else 0
        return f"{self.translated}/{total} instructions translated ({pct:.1f}%)"

    def _build_index(self):
        for insn in self.instructions:
            if insn.address not in self.insn_by_addr:
                self.insn_by_addr[insn.address] = insn

    COND_JUMPS = {
        'je', 'jne', 'jz', 'jnz', 'jb', 'jnae', 'jbe', 'jna', 'ja', 'jnbe',
        'jae', 'jnb', 'jg', 'jnle', 'jge', 'jnl', 'jl', 'jnge', 'jle', 'jng',
        'jo', 'jno', 'js', 'jns', 'jp', 'jpe', 'jnp', 'jpo',
    }

    def _target_of(self, insn):
        """Static branch target of an instruction (immediate operand only)."""
        if not insn.operands:
            return None
        op = insn.operands[0]
        if op.type == X86_OP_IMM:
            return op.imm & 0xFFFFFFFFFFFFFFFF
        return None

    def _mem_va(self, insn, op):
        """Effective VA of a memory operand when it is statically known."""
        if op.type != X86_OP_MEM:
            return None
        if op.mem.base and insn.reg_name(op.mem.base).lower() in ('rip', 'eip'):
            return (insn.address + insn.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
        if not op.mem.base and not op.mem.index:
            return op.mem.disp & 0xFFFFFFFFFFFFFFFF
        return None

    def _mem_ea(self, insn, op):
        """Return (address expression, absolute VA or None) for a memory operand."""
        base = op.mem.base
        index = op.mem.index
        scale = op.mem.scale or 1
        disp = op.mem.disp
        if base and insn.reg_name(base).lower() in ('rip', 'eip'):
            absva = (insn.address + insn.size + disp) & 0xFFFFFFFFFFFFFFFF
            return f'0x{absva:x}', absva
        if not base and not index:
            absva = disp & 0xFFFFFFFFFFFFFFFF
            return f'0x{absva:x}', absva
        expr = ''
        if base:
            expr = self._reg_name(insn, base)
        if index:
            name = self._reg_name(insn, index)
            term = f'{name}*{scale}' if scale != 1 else name
            expr = f'{expr} + {term}' if expr else term
        if disp:
            if expr:
                expr = f'{expr} + {disp}' if disp > 0 else f'{expr} - {abs(disp)}'
            else:
                expr = f'-{abs(disp)}' if disp < 0 else str(disp)
        if not expr:
            expr = '0'
        return expr, None

    def _build_jump_places(self):
        for insn in self.instructions:
            mnemonic = insn.mnemonic
            if mnemonic in self.COND_JUMPS or mnemonic in ('jmp', 'loop', 'loope', 'loopne'):
                target = self._target_of(insn)
                if target is not None:
                    self.jump_places.add(target)
            elif mnemonic == 'call':
                target = self._target_of(insn)
                if target is not None:
                    self.call_targets.add(target)
                    self.jump_places.add(target)

    def _resolve_iat_addr(self, insn, op):
        address = self._mem_va(insn, op)
        if address is None and op.type == X86_OP_IMM:
            address = op.imm & 0xFFFFFFFFFFFFFFFF
        if address is None:
            return None
        return self.import_names.get(address)

    def generate(self):
        if not self.instructions:
            return ''
        entry_point = self.instructions[0].address
        self.visited_blocks = set()
        self.emitted_insns = set()
        self.labels_emitted = set()
        self.c_code = '    /* return-address sentinel for the initial frame */\n    PUSH64((uint64_t)&&_end);\n'
        work = [entry_point]
        while work:
            self._run_block(work.pop(), work)
        self.c_code += '_end:;\n'
        return self.c_code

    def _emit_label(self, address):
        if address in self.labels_emitted:
            return
        self.labels_emitted.add(address)
        self.c_code += f'_0x{address:x}:\n'

    def _run_block(self, address, work):
        """Iterative traversal of one basic block (no Python recursion)."""
        if address in self.visited_blocks:
            return
        insn = self.insn_by_addr.get(address)
        if insn is None:
            return
        self.visited_blocks.add(address)

        while insn is not None:
            addr = insn.address

            if addr in self.emitted_insns:
                if addr in self.jump_places:
                    self._emit_label(addr)
                    self.c_code += f'    goto _0x{addr:x};\n'
                return

            if addr in self.jump_places:
                self._emit_label(addr)
            self.emitted_insns.add(addr)
            mnemonic = insn.mnemonic

            if mnemonic == 'ret':
                ops = list(insn.operands)
                if ops and ops[0].type == X86_OP_IMM and ops[0].imm:
                    self.c_code += f'    rsp += {ops[0].imm};\n'
                self.c_code += '    goto *(void *)(uintptr_t)POP64();\n'
                self.translated += 1
                return

            if mnemonic == 'jmp':
                op = insn.operands[0] if insn.operands else None
                if op is not None and op.type == X86_OP_MEM:
                    iat_name = self._resolve_iat_addr(insn, op)
                    if iat_name:
                        self.c_code += f'    /* jmp -> {iat_name} */\n'
                        self.commented += 1
                        return
                target = self._target_of(insn)
                if target is not None:
                    self.c_code += f'    goto _0x{target:x};\n'
                    self.translated += 1
                    work.append(target)
                else:
                    src = self._op_to_c_val(insn, op) if op is not None else None
                    if src:
                        self.c_code += f'    goto *(void *)(uintptr_t){src};\n'
                        self.translated += 1
                    else:
                        self.c_code += f'    /* jmp {insn.op_str} */\n'
                        self.commented += 1
                return

            if mnemonic in self.COND_JUMPS:
                target = self._target_of(insn)
                condition = self._get_condition(mnemonic)
                if target is not None:
                    self.c_code += f'    if({condition}) goto _0x{target:x};\n'
                    self.translated += 1
                    work.append(target)
                else:
                    self.c_code += f'    /* {mnemonic} {insn.op_str} */\n'
                    self.commented += 1
                nxt = self.insn_by_addr.get(addr + insn.size)
                if nxt is None:
                    return
                insn = nxt
                continue

            if mnemonic in ('loop', 'loope', 'loopne'):
                target = self._target_of(insn)
                if target is not None:
                    if mnemonic == 'loop':
                        condition = '--rcx'
                    elif mnemonic == 'loope':
                        condition = '--rcx && zf'
                    else:
                        condition = '--rcx && !zf'
                    self.c_code += f'    if({condition}) goto _0x{target:x};\n'
                    self.translated += 1
                    work.append(target)
                else:
                    self.c_code += f'    /* {mnemonic} {insn.op_str} */\n'
                    self.commented += 1
                nxt = self.insn_by_addr.get(addr + insn.size)
                if nxt is None:
                    return
                insn = nxt
                continue

            if mnemonic == 'call':
                op = insn.operands[0] if insn.operands else None
                iat_name = self._resolve_iat_addr(insn, op) if op is not None else None
                if iat_name:
                    self.c_code += f'    /* call -> {iat_name} */\n'
                    self.commented += 1
                else:
                    target = self._target_of(insn)
                    if target is not None:
                        self.c_code += (f'    PUSH64((uint64_t)&&_ret_{addr:x}); '
                                        f'goto _0x{target:x}; _ret_{addr:x}:;\n')
                        self.translated += 1
                        work.append(target)
                    elif op is not None:
                        src = self._op_to_c_val(insn, op)
                        self.c_code += f'    /* indirect call {src} */\n'
                        self.commented += 1
                    else:
                        self.c_code += '    /* call */\n'
                        self.commented += 1
                nxt = self.insn_by_addr.get(addr + insn.size)
                if nxt is None:
                    return
                insn = nxt
                continue

            if mnemonic in ('rep', 'repe', 'repne'):
                nxt = self.insn_by_addr.get(addr + insn.size)
                if nxt is not None and nxt.mnemonic in ('stosb', 'stosw', 'stosd', 'stosq',
                                                        'movsb', 'movsw', 'movsd', 'movsq'):
                    handler = self._get_rep_handler(nxt.mnemonic, mnemonic)
                    if handler:
                        try:
                            self.c_code += handler(nxt, list(nxt.operands))
                            self.translated += 1
                            self.emitted_insns.add(nxt.address)
                            after = self.insn_by_addr.get(nxt.address + nxt.size)
                            if after is None:
                                return
                            insn = after
                            continue
                        except Exception:
                            pass
                self.c_code += f'    /* {mnemonic} */\n'
                self.commented += 1
                if nxt is None:
                    return
                insn = nxt
                continue

            handler = self._get_handler(insn)
            if handler:
                try:
                    self.c_code += handler(insn, list(insn.operands))
                    self.translated += 1
                except Exception:
                    self.c_code += f'    /* {mnemonic} {insn.op_str} */\n'
                    self.commented += 1
            else:
                self.c_code += f'    /* {mnemonic} {insn.op_str} */\n'
                self.commented += 1

            nxt = self.insn_by_addr.get(addr + insn.size)
            if nxt is None:
                return
            insn = nxt

    def _get_condition(self, mnemonic):
        conditions = {
            'je': 'zf', 'jz': 'zf',
            'jne': '!zf', 'jnz': '!zf',
            'jb': 'cf', 'jae': '!cf',
            'jbe': 'cf || zf', 'ja': '!cf && !zf',
            'jg': '!zf && sf == of', 'jge': 'sf == of',
            'jl': 'sf != of', 'jle': 'zf || sf != of',
            'jo': 'of', 'jno': '!of',
            'js': 'sf', 'jns': '!sf',
            'jp': 'pf', 'jnp': '!pf',
        }
        return conditions.get(mnemonic, '?')

    def _get_rep_handler(self, mnemonic, rep_prefix):
        handlers = {
            ('stosb', 'rep'): self._h_rep_stosb,
            ('stosw', 'rep'): self._h_rep_stosw,
            ('stosd', 'rep'): self._h_rep_stosd,
            ('stosq', 'rep'): self._h_rep_stosq,
            ('movsb', 'rep'): self._h_rep_movsb,
            ('movsw', 'rep'): self._h_rep_movsw,
            ('movsd', 'rep'): self._h_rep_movsd,
            ('movsq', 'rep'): self._h_rep_movsq,
        }
        return handlers.get((mnemonic, rep_prefix))

    def _get_handler(self, insn):
        mnemonic = insn.mnemonic
        if mnemonic in ('movsd', 'movss', 'cmpsd', 'cmpss', 'comisd', 'comiss', 'ucomisd', 'ucomiss'):
            has_xmm = any(op.type == X86_OP_REG and
                          insn.reg_name(op.reg).lower().startswith(('xmm', 'ymm'))
                          for op in insn.operands)
            if has_xmm:
                sse = {
                    'movsd': self._h_movsd_sse, 'movss': self._h_movss_sse,
                    'cmpsd': self._h_ucomisd, 'cmpss': self._h_ucomiss,
                    'comisd': self._h_ucomisd, 'comiss': self._h_ucomiss,
                    'ucomisd': self._h_ucomisd, 'ucomiss': self._h_ucomiss,
                }
                return sse.get(mnemonic)
        handlers = {
            'mov': self._h_mov, 'movzx': self._h_movzx, 'movsx': self._h_movsx,
            'movsxd': self._h_movsx,
            'movaps': self._h_movaps, 'movups': self._h_movups,
            'movdqa': self._h_movdqa, 'movdqu': self._h_movdqu,
            'lea': self._h_lea, 'xchg': self._h_xchg,
            'push': self._h_push, 'pop': self._h_pop,
            'pusha': self._h_pusha, 'popa': self._h_popa,
            'enter': self._h_enter, 'leave': self._h_leave,
            'sub': self._h_sub, 'add': self._h_add, 'inc': self._h_inc, 'dec': self._h_dec,
            'neg': self._h_neg, 'not': self._h_not,
            'and': self._h_and, 'or': self._h_or, 'xor': self._h_xor,
            'shl': self._h_shl, 'shr': self._h_shr, 'sal': self._h_shl, 'sar': self._h_sar,
            'mul': self._h_mul, 'imul': self._h_imul, 'div': self._h_div, 'idiv': self._h_idiv,
            'cmp': self._h_cmp, 'test': self._h_test,
            'call': self._h_call, 'ret': self._h_ret, 'jmp': self._h_jmp,
            'je': self._h_je, 'jne': self._h_jne, 'jz': self._h_je, 'jnz': self._h_jne,
            'jb': self._h_jb, 'jbe': self._h_jbe, 'ja': self._h_ja, 'jae': self._h_jae,
            'jg': self._h_jg, 'jge': self._h_jge, 'jl': self._h_jl, 'jle': self._h_jle,
            'jo': self._h_jo, 'jno': self._h_jno, 'js': self._h_js, 'jns': self._h_jns,
            'jp': self._h_jp, 'jnp': self._h_jnp,
            'sete': self._h_sete, 'setne': self._h_setne, 'setb': self._h_setb, 'setbe': self._h_setbe,
            'seta': self._h_seta, 'setae': self._h_setae, 'setg': self._h_setg, 'setge': self._h_setge,
            'setl': self._h_setl, 'setle': self._h_setle,
            'seto': self._h_seto, 'setno': self._h_setno, 'sets': self._h_sets, 'setns': self._h_setns,
            'cmovz': self._h_cmovz, 'cmovnz': self._h_cmovnz, 'cmovb': self._h_cmovb, 'cmovbe': self._h_cmovbe,
            'cmova': self._h_cmova, 'cmovae': self._h_cmovae, 'cmovg': self._h_cmovg, 'cmovge': self._h_cmovge,
            'cmovl': self._h_cmovl, 'cmovle': self._h_cmovle,
            'cmovo': self._h_cmovo, 'cmovno': self._h_cmovno, 'cmovs': self._h_cmovs, 'cmovns': self._h_cmovns,
            'cmovp': self._h_cmovp, 'cmovnp': self._h_cmovnp, 'cmovne': self._h_cmovnz,
            'nop': self._h_nop, 'int3': self._h_int3,
            'endbr64': self._h_nop, 'endbr32': self._h_nop, 'hlt': self._h_nop, 'ud2': self._h_nop,
            'cbw': self._h_cbw, 'cwde': self._h_cwde, 'cdqe': self._h_cdqe, 'cwd': self._h_cwd, 'cdq': self._h_cdq,
            'cqo': self._h_cqo,
            'stosb': self._h_stosb, 'stosw': self._h_stosw, 'stosd': self._h_stosd, 'stosq': self._h_stosq,
            'movsb': self._h_movsb, 'movsw': self._h_movsw, 'movsd': self._h_movsd, 'movsq': self._h_movsq,
            'bsr': self._h_bsr, 'bsf': self._h_bsf,
            'bswap': self._h_bswap,
            'bt': self._h_bt, 'bts': self._h_bts, 'btr': self._h_btr, 'btc': self._h_btc,
            'xorps': self._h_xorps, 'xorpd': self._h_xorpd, 'pxor': self._h_pxor,
            'addps': self._h_addps, 'addpd': self._h_addpd,
            'mulps': self._h_mulps, 'mulpd': self._h_mulpd,
            'cvtsi2sd': self._h_cvtsi2sd, 'cvttsd2si': self._h_cvttsd2si,
            'cvtsd2ss': self._h_cvtsd2ss, 'cvtss2sd': self._h_cvtss2sd,
            'syscall': self._h_syscall, 'cpuid': self._h_cpuid,
            'rdtsc': self._h_rdtsc, 'rdtscp': self._h_rdtscp,
            'xlat': self._h_xlat, 'xlatb': self._h_xlat,
            'fld': self._h_fld, 'fst': self._h_fst, 'fstp': self._h_fstp,
            'fadd': self._h_fadd, 'fmul': self._h_fmul, 'fdiv': self._h_fdiv,
            'fcom': self._h_fcom, 'fldz': self._h_fldz, 'fld1': self._h_fld1,
            'fild': self._h_fild, 'fistp': self._h_fistp,
            'loop': self._h_loop, 'loope': self._h_loope, 'loopne': self._h_loopne,
        }
        return handlers.get(mnemonic)

    def _op_to_c(self, insn, op, size_override=None):
        if op.type == X86_OP_REG:
            return self._reg_name(insn, op.reg)
        elif op.type == X86_OP_IMM:
            return hex(op.imm) if abs(op.imm) > 9 else str(op.imm)
        elif op.type == X86_OP_MEM:
            size = size_override or op.size
            address, absva = self._mem_ea(insn, op)
            if absva is not None and absva in self.import_names:
                return f'(uint64_t)&{self.import_names[absva]}'
            if size not in (1, 2, 4, 8, 16):
                size = 8
            return f'MEMORY(uint{size * 8}_t, {address})'
        return '?'

    def _op_to_c_val(self, insn, op):
        if op.type == X86_OP_REG:
            return self._reg_name(insn, op.reg)
        elif op.type == X86_OP_IMM:
            return hex(op.imm) if abs(op.imm) > 9 else str(op.imm)
        elif op.type == X86_OP_MEM:
            return self._op_to_c(insn, op)
        return '?'

    def _reg_name(self, insn, reg_id):
        if reg_id is None:
            return ''
        return insn.reg_name(reg_id)

    def _xmm_name(self, insn, reg_id):
        if reg_id is None:
            return ''
        return insn.reg_name(reg_id)

    def _xmm_idx(self, name):
        for r in XMM_REGS:
            if name == r:
                return XMM_REGS.index(r)
        return 0

    def _h_mov(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    {dst} = {src};\n'

    def _h_movzx(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    {dst} = (uint{ops[0].size * 8}_t){src};\n'

    def _h_movsx(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    {dst} = (int{ops[0].size * 8}_t)(int{ops[1].size * 8}_t){src};\n'

    def _h_movaps(self, insn, ops):
        dst, src = ops[0], ops[1]
        if dst.type == X86_OP_REG and src.type == X86_OP_REG:
            d = self._xmm_idx(insn.reg_name(dst.reg).lower())
            s = self._xmm_idx(insn.reg_name(src.reg).lower())
            return f'    xmm[{d}] = xmm[{s}];\n'
        if dst.type == X86_OP_REG and src.type == X86_OP_MEM:
            d = self._xmm_idx(insn.reg_name(dst.reg).lower())
            ea, _ = self._mem_ea(insn, src)
            return (f'    xmm[{d}].u64[0] = MEMORY(uint64_t, {ea}); '
                    f'xmm[{d}].u64[1] = MEMORY(uint64_t, ({ea}) + 8);\n')
        if dst.type == X86_OP_MEM and src.type == X86_OP_REG:
            s = self._xmm_idx(insn.reg_name(src.reg).lower())
            ea, _ = self._mem_ea(insn, dst)
            return (f'    MEMORY(uint64_t, {ea}) = xmm[{s}].u64[0]; '
                    f'MEMORY(uint64_t, ({ea}) + 8) = xmm[{s}].u64[1];\n')
        return f'    /* movaps {insn.op_str} */\n'

    def _h_movups(self, insn, ops):
        return self._h_movaps(insn, ops)

    def _h_movdqa(self, insn, ops):
        return self._h_movaps(insn, ops)

    def _h_movdqu(self, insn, ops):
        return self._h_movaps(insn, ops)

    def _h_lea(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = ops[1]
        if src.type == X86_OP_MEM:
            ea, absva = self._mem_ea(insn, src)
            if absva is not None and absva in self.import_names:
                return f'    {dst} = (uint64_t)&{self.import_names[absva]};\n'
            return f'    {dst} = (uint64_t)&MEMORY(uint8_t, {ea});\n'
        return f'    {dst} = (uint64_t){self._op_to_c_val(insn, src)};\n'

    def _sse_scalar_move(self, insn, ops, suffix, size):
        def read(op):
            if op.type == X86_OP_REG:
                name = insn.reg_name(op.reg).lower()
                if name.startswith(('xmm', 'ymm')):
                    return f'xmm[{self._xmm_idx(name)}].{suffix}'
                return self._reg_name(insn, op.reg)
            if op.type == X86_OP_MEM:
                return self._op_to_c(insn, op, size)
            return None
        dst = read(ops[0])
        src = read(ops[1])
        if dst is None or src is None:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'
        return f'    {dst} = {src};\n'

    def _h_movsd_sse(self, insn, ops):
        return self._sse_scalar_move(insn, ops, 'u64[0]', 8)

    def _h_movss_sse(self, insn, ops):
        return self._sse_scalar_move(insn, ops, 'u32[0]', 4)

    def _h_ucomisd(self, insn, ops):
        return f'    /* comisd {insn.op_str}: sets ZF/PF/CF */\n'

    def _h_ucomiss(self, insn, ops):
        return f'    /* comiss {insn.op_str}: sets ZF/PF/CF */\n'

    def _h_xchg(self, insn, ops):
        a = self._op_to_c(insn, ops[0])
        b = self._op_to_c_val(insn, ops[1])
        return f'    do {{ typeof({a}) _tmp = {a}; {a} = {b}; {b} = _tmp; }} while(0);\n'

    def _h_push(self, insn, ops):
        val = self._op_to_c_val(insn, ops[0])
        return f'    PUSH64({val});\n'

    def _h_pop(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = POP64();\n'

    def _h_pusha(self, insn, ops):
        return '    PUSH64(rax); PUSH64(rbx); PUSH64(rcx); PUSH64(rdx); PUSH64(rbp); PUSH64(rsi); PUSH64(rdi);\n'

    def _h_popa(self, insn, ops):
        return '    rdi = POP64(); rsi = POP64(); rbp = POP64(); rdx = POP64(); rcx = POP64(); rbx = POP64(); rax = POP64();\n'

    def _h_enter(self, insn, ops):
        return '    PUSH64(rbp); rbp = rsp; rsp -= ' + str(ops[1].imm if len(ops) > 1 else 0) + ';\n'

    def _h_leave(self, insn, ops):
        return '    rsp = rbp; rbp = POP64();\n'

    def _h_sub(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        s = ops[0].size * 8
        mask = hex(ofMask.get(ops[0].size, 0))
        return f'    TMP{s}({dst}, -, {src}); SET_ZF({s}); SET_CF_SUB({dst}, {src}); SET_AF_0({dst}, {src}); SET_OF_SUB({dst}, {src}, {s}, {mask}); SET_SF({s}); SET_PF(); {dst} = tmp{s};\n'

    def _h_add(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        s = ops[0].size * 8
        mask = hex(ofMask.get(ops[0].size, 0))
        return f'    TMP{s}({dst}, +, {src}); SET_ZF({s}); SET_CF_ADD({s}, {dst}); SET_AF_0({dst}, {src}); SET_OF_ADD({dst}, {src}, tmp{s}, {mask}); SET_SF({s}); SET_PF(); {dst} = tmp{s};\n'

    def _h_inc(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        s = ops[0].size * 8
        mask = hex(ofMask.get(ops[0].size, 0))
        return f'    TMP{s}({dst}, +, 1); SET_ZF({s}); SET_AF_INC({s}); SET_OF_INC_DEC_NEG({s}, {mask}); SET_SF({s}); SET_PF(); {dst} = tmp{s};\n'

    def _h_dec(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        s = ops[0].size * 8
        mask = hex(ofMask.get(ops[0].size, 0) - 1)
        return f'    TMP{s}({dst}, -, 1); SET_ZF({s}); SET_AF_DEC({s}); SET_OF_INC_DEC_NEG({s}, {mask}); SET_SF({s}); SET_PF(); {dst} = tmp{s};\n'

    def _h_neg(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = -{dst};\n'

    def _h_not(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = ~{dst};\n'

    def _h_and(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        s = ops[0].size * 8
        return f'    {dst} &= {src}; SET_ZF({s}); SET_SF({s}); SET_PF(); cf = 0; of = 0;\n'

    def _h_or(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        s = ops[0].size * 8
        return f'    {dst} |= {src}; SET_ZF({s}); SET_SF({s}); SET_PF(); cf = 0; of = 0;\n'

    def _h_xor(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        s = ops[0].size * 8
        return f'    {dst} ^= {src}; SET_ZF({s}); SET_SF({s}); SET_PF(); cf = 0; of = 0;\n'

    def _h_shl(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    {dst} <<= {src};\n'

    def _h_shr(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    {dst} >>= {src};\n'

    def _h_sar(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    {dst} = (int{ops[0].size * 8}_t){dst} >> {src};\n'

    def _h_mul(self, insn, ops):
        src = self._op_to_c_val(insn, ops[0])
        s = ops[0].size * 8
        return f'    tmp{s} = (uint{s}_t)rax * (uint{s}_t){src}; rax = tmp{s};\n'

    def _h_imul(self, insn, ops):
        if len(ops) == 1:
            src = self._op_to_c_val(insn, ops[0])
            s = ops[0].size * 8
            return f'    tmp{s * 2} = (int{s}_t)rax * (int{s}_t){src}; rax = (uint{s}_t)tmp{s * 2}; rdx = (uint{s}_t)(tmp{s * 2} >> {s});\n'
        elif len(ops) == 2:
            dst = self._op_to_c(insn, ops[0])
            src = self._op_to_c_val(insn, ops[1])
            return f'    {dst} *= {src};\n'
        else:
            dst = self._op_to_c(insn, ops[0])
            src1 = self._op_to_c_val(insn, ops[1])
            src2 = self._op_to_c_val(insn, ops[2])
            return f'    {dst} = {src1} * {src2};\n'

    def _h_div(self, insn, ops):
        src = self._op_to_c_val(insn, ops[0])
        s = ops[0].size * 8
        return f'    rax = (uint{s}_t)(((uint{s * 2}_t)rdx << {s}) | (uint{s}_t)rax) / (uint{s}_t){src}; rdx = (uint{s}_t)(((uint{s * 2}_t)rdx << {s}) | (uint{s}_t)rax) % (uint{s}_t){src};\n'

    def _h_idiv(self, insn, ops):
        src = self._op_to_c_val(insn, ops[0])
        s = ops[0].size * 8
        return f'    rax = (int{s}_t)(((int{s * 2}_t)rdx << {s}) | (uint{s}_t)rax) / (int{s}_t){src}; rdx = (int{s}_t)(((int{s * 2}_t)rdx << {s}) | (uint{s}_t)rax) % (int{s}_t){src};\n'

    def _h_cmp(self, insn, ops):
        a = self._op_to_c_val(insn, ops[0])
        b = self._op_to_c_val(insn, ops[1])
        s = ops[0].size * 8
        mask = hex(ofMask.get(ops[0].size, 0))
        return f'    TMP{s}({a}, -, {b}); SET_ZF({s}); SET_CF_SUB({a}, {b}); SET_AF_0({a}, {b}); SET_OF_SUB({a}, {b}, {s}, {mask}); SET_SF({s}); SET_PF();\n'

    def _h_test(self, insn, ops):
        a = self._op_to_c_val(insn, ops[0])
        b = self._op_to_c_val(insn, ops[1])
        s = ops[0].size * 8
        return f'    tmp{s} = {a} & {b}; SET_ZF({s}); SET_SF({s}); SET_PF(); cf = 0; of = 0;\n'

    def _h_call(self, insn, ops):
        if len(ops) > 0:
            op = ops[0]
            iat_name = self._resolve_iat_addr(insn, op)
            if iat_name:
                return f'    /* call -> {iat_name} */\n'
            try:
                target = self._imm_target(insn)
                return f'    PUSH64((uint64_t)&&_ret_{insn.address:x}); goto _0x{target:x}; _ret_{insn.address:x}:;\n'
            except (ValueError, AttributeError):
                pass
            return f'    /* call {insn.op_str} */\n'
        return '    /* call */\n'

    def _h_ret(self, insn, ops):
        return '    goto _end;\n'

    def _h_jmp(self, insn, ops):
        op = ops[0]
        iat_name = self._resolve_iat_addr(insn, op)
        if iat_name:
            return f'    /* jmp -> {iat_name} */\n'
        try:
            target = self._imm_target(insn)
            return f'    goto _0x{target:x};\n'
        except (ValueError, AttributeError):
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_je(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(zf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jne(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(!zf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jb(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(cf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jbe(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(cf || zf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_ja(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(!cf && !zf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jae(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(!cf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jg(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(!zf && sf == of) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jge(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(sf == of) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jl(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(sf != of) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jle(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(zf || sf != of) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jo(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(of) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jno(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(!of) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_js(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(sf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jns(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(!sf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jp(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(pf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jnp(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(!pf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_sete(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = zf;\n'

    def _h_setne(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = !zf;\n'

    def _h_setb(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = cf;\n'

    def _h_setbe(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = cf || zf;\n'

    def _h_seta(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = !cf && !zf;\n'

    def _h_setae(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = !cf;\n'

    def _h_setg(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = !zf && sf == of;\n'

    def _h_setge(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = sf == of;\n'

    def _h_setl(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = sf != of;\n'

    def _h_setle(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = zf || sf != of;\n'

    def _h_seto(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = of;\n'

    def _h_setno(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = !of;\n'

    def _h_sets(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = sf;\n'

    def _h_setns(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = !sf;\n'

    def _h_cmovz(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(zf) {dst} = {src};\n'

    def _h_cmovnz(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(!zf) {dst} = {src};\n'

    def _h_cmovb(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(cf) {dst} = {src};\n'

    def _h_cmovbe(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(cf || zf) {dst} = {src};\n'

    def _h_cmova(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(!cf && !zf) {dst} = {src};\n'

    def _h_cmovae(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(!cf) {dst} = {src};\n'

    def _h_cmovg(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(!zf && sf == of) {dst} = {src};\n'

    def _h_cmovge(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(sf == of) {dst} = {src};\n'

    def _h_cmovl(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(sf != of) {dst} = {src};\n'

    def _h_cmovle(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(zf || sf != of) {dst} = {src};\n'

    def _h_cmovo(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(of) {dst} = {src};\n'

    def _h_cmovno(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(!of) {dst} = {src};\n'

    def _h_cmovs(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(sf) {dst} = {src};\n'

    def _h_cmovns(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(!sf) {dst} = {src};\n'

    def _h_cmovp(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(pf) {dst} = {src};\n'

    def _h_cmovnp(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    if(!pf) {dst} = {src};\n'

    def _h_nop(self, insn, ops):
        return '    /* nop */\n'

    def _h_int3(self, insn, ops):
        return '\n    /* ——— function boundary ——— */\n\n'

    def _h_cbw(self, insn, ops):
        return '    ax = (int16_t)(int8_t)al;\n'

    def _h_cwde(self, insn, ops):
        return '    eax = (int32_t)(int16_t)ax;\n'

    def _h_cdqe(self, insn, ops):
        return '    rax = (int64_t)(int32_t)eax;\n'

    def _h_cwd(self, insn, ops):
        return '    dx = (int16_t)((int16_t)ax < 0 ? 0xffff : 0);\n'

    def _h_cdq(self, insn, ops):
        return '    edx = (int32_t)((int32_t)eax < 0 ? 0xffffffff : 0);\n'

    def _h_cqo(self, insn, ops):
        return '    rdx = (int64_t)((int64_t)rax < 0 ? 0xffffffffffffffff : 0);\n'

    def _h_stosb(self, insn, ops):
        return '    MEMORY(uint8_t, rdi) = al; rdi++;\n'

    def _h_stosw(self, insn, ops):
        return '    MEMORY(uint16_t, rdi) = ax; rdi += 2;\n'

    def _h_stosd(self, insn, ops):
        return '    MEMORY(uint32_t, rdi) = eax; rdi += 4;\n'

    def _h_stosq(self, insn, ops):
        return '    MEMORY(uint64_t, rdi) = rax; rdi += 8;\n'

    def _h_movsb(self, insn, ops):
        return '    MEMORY(uint8_t, rdi) = MEMORY(uint8_t, rsi); rdi++; rsi++;\n'

    def _h_movsw(self, insn, ops):
        return '    MEMORY(uint16_t, rdi) = MEMORY(uint16_t, rsi); rdi += 2; rsi += 2;\n'

    def _h_movsd(self, insn, ops):
        return '    MEMORY(uint32_t, rdi) = MEMORY(uint32_t, rsi); rdi += 4; rsi += 4;\n'

    def _h_movsq(self, insn, ops):
        return '    MEMORY(uint64_t, rdi) = MEMORY(uint64_t, rsi); rdi += 8; rsi += 8;\n'

    def _h_rep_stosb(self, insn, ops):
        return '    while(rcx--) { MEMORY(uint8_t, rdi) = al; rdi++; }\n'

    def _h_rep_stosw(self, insn, ops):
        return '    while(rcx--) { MEMORY(uint16_t, rdi) = ax; rdi += 2; }\n'

    def _h_rep_stosd(self, insn, ops):
        return '    while(rcx--) { MEMORY(uint32_t, rdi) = eax; rdi += 4; }\n'

    def _h_rep_stosq(self, insn, ops):
        return '    while(rcx--) { MEMORY(uint64_t, rdi) = rax; rdi += 8; }\n'

    def _h_rep_movsb(self, insn, ops):
        return '    while(rcx--) { MEMORY(uint8_t, rdi) = MEMORY(uint8_t, rsi); rdi++; rsi++; }\n'

    def _h_rep_movsw(self, insn, ops):
        return '    while(rcx--) { MEMORY(uint16_t, rdi) = MEMORY(uint16_t, rsi); rdi += 2; rsi += 2; }\n'

    def _h_rep_movsd(self, insn, ops):
        return '    while(rcx--) { MEMORY(uint32_t, rdi) = MEMORY(uint32_t, rsi); rdi += 4; rsi += 4; }\n'

    def _h_rep_movsq(self, insn, ops):
        return '    while(rcx--) { MEMORY(uint64_t, rdi) = MEMORY(uint64_t, rsi); rdi += 8; rsi += 8; }\n'

    def _h_bsr(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    BSR({src}, {dst});\n'

    def _h_bsf(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c_val(insn, ops[1])
        return f'    BSF({src}, {dst});\n'

    def _h_bswap(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        return f'    {dst} = __builtin_bswap{ops[0].size * 8}({dst});\n'

    def _h_bt(self, insn, ops):
        a = self._op_to_c_val(insn, ops[0])
        b = self._op_to_c_val(insn, ops[1])
        return f'    cf = BT({a}, {b});\n'

    def _h_bts(self, insn, ops):
        a = self._op_to_c(insn, ops[0])
        b = self._op_to_c_val(insn, ops[1])
        return f'    cf = BT({a}, {b}); BTS({a}, {b});\n'

    def _h_btr(self, insn, ops):
        a = self._op_to_c(insn, ops[0])
        b = self._op_to_c_val(insn, ops[1])
        return f'    cf = BT({a}, {b}); BTR({a}, {b});\n'

    def _h_btc(self, insn, ops):
        a = self._op_to_c(insn, ops[0])
        b = self._op_to_c_val(insn, ops[1])
        return f'    cf = BT({a}, {b}); BTC({a}, {b});\n'

    def _h_xorps(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        return f'    xmm[{d}].u64[0] = 0; xmm[{d}].u64[1] = 0;\n'

    def _h_xorpd(self, insn, ops):
        return self._h_xorps(insn, ops)

    def _h_pxor(self, insn, ops):
        return self._h_xorps(insn, ops)

    def _h_addps(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        s = self._xmm_idx(self._xmm_name(insn, ops[1].reg))
        return (f'    xmm[{d}].f[0] += xmm[{s}].f[0]; xmm[{d}].f[1] += xmm[{s}].f[1]; '
                f'xmm[{d}].f[2] += xmm[{s}].f[2]; xmm[{d}].f[3] += xmm[{s}].f[3];\n')

    def _h_addpd(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        s = self._xmm_idx(self._xmm_name(insn, ops[1].reg))
        return f'    xmm[{d}].d[0] += xmm[{s}].d[0]; xmm[{d}].d[1] += xmm[{s}].d[1];\n'

    def _h_mulps(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        s = self._xmm_idx(self._xmm_name(insn, ops[1].reg))
        return (f'    xmm[{d}].f[0] *= xmm[{s}].f[0]; xmm[{d}].f[1] *= xmm[{s}].f[1]; '
                f'xmm[{d}].f[2] *= xmm[{s}].f[2]; xmm[{d}].f[3] *= xmm[{s}].f[3];\n')

    def _h_mulpd(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        s = self._xmm_idx(self._xmm_name(insn, ops[1].reg))
        return f'    xmm[{d}].d[0] *= xmm[{s}].d[0]; xmm[{d}].d[1] *= xmm[{s}].d[1];\n'

    def _h_cvtsi2sd(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        src = self._op_to_c_val(insn, ops[1])
        return f'    xmm[{d}].d[0] = (double)(int64_t){src};\n'

    def _h_cvttsd2si(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        s = self._xmm_idx(self._xmm_name(insn, ops[1].reg))
        return f'    {dst} = (int{ops[0].size * 8}_t)xmm[{s}].d[0];\n'

    def _h_cvtsd2ss(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        s = self._xmm_idx(self._xmm_name(insn, ops[1].reg))
        return f'    xmm[{d}].f[0] = (float)xmm[{s}].d[0];\n'

    def _h_cvtss2sd(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        s = self._xmm_idx(self._xmm_name(insn, ops[1].reg))
        return f'    xmm[{d}].d[0] = (double)xmm[{s}].f[0];\n'

    def _h_syscall(self, insn, ops):
        return '    /* syscall */\n'

    def _h_cpuid(self, insn, ops):
        return '    /* cpuid */\n'

    def _h_rdtsc(self, insn, ops):
        return '    /* rdtsc */\n'

    def _h_rdtscp(self, insn, ops):
        return '    /* rdtscp */\n'

    def _h_xlat(self, insn, ops):
        return '    al = MEMORY(uint8_t, rbx + al);\n'

    def _h_fld(self, insn, ops):
        return f'    /* fld {insn.op_str} */\n'

    def _h_fst(self, insn, ops):
        return f'    /* fst {insn.op_str} */\n'

    def _h_fstp(self, insn, ops):
        return f'    /* fstp {insn.op_str} */\n'

    def _h_fadd(self, insn, ops):
        return f'    /* fadd {insn.op_str} */\n'

    def _h_fmul(self, insn, ops):
        return f'    /* fmul {insn.op_str} */\n'

    def _h_fdiv(self, insn, ops):
        return f'    /* fdiv {insn.op_str} */\n'

    def _h_fcom(self, insn, ops):
        return f'    /* fcom {insn.op_str} */\n'

    def _h_fldz(self, insn, ops):
        return '    /* fldz */\n'

    def _h_fld1(self, insn, ops):
        return '    /* fld1 */\n'

    def _h_fild(self, insn, ops):
        return f'    /* fild {insn.op_str} */\n'

    def _h_fistp(self, insn, ops):
        return f'    /* fistp {insn.op_str} */\n'

    def _h_loop(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(--rcx) goto _0x{target:x};\n'
        except:
            return f'    /* loop {insn.op_str} */\n'

    def _h_loope(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(--rcx && zf) goto _0x{target:x};\n'
        except:
            return f'    /* loope {insn.op_str} */\n'

    def _h_loopne(self, insn, ops):
        try:
            target = self._imm_target(insn)
            return f'    if(--rcx && !zf) goto _0x{target:x};\n'
        except:
            return f'    /* loopne {insn.op_str} */\n'


ofMask = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}



# Asm-to-C pseudocode clean engine v1.6

MASK64 = 0xFFFFFFFFFFFFFFFF


def _mask_for(size):
    if size >= 8:
        return MASK64
    return (1 << (size * 8)) - 1


def _c_type(size, signed=True):
    table = {1: 'int8_t', 2: 'int16_t', 4: 'int32_t', 8: 'int64_t', 16: 'int128_t'}
    name = table.get(size, 'int64_t')
    if not signed and size in (1, 2, 4, 8):
        name = 'u' + name
    return name



# IR expressions

class CExpr:
    __slots__ = ()
    size = 8


class CConst(CExpr):
    __slots__ = ('value', 'size')

    def __init__(self, value, size=8):
        self.value = value
        self.size = size


class CReg(CExpr):
    __slots__ = ('name', 'size')

    def __init__(self, name, size=8):
        self.name = name
        self.size = size


class CVar(CExpr):
    __slots__ = ('name', 'size', 'ptype')

    def __init__(self, name, size=8, ptype=None):
        self.name = name
        self.size = size
        self.ptype = ptype


class CAddr(CExpr):
    """Address-of: result of LEA. `expr` is the effective address."""
    __slots__ = ('expr', 'size')

    def __init__(self, expr):
        self.expr = expr
        self.size = 8


class CDeref(CExpr):
    __slots__ = ('addr', 'size')

    def __init__(self, addr, size):
        self.addr = addr
        self.size = size


class CBin(CExpr):
    __slots__ = ('op', 'a', 'b', 'size')

    def __init__(self, op, a, b, size=8):
        self.op = op
        self.a = a
        self.b = b
        self.size = size


class CUn(CExpr):
    __slots__ = ('op', 'a', 'size')

    def __init__(self, op, a, size=8):
        self.op = op
        self.a = a
        self.size = size


class CCast(CExpr):
    __slots__ = ('expr', 'size', 'signed')

    def __init__(self, expr, size, signed=False):
        self.expr = expr
        self.size = size
        self.signed = signed


class CCmp(CExpr):
    __slots__ = ('op', 'a', 'b', 'unsigned', 'size')

    def __init__(self, op, a, b, unsigned=False, size=8):
        self.op = op
        self.a = a
        self.b = b
        self.unsigned = unsigned
        self.size = size


class CCall(CExpr):
    __slots__ = ('name', 'args', 'size')

    def __init__(self, name, args=None, size=8):
        self.name = name
        self.args = args or []
        self.size = size


class CFlag(CExpr):
    __slots__ = ('name', 'size')

    def __init__(self, name):
        self.name = name
        self.size = 8


class CString(CExpr):
    __slots__ = ('value', 'size')

    def __init__(self, value):
        self.value = value
        self.size = 8



# IR statements

class CStmt:
    __slots__ = ()


class CSet(CStmt):
    __slots__ = ('dst', 'src')

    def __init__(self, dst, src):
        self.dst = dst
        self.src = src


class CJump(CStmt):
    __slots__ = ('target',)

    def __init__(self, target):
        self.target = target


class CBranch(CStmt):
    __slots__ = ('cond', 't', 'f')

    def __init__(self, cond, t, f=None):
        self.cond = cond
        self.t = t
        self.f = f


class CRet(CStmt):
    __slots__ = ('value',)

    def __init__(self, value=None):
        self.value = value


class CCallStmt(CStmt):
    __slots__ = ('call', 'dst')

    def __init__(self, call, dst=None):
        self.call = call
        self.dst = dst


class CComment(CStmt):
    __slots__ = ('text',)

    def __init__(self, text):
        self.text = text


class CPush(CStmt):
    __slots__ = ('value',)

    def __init__(self, value):
        self.value = value


class CPop(CStmt):
    __slots__ = ('dst',)

    def __init__(self, dst):
        self.dst = dst


class CJumpIndirect(CStmt):
    __slots__ = ('value',)

    def __init__(self, value):
        self.value = value


class CSwitch(CStmt):
    __slots__ = ('value', 'cases', 'default')

    def __init__(self, value, cases, default):
        self.value = value
        self.cases = cases
        self.default = default



# Register helpers


REG_INFO = {}
REG_PRINT = {}


def _build_register_tables():
    for names, sizes in regsSize:
        canonical = names[0]
        for size, spelling in sizes.items():
            if not spelling:
                continue
            REG_INFO[spelling] = (canonical, size)
            REG_PRINT[(canonical, size)] = spelling
        for extra in names:
            if extra and extra not in REG_INFO:
                REG_INFO[extra] = (canonical, 8 if len(extra) and extra[0] == 'r' and extra[1:].isdigit() else 4)
    for hi, base in (('ah', 'rax'), ('bh', 'rbx'), ('ch', 'rcx'), ('dh', 'rdx')):
        REG_INFO[hi] = (base, 1)


_build_register_tables()


def reg_info(name, is64=True):
    name = name.lower()
    if name in REG_INFO:
        canonical, size = REG_INFO[name]
        if not is64:
            spelled = REG_PRINT.get((canonical, 4))
            if spelled:
                canonical = spelled
        return canonical, size
    return name, 8


def reg_print(canonical, size):
    name = REG_PRINT.get((canonical, size))
    if name:
        return name
    return canonical


# condition-code names
CC_NAMES = {
    'je': 'e', 'jz': 'e', 'jne': 'ne', 'jnz': 'ne',
    'jb': 'b', 'jnae': 'b', 'jc': 'b', 'jae': 'ae', 'jnb': 'ae', 'jnc': 'ae',
    'jbe': 'be', 'jna': 'be', 'ja': 'a', 'jnbe': 'a',
    'jl': 'l', 'jnge': 'l', 'jge': 'ge', 'jnl': 'ge',
    'jg': 'g', 'jnle': 'g', 'jle': 'le', 'jng': 'le',
    'js': 's', 'jns': 'ns', 'jo': 'o', 'jno': 'no', 'jp': 'p', 'jpe': 'p',
    'jnp': 'np', 'jpo': 'np',
    'sete': 'e', 'setz': 'e', 'setne': 'ne', 'setnz': 'ne',
    'setb': 'b', 'setnae': 'b', 'setae': 'ae', 'setnb': 'ae',
    'setbe': 'be', 'setna': 'be', 'seta': 'a', 'setnbe': 'a',
    'setl': 'l', 'setnge': 'l', 'setge': 'ge', 'setnl': 'ge',
    'setg': 'g', 'setnle': 'g', 'setle': 'le', 'setng': 'le',
    'sets': 's', 'setns': 'ns', 'seto': 'o', 'setno': 'no', 'setp': 'p', 'setnp': 'np',
    'cmove': 'e', 'cmovz': 'e', 'cmovne': 'ne', 'cmovnz': 'ne',
    'cmovb': 'b', 'cmovnae': 'b', 'cmovae': 'ae', 'cmovnb': 'ae',
    'cmovbe': 'be', 'cmovna': 'be', 'cmova': 'a', 'cmovnbe': 'a',
    'cmovl': 'l', 'cmovnge': 'l', 'cmovge': 'ge', 'cmovnl': 'ge',
    'cmovg': 'g', 'cmovnle': 'g', 'cmovle': 'le', 'cmovng': 'le',
    'cmovs': 's', 'cmovns': 'ns', 'cmovo': 'o', 'cmovno': 'no',
    'cmovp': 'p', 'cmovnp': 'np',
}

COND_JUMPS = set(k for k in CC_NAMES if k.startswith('j'))



# Expression helpers


def _is_const(e):
    return isinstance(e, CConst)


def simplify(e):
    if isinstance(e, CBin):
        a = simplify(e.a)
        b = simplify(e.b)
        op = e.op
        if _is_const(a) and _is_const(b):
            try:
                value = _eval_bin(op, a.value, b.value)
                if value is not None:
                    return CConst(value & _mask_for(e.size) if value >= 0 else value, e.size)
            except Exception:
                pass
        if op == '+':
            if _is_const(b) and b.value == 0:
                return a
            if _is_const(a) and a.value == 0:
                return b
        elif op == '-':
            if _is_const(b) and b.value == 0:
                return a
            if _expr_key(a) == _expr_key(b):
                return CConst(0, e.size)
        elif op == '*':
            if _is_const(b) and b.value == 1:
                return a
            if _is_const(a) and a.value == 1:
                return b
            if (_is_const(a) and a.value == 0) or (_is_const(b) and b.value == 0):
                return CConst(0, e.size)
        elif op in ('&', '|'):
            if _expr_key(a) == _expr_key(b):
                return a
            if _is_const(b) and b.value == _mask_for(e.size):
                return CConst(_mask_for(e.size), e.size) if op == '|' else a
            if _is_const(a) and a.value == _mask_for(e.size):
                return CConst(_mask_for(e.size), e.size) if op == '|' else b
            if (op == '&' and _is_const(b) and b.value == 0) or \
                    (op == '&' and _is_const(a) and a.value == 0):
                return CConst(0, e.size)
        elif op == '^':
            if _expr_key(a) == _expr_key(b):
                return CConst(0, e.size)
            if _is_const(b) and b.value == 0:
                return a
        elif op in ('<<', '>>'):
            if _is_const(b) and b.value == 0:
                return a
        return CBin(op, a, b, e.size)
    if isinstance(e, CUn):
        a = simplify(e.a)
        if _is_const(a):
            if e.op == '~':
                return CConst(~a.value & _mask_for(e.size), e.size)
            if e.op == '-':
                return CConst(-a.value, e.size)
        if e.op == '~' and isinstance(a, CUn) and a.op == '~':
            return a.a
        return CUn(e.op, a, e.size)
    if isinstance(e, CCast):
        inner = simplify(e.expr)
        if _is_const(inner):
            value = inner.value & _mask_for(e.size)
            if e.signed and e.size < 8 and value >= (1 << (e.size * 8 - 1)):
                value -= (1 << (e.size * 8))
            return CConst(value, e.size)
        if isinstance(inner, CCast) and inner.size == e.size and inner.signed == e.signed:
            return inner
        return CCast(inner, e.size, e.signed)
    if isinstance(e, CDeref):
        return CDeref(simplify(e.addr), e.size)
    if isinstance(e, CAddr):
        return CAddr(simplify(e.expr))
    if isinstance(e, CCmp):
        a = simplify(e.a)
        b = simplify(e.b)
        if _is_const(a) and _is_const(b):
            try:
                res = _eval_cmp(e.op, a.value, b.value, e.unsigned)
                if res is not None:
                    return CConst(1 if res else 0, 1)
            except Exception:
                pass
        return CCmp(e.op, a, b, e.unsigned, e.size)
    return e


def _eval_bin(op, a, b):
    if op == '+':
        return a + b
    if op == '-':
        return a - b
    if op == '*':
        return a * b
    if op in ('/', 'div'):
        return int(a / b) if b else None
    if op in ('%', 'mod'):
        return a % b if b else None
    if op == '&':
        return a & b
    if op == '|':
        return a | b
    if op == '^':
        return a ^ b
    if op in ('<<', 'shl'):
        return (a << (b & 63)) & MASK64
    if op in ('>>', 'shr'):
        return (a & MASK64) >> (b & 63)
    if op in ('sar',):
        return a >> (b & 63)
    return None


def _eval_cmp(op, a, b, unsigned):
    if unsigned:
        a &= MASK64
        b &= MASK64
    return {
        '==': a == b, '!=': a != b,
        '<': a < b, '<=': a <= b, '>': a > b, '>=': a >= b,
    }.get(op)


def _expr_key(e):
    if isinstance(e, CConst):
        return ('c', e.value, e.size)
    if isinstance(e, CReg):
        return ('r', e.name, e.size)
    if isinstance(e, CVar):
        return ('v', e.name, e.size)
    if isinstance(e, CAddr):
        return ('a', _expr_key(e.expr))
    if isinstance(e, CDeref):
        return ('d', _expr_key(e.addr), e.size)
    if isinstance(e, CBin):
        return ('b', e.op, _expr_key(e.a), _expr_key(e.b), e.size)
    if isinstance(e, CUn):
        return ('u', e.op, _expr_key(e.a), e.size)
    if isinstance(e, CCast):
        return ('t', _expr_key(e.expr), e.size, e.signed)
    if isinstance(e, CCmp):
        return ('m', e.op, _expr_key(e.a), _expr_key(e.b), e.unsigned)
    if isinstance(e, CFlag):
        return ('f', e.name)
    if isinstance(e, CString):
        return ('s', e.value)
    if isinstance(e, CCall):
        return ('call', e.name) + tuple(_expr_key(x) for x in e.args)
    return ('?', id(e))


def expr_uses(e, names):
    stack = [e]
    while stack:
        x = stack.pop()
        if isinstance(x, (CReg, CVar)):
            if x.name in names:
                return True
        elif isinstance(x, (CBin,)):
            stack.append(x.a)
            stack.append(x.b)
        elif isinstance(x, CUn):
            stack.append(x.a)
        elif isinstance(x, CCast):
            stack.append(x.expr)
        elif isinstance(x, CDeref):
            stack.append(x.addr)
        elif isinstance(x, CAddr):
            stack.append(x.expr)
        elif isinstance(x, CCmp):
            stack.append(x.a)
            stack.append(x.b)
        elif isinstance(x, CCall):
            stack.extend(x.args)
    return False


def expr_regs(e, out=None):
    if out is None:
        out = set()
    stack = [e]
    while stack:
        x = stack.pop()
        if isinstance(x, CReg):
            out.add(x.name)
        elif isinstance(x, CVar):
            out.add(x.name)
        elif isinstance(x, CBin):
            stack.append(x.a)
            stack.append(x.b)
        elif isinstance(x, CUn):
            stack.append(x.a)
        elif isinstance(x, CCast):
            stack.append(x.expr)
        elif isinstance(x, CDeref):
            stack.append(x.addr)
        elif isinstance(x, CAddr):
            stack.append(x.expr)
        elif isinstance(x, CCmp):
            stack.append(x.a)
            stack.append(x.b)
        elif isinstance(x, CCall):
            stack.extend(x.args)
    return out


def replace_expr(e, mapping):
    if not mapping:
        return e
    if isinstance(e, (CReg, CVar)):
        return mapping.get(e.name, e)
    if isinstance(e, CBin):
        return CBin(e.op, replace_expr(e.a, mapping), replace_expr(e.b, mapping), e.size)
    if isinstance(e, CUn):
        return CUn(e.op, replace_expr(e.a, mapping), e.size)
    if isinstance(e, CCast):
        return CCast(replace_expr(e.expr, mapping), e.size, e.signed)
    if isinstance(e, CDeref):
        return CDeref(replace_expr(e.addr, mapping), e.size)
    if isinstance(e, CAddr):
        return CAddr(replace_expr(e.expr, mapping))
    if isinstance(e, CCmp):
        return CCmp(e.op, replace_expr(e.a, mapping), replace_expr(e.b, mapping), e.unsigned, e.size)
    if isinstance(e, CCall):
        return CCall(e.name, [replace_expr(x, mapping) for x in e.args], e.size)
    return e


def stmt_uses(stmt):
    if isinstance(stmt, CSet):
        out = expr_regs(stmt.src)
        if isinstance(stmt.dst, CDeref):
            out |= expr_regs(stmt.dst.addr)
        return out
    if isinstance(stmt, CBranch):
        return expr_regs(stmt.cond)
    if isinstance(stmt, CRet):
        return expr_regs(stmt.value) if stmt.value is not None else set()
    if isinstance(stmt, CCallStmt):
        out = set()
        for a in stmt.call.args:
            out |= expr_regs(a)
        return out
    if isinstance(stmt, CPush):
        return expr_regs(stmt.value)
    if isinstance(stmt, CPop):
        return set()
    if isinstance(stmt, CJumpIndirect):
        return expr_regs(stmt.value)
    if isinstance(stmt, CSwitch):
        return expr_regs(stmt.value)
    return set()


def stmt_defs(stmt):
    if isinstance(stmt, CSet):
        d = stmt.dst
        if isinstance(d, (CReg, CVar)):
            return {d.name}
    if isinstance(stmt, CPop):
        d = stmt.dst
        if isinstance(d, (CReg, CVar)):
            return {d.name}
    if isinstance(stmt, CCallStmt) and stmt.dst is not None:
        d = stmt.dst
        if isinstance(d, (CReg, CVar)):
            return {d.name}
        return set()
    return set()



# Basic block / function containers

class CBlock:
    def __init__(self, address):
        self.address = address
        self.insns = []
        self.stmts = []
        self.term = None
        self.succ = []
        self.pred = []
        self.fallthrough = None

    def __repr__(self):
        return f'<CBlock 0x{self.address:x} stmts={len(self.stmts)}>'


class CFunction:
    def __init__(self, address, is64=True):
        self.address = address
        self.is64 = is64
        self.insns = []
        self.insn_by_addr = {}
        self.blocks = OrderedDict()
        self.entry = address
        self.end = address
        self.call_targets = []
        self.tail_targets = []
        self.locals = OrderedDict()     # name -> size
        self.arg_vars = OrderedDict()   # name -> size
        self.pointer_args = {}          # name -> pointee size
        self.ret_size = 8
        self.ret_void = False
        self.string_refs = {}           # expr key -> string
        self.switches = {}
        self.uses_frame = False
        self.frame_base = None
        self.frame_size = 0
        self.rbp_const = 0
        self.name = f'sub_{address:X}'



# Machine instruction to IR


class CLifter:
    def __init__(self, is64=True, imports=None):
        self.is64 = is64
        self.imports = imports or {}      # va -> "dll!Name"
        self.flag_state = None
        self.stmts = []
        self.call_args = []
        self.last_rax = False
        self.last_rax_size = 8
        self.pending_lea = None

    # Register / operand helpers

    ARG_REGS = ('rcx', 'rdx', 'r8', 'r9')

    def reg(self, insn, reg_id, size=None):
        name = insn.reg_name(reg_id)
        canonical, reg_size = reg_info(name, self.is64)
        return CReg(canonical, size or reg_size)

    def _set_call_arg(self, canonical, expr):
        if canonical not in self.ARG_REGS:
            return
        index = self.ARG_REGS.index(canonical)
        while len(self.call_args) <= index:
            self.call_args.append(None)
        self.call_args[index] = expr

    def _note_write(self, canonical, expr):
        if canonical == 'rax':
            self.last_rax = True
            self.last_rax_size = getattr(expr, 'size', 8)
        self._set_call_arg(canonical, expr)

    def addr_expr(self, insn, op):
        mem = op.mem
        base = mem.base
        index = mem.index
        scale = mem.scale or 1
        disp = mem.disp
        if base and insn.reg_name(base).lower() in ('rip', 'eip'):
            absolute = (insn.address + insn.size + disp) & MASK64
            return CConst(absolute, 8)
        terms = []
        if base:
            terms.append(self.reg(insn, base))
        if index:
            idx = self.reg(insn, index)
            terms.append(CBin('*', idx, CConst(scale), 8) if scale != 1 else idx)
        if disp or not terms:
            value = disp if disp >= 0 else disp
            terms.append(CConst(value & MASK64 if self.is64 else value & 0xFFFFFFFF, 8))
        expr = terms[0]
        for term in terms[1:]:
            expr = CBin('+', expr, term, 8)
        return simplify(expr)

    def read_op(self, insn, op):
        if op.type == X86_OP_REG:
            return self.reg(insn, op.reg)
        if op.type == X86_OP_IMM:
            size = op.size or 8
            return CConst(op.imm & _mask_for(size), size)
        if op.type == X86_OP_MEM:
            address = self.addr_expr(insn, op)
            if isinstance(address, CConst) and address.value in self.imports:
                return CAddr(CString(self.imports[address.value]))
            size = op.size or 8
            return CDeref(address, size)
        return CConst(0, 8)

    def write_op(self, insn, op, value):
        if op.type == X86_OP_REG:
            dst = self.reg(insn, op.reg)
            return CSet(dst, value)
        if op.type == X86_OP_MEM:
            size = op.size or 8
            return CSet(CDeref(self.addr_expr(insn, op), size), value)
        return CComment(f'/* unsupported destination {insn.op_str} */')

    # Symbolic flags

    def _clear_flags(self):
        self.flag_state = None

    def _set_arith_flags(self, kind, lhs, rhs, result, size, op=None):
        self.flag_state = {
            'kind': kind, 'lhs': lhs, 'rhs': rhs,
            'res': result, 'size': size, 'op': op,
        }

    def cond_for(self, cc):
        fs = self.flag_state
        if fs is None:
            return CFlag('flag_' + cc)
        kind = fs['kind']
        lhs = fs['lhs']
        rhs = fs['rhs']
        res = fs['res']
        size = fs['size']
        zero = CConst(0, size)
        if kind == 'cmp':
            signed = cc in ('l', 'le', 'g', 'ge')
            unsigned = cc in ('b', 'be', 'a', 'ae')
            table = {
                'e': ('==', False), 'ne': ('!=', False),
                'b': ('<', True), 'be': ('<=', True), 'a': ('>', True), 'ae': ('>=', True),
                'l': ('<', False), 'le': ('<=', False), 'g': ('>', False), 'ge': ('>=', False),
            }
            if cc in table:
                op, is_unsigned = table[cc]
                a, b = lhs, rhs
                if is_unsigned and size < 8:
                    a = CCast(a, size, signed=False)
                    b = CCast(b, size, signed=False)
                return CCmp(op, a, b, unsigned=is_unsigned, size=size)
        if kind == 'test':
            if cc in ('e', 'ne'):
                value = CBin('&', lhs, rhs, size)
                op = '==' if cc == 'e' else '!='
                return CCmp(op, simplify(value), zero, unsigned=False, size=size)
            if cc in ('b', 'be', 'a', 'ae'):
                return CConst(0, 1) if cc in ('b', 'be') else CConst(1, 1)
        if kind == 'fcmp':
            table = {'b': '<', 'ae': '>=', 'be': '<=', 'a': '>',
                     'e': '==', 'ne': '!=', 'l': '<', 'ge': '>=', 'le': '<=', 'g': '>'}
            if cc in table:
                return CCmp(table[cc], lhs, rhs, unsigned=False, size=8)
        if cc in ('e', 'ne'):
            op = '==' if cc == 'e' else '!='
            return CCmp(op, res, zero, unsigned=False, size=size)
        if cc in ('l', 'le', 'g', 'ge'):
            op = {'l': '<', 'le': '<=', 'g': '>', 'ge': '>='}[cc]
            return CCmp(op, res, zero, unsigned=False, size=size)
        if cc in ('s', 'ns'):
            op = '<' if cc == 's' else '>='
            return CCmp(op, res, zero, unsigned=False, size=size)
        return CFlag('flag_' + cc)

    # Main entry

    def lift(self, insn):
        self.stmts = []
        mnemonic = insn.mnemonic
        handler = getattr(self, '_lift_' + mnemonic, None)
        if handler is not None:
            try:
                handler(insn)
            except Exception:
                self._clear_flags()
                self.stmts.append(CComment(f'/* {insn.mnemonic} {insn.op_str} */'))
        else:
            self._lift_generic(insn)
        for stmt in self.stmts:
            if (isinstance(stmt, CSet) and isinstance(stmt.dst, CReg)
                    and stmt.dst.name == 'rax'
                    and not expr_uses(stmt.src, {'rsp'})):
                self.last_rax = True
                self.last_rax_size = stmt.dst.size
        return self.stmts

    def _lift_generic(self, insn):
        if insn.mnemonic.startswith('.'):
            self.stmts.append(CComment(f'/* db 0x{insn.bytes[0]:02x} */' if insn.bytes else '/* db */'))
            return
        self._clear_flags()
        self.stmts.append(CComment(f'/* {insn.mnemonic} {insn.op_str} */'))

    # Data movement

    def _lift_mov(self, insn):
        ops = insn.operands
        dst, src = ops[0], ops[1]
        value = self.read_op(insn, src)
        if dst.type == X86_OP_REG:
            canonical, size = reg_info(insn.reg_name(dst.reg), self.is64)
            if size < 8:
                value = CCast(value, size, signed=False)
            self.stmts.append(CSet(CReg(canonical, size), value))
            self._note_write(canonical, value)
        else:
            self.stmts.append(self.write_op(insn, dst, value))

    def _lift_movzx(self, insn):
        ops = insn.operands
        dst = self.reg(insn, ops[0].reg)
        src = self.read_op(insn, ops[1])
        self.stmts.append(CSet(dst, CCast(src, dst.size, signed=False)))
        self._note_write(dst.name, dst)

    def _lift_movsx(self, insn):
        ops = insn.operands
        dst = self.reg(insn, ops[0].reg)
        src = self.read_op(insn, ops[1])
        self.stmts.append(CSet(dst, CCast(src, dst.size, signed=True)))
        self._note_write(dst.name, dst)

    def _lift_movsxd(self, insn):
        self._lift_movsx(insn)

    # SSE

    @staticmethod
    def _is_xmm(insn, op):
        return (op.type == X86_OP_REG
                and insn.reg_name(op.reg).lower().startswith(('xmm', 'ymm')))

    def _lift_sse_move(self, insn):
        ops = insn.operands
        self._clear_flags()
        dst = self._as_lvalue(insn, ops[0])
        if isinstance(dst, CReg):
            dst = CReg(dst.name, 8)
        src = self.read_op(insn, ops[1])
        if isinstance(src, CReg):
            src = CReg(src.name, 8)
        self.stmts.append(CSet(dst, src))

    def _lift_movsd(self, insn):
        if any(self._is_xmm(insn, op) for op in insn.operands):
            self._lift_sse_move(insn)
        else:
            self._lift_generic(insn)

    def _lift_movss(self, insn):
        if any(self._is_xmm(insn, op) for op in insn.operands):
            self._lift_sse_move(insn)
        else:
            self._lift_generic(insn)

    def _lift_movaps(self, insn):
        self._lift_sse_move(insn)

    def _lift_movups(self, insn):
        self._lift_sse_move(insn)

    def _lift_movdqa(self, insn):
        self._lift_sse_move(insn)

    def _lift_movdqu(self, insn):
        self._lift_sse_move(insn)

    def _lift_movq(self, insn):
        self._lift_sse_move(insn)

    def _lift_movd(self, insn):
        self._lift_sse_move(insn)

    def _lift_sse_bin(self, insn, op):
        self._clear_flags()
        ops = insn.operands
        dst = self._as_lvalue(insn, ops[0])
        lhs = self.read_op(insn, ops[0])
        rhs = self.read_op(insn, ops[1])
        self.stmts.append(CSet(dst, CBin(op, lhs, rhs, 8)))

    def _lift_addsd(self, insn):
        self._lift_sse_bin(insn, '+')

    def _lift_addss(self, insn):
        self._lift_sse_bin(insn, '+')

    def _lift_subsd(self, insn):
        self._lift_sse_bin(insn, '-')

    def _lift_subss(self, insn):
        self._lift_sse_bin(insn, '-')

    def _lift_mulsd(self, insn):
        self._lift_sse_bin(insn, '*')

    def _lift_mulss(self, insn):
        self._lift_sse_bin(insn, '*')

    def _lift_divsd(self, insn):
        self._lift_sse_bin(insn, '/')

    def _lift_divss(self, insn):
        self._lift_sse_bin(insn, '/')

    def _lift_xorps(self, insn):
        self._clear_flags()
        dst = self._as_lvalue(insn, insn.operands[0])
        self.stmts.append(CSet(dst, CConst(0, 16)))

    _lift_xorpd = _lift_xorps
    _lift_pxor = _lift_xorps
    _lift_pxord = _lift_xorps

    def _lift_fcmp(self, insn):
        lhs = self.read_op(insn, insn.operands[0])
        rhs = self.read_op(insn, insn.operands[1])
        self.flag_state = {'kind': 'fcmp', 'lhs': lhs, 'rhs': rhs,
                           'res': CConst(0, 8), 'size': 8, 'op': None}

    _lift_ucomisd = _lift_fcmp
    _lift_ucomiss = _lift_fcmp
    _lift_comisd = _lift_fcmp
    _lift_comiss = _lift_fcmp

    def _lift_cvtsi2sd(self, insn):
        dst = self._as_lvalue(insn, insn.operands[0])
        src = self.read_op(insn, insn.operands[1])
        self.stmts.append(CSet(dst, CCast(src, 8, signed=True)))

    _lift_cvtsi2ss = _lift_cvtsi2sd

    def _lift_cvttsd2si(self, insn):
        dst = self._as_lvalue(insn, insn.operands[0])
        src = self.read_op(insn, insn.operands[1])
        self.stmts.append(CSet(dst, CCast(src, dst.size if isinstance(dst, CReg) else 8, signed=True)))

    _lift_cvttss2si = _lift_cvttsd2si

    def _lift_cvtsd2ss(self, insn):
        self._lift_sse_move(insn)

    _lift_cvtss2sd = _lift_cvtsd2ss

    def _lift_lea(self, insn):
        ops = insn.operands
        dst = self.reg(insn, ops[0].reg)
        address = self.addr_expr(insn, ops[1])
        self.stmts.append(CSet(dst, CAddr(address)))
        self._note_write(dst.name, CAddr(address))

    def _lift_xchg(self, insn):
        ops = insn.operands
        a = self.read_op(insn, ops[0])
        b = self.read_op(insn, ops[1])
        self.stmts.append(CSet(self._as_lvalue(insn, ops[0]), b))
        self.stmts.append(CSet(self._as_lvalue(insn, ops[1]), a))

    def _as_lvalue(self, insn, op):
        if op.type == X86_OP_REG:
            return self.reg(insn, op.reg)
        return CDeref(self.addr_expr(insn, op), op.size or 8)

    def _lift_push(self, insn):
        self.stmts.append(CPush(self.read_op(insn, insn.operands[0])))

    def _lift_pop(self, insn):
        self.stmts.append(CPop(self._as_lvalue(insn, insn.operands[0])))

    def _lift_leave(self, insn):
        self.stmts.append(CSet(CReg('rsp', 8), CReg('rbp', 8)))
        self.stmts.append(CPop(CReg('rbp', 8)))

    def _lift_enter(self, insn):
        self.stmts.append(CPush(CReg('rbp', 8)))
        self.stmts.append(CSet(CReg('rbp', 8), CReg('rsp', 8)))
        if len(insn.operands) > 1:
            self.stmts.append(CSet(CReg('rsp', 8),
                                   CBin('-', CReg('rsp', 8), CConst(insn.operands[1].imm), 8)))

    def _lift_nop(self, insn):
        return

    def _lift_int3(self, insn):
        self.stmts.append(CComment('__debugbreak();'))

    def _lift_hlt(self, insn):
        self.stmts.append(CComment('__halt();'))

    def _lift_ud2(self, insn):
        self.stmts.append(CComment('__builtin_trap();'))

    # Arithmetic

    def _binary_arith(self, insn, op, size, signed=False):
        ops = insn.operands
        lhs = self.read_op(insn, ops[0])
        rhs = self.read_op(insn, ops[1])
        result = CBin(op, lhs, rhs, size)
        self._set_arith_flags('arith', lhs, rhs, result, size, op)
        self.stmts.append(CSet(self._as_lvalue(insn, ops[0]), result))

    def _lift_add(self, insn):
        self._binary_arith(insn, '+', insn.operands[0].size or 8)

    def _lift_sub(self, insn):
        self._binary_arith(insn, '-', insn.operands[0].size or 8)

    def _lift_adc(self, insn):
        ops = insn.operands
        lhs = self.read_op(insn, ops[0])
        rhs = self.read_op(insn, ops[1])
        size = ops[0].size or 8
        result = CBin('+', CBin('+', lhs, rhs, size), CFlag('cf'), size)
        self._set_arith_flags('arith', lhs, rhs, result, size, '+')
        self.stmts.append(CSet(self._as_lvalue(insn, ops[0]), result))

    def _lift_sbb(self, insn):
        ops = insn.operands
        lhs = self.read_op(insn, ops[0])
        rhs = self.read_op(insn, ops[1])
        size = ops[0].size or 8
        result = CBin('-', CBin('-', lhs, rhs, size), CFlag('cf'), size)
        self._set_arith_flags('arith', lhs, rhs, result, size, '-')
        self.stmts.append(CSet(self._as_lvalue(insn, ops[0]), result))

    def _lift_inc(self, insn):
        op = insn.operands[0]
        size = op.size or 8
        lhs = self.read_op(insn, op)
        result = CBin('+', lhs, CConst(1, size), size)
        self._set_arith_flags('arith', lhs, CConst(1, size), result, size, '+')
        self.stmts.append(CSet(self._as_lvalue(insn, op), result))

    def _lift_dec(self, insn):
        op = insn.operands[0]
        size = op.size or 8
        lhs = self.read_op(insn, op)
        result = CBin('-', lhs, CConst(1, size), size)
        self._set_arith_flags('arith', lhs, CConst(1, size), result, size, '-')
        self.stmts.append(CSet(self._as_lvalue(insn, op), result))

    def _lift_neg(self, insn):
        op = insn.operands[0]
        size = op.size or 8
        lhs = self.read_op(insn, op)
        result = CUn('-', lhs, size)
        self._set_arith_flags('arith', CConst(0, size), lhs, result, size, '-')
        self.stmts.append(CSet(self._as_lvalue(insn, op), result))

    def _lift_not(self, insn):
        op = insn.operands[0]
        size = op.size or 8
        self.stmts.append(CSet(self._as_lvalue(insn, op), CUn('~', self.read_op(insn, op), size)))
        self._clear_flags()

    def _lift_and(self, insn):
        self._binary_arith(insn, '&', insn.operands[0].size or 8)

    def _lift_or(self, insn):
        self._binary_arith(insn, '|', insn.operands[0].size or 8)

    def _lift_xor(self, insn):
        ops = insn.operands
        lhs = self.read_op(insn, ops[0])
        rhs = self.read_op(insn, ops[1])
        size = ops[0].size or 8
        if _expr_key(lhs) == _expr_key(rhs):
            result = CConst(0, size)
        else:
            result = CBin('^', lhs, rhs, size)
        self._set_arith_flags('logic', lhs, rhs, result, size, '^')
        self.stmts.append(CSet(self._as_lvalue(insn, ops[0]), result))
        if ops[0].type == X86_OP_REG:
            canonical, _ = reg_info(insn.reg_name(ops[0].reg), self.is64)
            self._note_write(canonical, result)

    def _lift_cmp(self, insn):
        ops = insn.operands
        lhs = self.read_op(insn, ops[0])
        rhs = self.read_op(insn, ops[1])
        size = ops[0].size or 8
        result = CBin('-', lhs, rhs, size)
        self._set_arith_flags('cmp', lhs, rhs, result, size, '-')

    def _lift_test(self, insn):
        ops = insn.operands
        lhs = self.read_op(insn, ops[0])
        rhs = self.read_op(insn, ops[1])
        size = ops[0].size or 8
        result = CBin('&', lhs, rhs, size)
        self._set_arith_flags('test', lhs, rhs, result, size, '&')

    def _lift_shl(self, insn):
        self._shift(insn, '<<')

    def _lift_sal(self, insn):
        self._shift(insn, '<<')

    def _lift_shr(self, insn):
        self._shift(insn, '>>', unsigned=True)

    def _lift_sar(self, insn):
        self._shift(insn, '>>')

    def _lift_rol(self, insn):
        self._lift_generic(insn)

    def _lift_ror(self, insn):
        self._lift_generic(insn)

    def _lift_shld(self, insn):
        self._lift_generic(insn)

    def _lift_shrd(self, insn):
        self._lift_generic(insn)

    def _shift(self, insn, op, unsigned=False):
        ops = insn.operands
        lhs = self.read_op(insn, ops[0])
        if len(ops) > 1:
            rhs = self.read_op(insn, ops[1])
        else:
            rhs = CConst(1, 8)
        size = ops[0].size or 8
        if unsigned:
            lhs = CCast(lhs, size, signed=False)
        result = CBin(op, lhs, rhs, size)
        self._set_arith_flags('logic', lhs, rhs, result, size, op)
        self.stmts.append(CSet(self._as_lvalue(insn, ops[0]), result))

    def _lift_imul(self, insn):
        ops = insn.operands
        if len(ops) == 1:
            src = self.read_op(insn, ops[0])
            size = ops[0].size or 8
            result = CBin('*', CCast(CReg('rax', size), size, signed=True), CCast(src, size, signed=True), size)
            self.stmts.append(CSet(CReg('rax', size), result))
            self._clear_flags()
        elif len(ops) == 2:
            dst = self._as_lvalue(insn, ops[0])
            lhs = self.read_op(insn, ops[0])
            rhs = self.read_op(insn, ops[1])
            self.stmts.append(CSet(dst, CBin('*', lhs, rhs, ops[0].size or 8)))
            self._clear_flags()
        else:
            dst = self._as_lvalue(insn, ops[0])
            lhs = self.read_op(insn, ops[1])
            rhs = self.read_op(insn, ops[2])
            self.stmts.append(CSet(dst, CBin('*', lhs, rhs, ops[0].size or 8)))
            self._clear_flags()

    def _lift_mul(self, insn):
        self._lift_imul(insn)

    def _lift_div(self, insn):
        src = self.read_op(insn, insn.operands[0])
        size = insn.operands[0].size or 8
        value = CBin('/', CCast(CReg('rdx', size * 2), size * 2, signed=False), CCast(src, size * 2, signed=False), size)
        self.stmts.append(CSet(CReg('rax', size), value))
        self._clear_flags()

    def _lift_idiv(self, insn):
        src = self.read_op(insn, insn.operands[0])
        size = insn.operands[0].size or 8
        value = CBin('/', CCast(CReg('rdx', size * 2), size * 2, signed=True), CCast(src, size * 2, signed=True), size)
        self.stmts.append(CSet(CReg('rax', size), value))
        self._clear_flags()

    def _lift_cdq(self, insn):
        self.stmts.append(CSet(CReg('rdx', 4), CCast(CBin('>>', CReg('rax', 4), CConst(31, 4), 4), 4, signed=True)))
        self._clear_flags()

    def _lift_cqo(self, insn):
        self.stmts.append(CSet(CReg('rdx', 8), CCast(CBin('>>', CReg('rax', 8), CConst(63, 8), 8), 8, signed=True)))
        self._clear_flags()

    def _lift_cwd(self, insn):
        self.stmts.append(CSet(CReg('rdx', 2), CCast(CBin('>>', CReg('rax', 2), CConst(15, 2), 2), 2, signed=True)))
        self._clear_flags()

    def _lift_cdqe(self, insn):
        self.stmts.append(CSet(CReg('rax', 8), CCast(CReg('rax', 4), 8, signed=True)))

    def _lift_cwde(self, insn):
        self.stmts.append(CSet(CReg('rax', 4), CCast(CReg('rax', 2), 4, signed=True)))

    def _lift_cbw(self, insn):
        self.stmts.append(CSet(CReg('rax', 2), CCast(CReg('rax', 1), 2, signed=True)))

    # Control flow

    def _lift_call(self, insn):
        op = insn.operands[0] if insn.operands else None
        target = None
        if op is not None and op.type == X86_OP_IMM:
            target = op.imm & MASK64
        name = None
        if target is not None and target in self.imports:
            name = self.imports[target].split('!')[-1]
        elif op is not None and op.type == X86_OP_MEM:
            address = self.addr_expr(insn, op)
            if isinstance(address, CConst) and address.value in self.imports:
                name = self.imports[address.value].split('!')[-1]
        if name is None:
            if target is not None:
                name = f'sub_{target:X}'
            else:
                name = 'unknown_indirect'
        args = list(self.call_args)
        while args and args[-1] is None:
            args.pop()
        args = [CConst(0, 8) if a is None else a for a in args]
        self.call_args = []
        lower = (name or '').lower()
        if ('security_check_cookie' in lower or 'stack_chk' in lower
                or any(expr_uses(a, {'rsp'}) for a in args)):
            self._clear_flags()
            return
        self.last_rax = True
        self.last_rax_size = 8
        self._clear_flags()
        self.stmts.append(CCallStmt(CCall(name, args), CReg('rax', 8)))

    def _lift_ret(self, insn):
        if self.stmts and isinstance(self.stmts[-1], CCallStmt):
            call = self.stmts.pop().call
            self.stmts.append(CRet(call))
            return
        value = CReg('rax', getattr(self, 'last_rax_size', 8)) if self.last_rax else None
        self.stmts.append(CRet(value))

    def _lift_jmp(self, insn):
        op = insn.operands[0] if insn.operands else None
        if op is not None and op.type == X86_OP_IMM:
            self.stmts.append(CJump(op.imm & MASK64))
        elif op is not None and op.type == X86_OP_MEM:
            address = self.addr_expr(insn, op)
            if isinstance(address, CConst) and address.value in self.imports:
                self.stmts.append(CComment(f'/* jmp {self.imports[address.value]} */'))
            else:
                self.stmts.append(CJumpIndirect(CDeref(address, 8)))
        else:
            self.stmts.append(CJumpIndirect(self.read_op(insn, op) if op else CConst(0)))

    def _jcc(self, insn):
        cc = CC_NAMES.get(insn.mnemonic)
        target = insn.operands[0].imm & MASK64 if insn.operands else None
        cond = self.cond_for(cc) if cc else CFlag('flags')
        self._clear_flags()
        self.stmts.append(CBranch(cond, target))

    _lift_je = _jcc
    _lift_jne = _jcc
    _lift_jz = _jcc
    _lift_jnz = _jcc
    _lift_jb = _jcc
    _lift_jnae = _jcc
    _lift_jbe = _jcc
    _lift_jna = _jcc
    _lift_ja = _jcc
    _lift_jnbe = _jcc
    _lift_jae = _jcc
    _lift_jnb = _jcc
    _lift_jg = _jcc
    _lift_jnle = _jcc
    _lift_jge = _jcc
    _lift_jnl = _jcc
    _lift_jl = _jcc
    _lift_jnge = _jcc
    _lift_jle = _jcc
    _lift_jng = _jcc
    _lift_js = _jcc
    _lift_jns = _jcc
    _lift_jo = _jcc
    _lift_jno = _jcc
    _lift_jp = _jcc
    _lift_jnp = _jcc

    def _lift_setcc(self, insn):
        cc = CC_NAMES.get(insn.mnemonic)
        cond = self.cond_for(cc) if cc else CFlag('flags')
        dst = self._as_lvalue(insn, insn.operands[0])
        self.stmts.append(CSet(dst, CCast(cond, dst.size, signed=False)))

    _lift_sete = _lift_setcc
    _lift_setne = _lift_setcc
    _lift_setb = _lift_setcc
    _lift_setae = _lift_setcc
    _lift_setbe = _lift_setcc
    _lift_seta = _lift_setcc
    _lift_setl = _lift_setcc
    _lift_setge = _lift_setcc
    _lift_setg = _lift_setcc
    _lift_setle = _lift_setcc
    _lift_sets = _lift_setcc
    _lift_setns = _lift_setcc
    _lift_seto = _lift_setcc
    _lift_setno = _lift_setcc
    _lift_setp = _lift_setcc
    _lift_setnp = _lift_setcc

    def _lift_cmovcc(self, insn):
        cc = CC_NAMES.get(insn.mnemonic)
        cond = self.cond_for(cc) if cc else CFlag('flags')
        dst_op, src_op = insn.operands[0], insn.operands[1]
        dst = self._as_lvalue(insn, dst_op)
        src = self.read_op(insn, src_op)
        current = self.read_op(insn, dst_op)
        self.stmts.append(CSet(dst, CBin('?', cond, src, dst.size)))
        self.stmts[-1].src = _Conditional(cond, src, current)

    _lift_cmove = _lift_cmovcc
    _lift_cmovne = _lift_cmovcc
    _lift_cmovb = _lift_cmovcc
    _lift_cmovae = _lift_cmovcc
    _lift_cmovbe = _lift_cmovcc
    _lift_cmova = _lift_cmovcc
    _lift_cmovl = _lift_cmovcc
    _lift_cmovge = _lift_cmovcc
    _lift_cmovg = _lift_cmovcc
    _lift_cmovle = _lift_cmovcc
    _lift_cmovs = _lift_cmovcc
    _lift_cmovns = _lift_cmovcc
    _lift_cmovo = _lift_cmovcc
    _lift_cmovno = _lift_cmovcc
    _lift_cmovp = _lift_cmovcc
    _lift_cmovnp = _lift_cmovcc

    # misc

    def _lift_cpuid(self, insn):
        self._clear_flags()
        self.stmts.append(CComment('__cpuid(rax, rbx, rcx, rdx);'))

    def _lift_rdtsc(self, insn):
        self.stmts.append(CSet(CReg('rax', 8), CCall('__rdtsc', [])))
        self.stmts.append(CSet(CReg('rdx', 8), CConst(0)))

    def _lift_syscall(self, insn):
        self._clear_flags()
        self.stmts.append(CComment('syscall();'))

    def _lift_rep(self, insn):
        self._clear_flags()
        self.stmts.append(CComment(f'/* rep {insn.op_str} */'))

    def _lift_stosb(self, insn):
        self.stmts.append(CSet(CDeref(CReg('rdi', 8), 1), CReg('rax', 1)))
        self.stmts.append(CSet(CReg('rdi', 8), CBin('+', CReg('rdi', 8), CConst(1), 8)))
        self._clear_flags()

    def _lift_stosd(self, insn):
        self.stmts.append(CSet(CDeref(CReg('rdi', 8), 4), CReg('rax', 4)))
        self.stmts.append(CSet(CReg('rdi', 8), CBin('+', CReg('rdi', 8), CConst(4), 8)))
        self._clear_flags()

    def _lift_stosq(self, insn):
        self.stmts.append(CSet(CDeref(CReg('rdi', 8), 8), CReg('rax', 8)))
        self.stmts.append(CSet(CReg('rdi', 8), CBin('+', CReg('rdi', 8), CConst(8), 8)))
        self._clear_flags()

    def _lift_movsb(self, insn):
        self.stmts.append(CSet(CDeref(CReg('rdi', 8), 1), CDeref(CReg('rsi', 8), 1)))
        self.stmts.append(CSet(CReg('rdi', 8), CBin('+', CReg('rdi', 8), CConst(1), 8)))
        self.stmts.append(CSet(CReg('rsi', 8), CBin('+', CReg('rsi', 8), CConst(1), 8)))
        self._clear_flags()

    def _lift_movsq(self, insn):
        self.stmts.append(CSet(CDeref(CReg('rdi', 8), 8), CDeref(CReg('rsi', 8), 8)))
        self.stmts.append(CSet(CReg('rdi', 8), CBin('+', CReg('rdi', 8), CConst(8), 8)))
        self.stmts.append(CSet(CReg('rsi', 8), CBin('+', CReg('rsi', 8), CConst(8), 8)))
        self._clear_flags()

    def _lift_bswap(self, insn):
        op = insn.operands[0]
        size = op.size or 8
        self.stmts.append(CCallStmt(CCall(f'__builtin_bswap{size * 8}', [self.read_op(insn, op)]),
                                    self._as_lvalue(insn, op)))

    def _lift_cmc(self, insn):
        self._clear_flags()

    def _lift_clc(self, insn):
        self._clear_flags()

    def _lift_stc(self, insn):
        self._clear_flags()

    def _lift_cld(self, insn):
        self._clear_flags()

    def _lift_std(self, insn):
        self._clear_flags()


class _Conditional(CExpr):
    """Ternary used only for cmov rendering."""
    __slots__ = ('cond', 'a', 'b', 'size')

    def __init__(self, cond, a, b):
        self.cond = cond
        self.a = a
        self.b = b
        self.size = a.size



class CPseudoProgram:
    def __init__(self, image, image_base, is64, imports=None, exec_ranges=None,
                 strings=None, logger=None):
        self.image = image
        self.image_base = image_base
        self.is64 = is64
        self.imports = imports or {}
        self.exec_ranges = list(exec_ranges or [])
        self.strings = strings or {}
        self.logger = logger
        self.md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
        self.md.detail = True
        self.md.skipdata = True
        self.decode_cache = {}
        self.functions = OrderedDict()
        self.pdata = []
        self.pdata_starts = set()
        self.lifter = CLifter(is64, imports)
        self.warnings = []


    def read(self, va, size):
        off = va - self.image_base
        if off < 0 or off >= len(self.image):
            return b''
        return self.image[off:off + size]

    def is_exec(self, va):
        for start, end in self.exec_ranges:
            if start <= va < end:
                return True
        return False

    def decode(self, va):
        if va in self.decode_cache:
            return self.decode_cache[va]
        off = va - self.image_base
        if off < 0 or off >= len(self.image):
            self.decode_cache[va] = None
            return None
        chunk = self.image[off:off + 16]
        insn = next(self.md.disasm(chunk, va), None)
        if insn is not None and (insn.mnemonic.startswith('.') or insn.size == 0):
            insn = None
        self.decode_cache[va] = insn
        return insn

    def imm_target(self, insn):
        if not insn.operands:
            return None
        op = insn.operands[0]
        if op.type != X86_OP_IMM:
            return None
        if insn.mnemonic in COND_JUMPS or insn.mnemonic in ('jmp', 'call'):
            return op.imm & MASK64
        return None

    def _range_for(self, start):
        for s, e in self.pdata:
            if s == start:
                return (s, e)
        return None

    def is_known_start(self, va):
        return va in self.pdata_starts

    # .pdata

    def load_pdata(self, pe):
        try:
            dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
            if len(dd) <= 3:
                return
            entry = dd[3]
            if not entry.VirtualAddress or not entry.Size:
                return
            raw = self.read(self.image_base + entry.VirtualAddress, entry.Size)
            for off in range(0, len(raw) - 11, 12):
                begin, end, _unwind = struct.unpack_from('<III', raw, off)
                if begin == 0 and end == 0:
                    continue
                if begin >= end or end - begin > 0x400000:
                    continue
                s = self.image_base + begin
                e = self.image_base + end
                self.pdata.append((s, e))
                self.pdata_starts.add(s)
        except Exception:
            pass

    # Function discovery

    def discover(self, roots, max_functions=5000, max_insns_per_func=200000):
        root_list = []
        seen_roots = set()
        for va in roots:
            if va and va not in seen_roots and self.is_exec(va):
                seen_roots.add(va)
                root_list.append(va)
        queue = deque(root_list)
        queued = set(root_list)
        while queue and len(self.functions) < max_functions:
            start = queue.popleft()
            if start in self.functions:
                continue
            func = self.build_function(start, max_insns_per_func)
            if func is None or not func.insns:
                continue
            self.functions[start] = func
            for target in list(func.call_targets) + list(func.tail_targets):
                if target not in queued and target not in self.functions and self.is_exec(target):
                    queued.add(target)
                    queue.append(target)

    def build_function(self, start, max_insns=200000):
        func = CFunction(start, self.is64)
        work = [start]
        seen = set()
        insns = []
        call_targets = []
        tail_targets = []
        switch_info = {}
        reg_const = {}
        limit = self._range_for(start)

        while work:
            va = work.pop()
            while True:
                if len(insns) > max_insns:
                    break
                if va in seen or not self.is_exec(va):
                    break
                if limit is not None and va >= limit[1]:
                    break
                insn = self.decode(va)
                if insn is None:
                    break
                seen.add(va)
                insns.append(insn)

                mnemonic = insn.mnemonic
                if mnemonic == 'ret' or mnemonic.startswith('ret'):
                    break
                if mnemonic == 'jmp':
                    target = self.imm_target(insn)
                    if target is None:
                        resolved = self.resolve_jump_table(insn, reg_const)
                        if resolved:
                            switch_info[insn.address] = resolved
                            for _case, tgt, _vals in resolved['cases']:
                                work.append(tgt)
                            if resolved['default'] is not None:
                                work.append(resolved['default'])
                        break
                    if self.is_known_start(target) and target != start:
                        tail_targets.append(target)
                        break
                    work.append(target)
                    break
                if mnemonic in COND_JUMPS:
                    target = self.imm_target(insn)
                    if target is not None:
                        work.append(target)
                    va += insn.size
                    continue
                if mnemonic == 'call':
                    target = self.imm_target(insn)
                    if target is not None and self.is_exec(target) and target not in self.imports:
                        call_targets.append(target)
                    va += insn.size
                    continue

                self._track_reg_const(insn, reg_const)
                if mnemonic in ('nop', 'endbr64', 'endbr32'):
                    va += insn.size
                    continue
                va += insn.size

        if not insns:
            return None

        func.insns = sorted(insns, key=lambda i: i.address)
        func.insn_by_addr = {i.address: i for i in func.insns}
        func.end = func.insns[-1].address + func.insns[-1].size
        func.call_targets = sorted(set(call_targets))
        func.tail_targets = sorted(set(tail_targets))

        func.stmts_by_addr = {}
        for insn in func.insns:
            func.stmts_by_addr[insn.address] = self.lifter.lift(insn)

        self.build_blocks(func, switch_info)
        return func

    def _track_reg_const(self, insn, reg_const):
        try:
            if insn.mnemonic == 'lea' and len(insn.operands) == 2:
                dst = insn.operands[0]
                src = insn.operands[1]
                if dst.type == X86_OP_REG and src.type == X86_OP_MEM:
                    if src.mem.base and insn.reg_name(src.mem.base).lower() in ('rip', 'eip'):
                        reg_const[insn.reg_name(dst.reg).lower()] = (
                            insn.address + insn.size + src.mem.disp) & MASK64
                        return
                reg_const.pop(insn.reg_name(dst.reg).lower() if dst.type == X86_OP_REG else '', None)
            elif insn.mnemonic == 'mov' and len(insn.operands) == 2:
                dst, src = insn.operands
                if dst.type == X86_OP_REG:
                    name = insn.reg_name(dst.reg).lower()
                    if src.type == X86_OP_IMM:
                        reg_const[name] = src.imm & MASK64
                    elif src.type == X86_OP_MEM and src.mem.base and \
                            insn.reg_name(src.mem.base).lower() in ('rip', 'eip') and not src.mem.index:
                        reg_const[name] = (insn.address + insn.size + src.mem.disp) & MASK64
                    else:
                        reg_const.pop(name, None)
        except Exception:
            pass

    def resolve_jump_table(self, insn, reg_const):
        """Resolve a static jump table used by `jmp [base + index*scale]`."""
        try:
            if not insn.operands:
                return None
            op = insn.operands[0]
            if op.type != X86_OP_MEM or not op.mem.index or op.mem.base:
                return None
            base_name = insn.reg_name(op.mem.base).lower() if op.mem.base else None
            if base_name is None:
                return None
            base = reg_const.get(base_name)
            if base is None:
                return None
            scale = op.mem.scale or 8
            if scale not in (4, 8):
                return None
            disp = op.mem.disp
            table = (base + disp) & MASK64
            entries = []
            default = None
            for idx in range(0, 1024):
                raw = self.read(table + idx * scale, scale)
                if len(raw) < scale:
                    break
                if scale == 8:
                    value = struct.unpack('<Q', raw)[0]
                    target = value
                else:
                    value = struct.unpack('<i', raw)[0]
                    target = (base + value) & MASK64
                if not self.is_exec(target):
                    if idx and default is None:
                        default = target
                    break
                entries.append((idx, target, idx))
            if len(entries) < 4:
                return None
            return {'cases': entries, 'default': default, 'table': table}
        except Exception:
            return None

    # basic blocks / CFG

    def build_blocks(self, func, switch_info):
        addrs = [i.address for i in func.insns]
        if not addrs:
            return
        addr_set = set(addrs)
        leaders = {addrs[0]}
        for insn in func.insns:
            mnemonic = insn.mnemonic
            is_term = (mnemonic in COND_JUMPS or mnemonic == 'jmp' or
                       mnemonic == 'ret' or mnemonic.startswith('ret'))
            if not is_term:
                continue
            nxt = insn.address + insn.size
            if nxt in addr_set:
                leaders.add(nxt)
            target = self.imm_target(insn)
            if target is not None and target in addr_set:
                leaders.add(target)
            info = switch_info.get(insn.address)
            if info:
                for _case, tgt, _vals in info['cases']:
                    if tgt in addr_set:
                        leaders.add(tgt)
                if info['default'] is not None and info['default'] in addr_set:
                    leaders.add(info['default'])
        leaders = sorted(a for a in leaders if a in addr_set)

        current = None
        for address in addrs:
            if address in leaders or current is None:
                current = CBlock(address)
                func.blocks[address] = current
            current.insns.append(func.insn_by_addr[address])

        for blk in func.blocks.values():
            all_stmts = []
            for insn in blk.insns:
                all_stmts.extend(func.stmts_by_addr.get(insn.address, []))
            blk.stmts = all_stmts
            if all_stmts and isinstance(all_stmts[-1], (CJump, CBranch, CRet, CJumpIndirect, CSwitch)):
                blk.term = all_stmts[-1]
                blk.stmts = all_stmts[:-1]
            if isinstance(blk.term, CJumpIndirect):
                last_insn = blk.insns[-1]
                info = switch_info.get(last_insn.address)
                if info:
                    value = self._switch_value(last_insn)
                    cases = OrderedDict()
                    for _case, tgt, vals in info['cases']:
                        cases[vals] = tgt
                    blk.term = CSwitch(value, cases, info['default'])
                    func.switches[last_insn.address] = info

        # fallthrough + successors
        order = [b.address for b in func.blocks.values()]
        for i, addr in enumerate(order):
            blk = func.blocks[addr]
            nxt = order[i + 1] if i + 1 < len(order) else None
            blk.fallthrough = nxt
            if isinstance(blk.term, CJump):
                blk.succ = [blk.term.target]
            elif isinstance(blk.term, CBranch):
                blk.succ = [blk.term.t]
                if blk.term.f is None and nxt is not None:
                    blk.term.f = nxt
                if blk.term.f is not None:
                    blk.succ.append(blk.term.f)
            elif isinstance(blk.term, CSwitch):
                blk.succ = list(blk.term.cases.values())
                if blk.term.default is not None:
                    blk.succ.append(blk.term.default)
            elif isinstance(blk.term, CRet):
                blk.succ = []
            elif isinstance(blk.term, CJumpIndirect):
                blk.succ = []
            else:
                blk.succ = [nxt] if nxt is not None else []
            blk.succ = [s for s in dict.fromkeys(blk.succ) if s in func.blocks]

        for blk in func.blocks.values():
            for s in blk.succ:
                if s in func.blocks and blk.address not in func.blocks[s].pred:
                    func.blocks[s].pred.append(blk.address)

        # reachability
        reachable = set()
        stack = [func.entry]
        while stack:
            b = stack.pop()
            if b in reachable or b not in func.blocks:
                continue
            reachable.add(b)
            for s in func.blocks[b].succ:
                stack.append(s)
        func.reachable = reachable
        func.blocks = OrderedDict((a, b) for a, b in func.blocks.items() if a in reachable)
        for blk in func.blocks.values():
            blk.succ = [s for s in blk.succ if s in func.blocks]
            blk.pred = [p for p in blk.pred if p in func.blocks]

    def _switch_value(self, insn):
        op = insn.operands[0]
        index = op.mem.index
        if index:
            name = insn.reg_name(index)
            canonical, size = reg_info(name, self.is64)
            return CReg(canonical, size)
        return CReg('rax', 8)



# Passes

def _const_signed(c):
    value = c.value
    if value >= (1 << 63):
        value -= (1 << 64)
    return value


def _stack_disp(expr, base):
    if isinstance(expr, CReg) and expr.name == base:
        return 0
    if isinstance(expr, CBin):
        if expr.op == '+':
            if isinstance(expr.a, CReg) and expr.a.name == base and isinstance(expr.b, CConst):
                return _const_signed(expr.b)
            if isinstance(expr.b, CReg) and expr.b.name == base and isinstance(expr.a, CConst):
                return _const_signed(expr.a)
        if expr.op == '-':
            if isinstance(expr.a, CReg) and expr.a.name == base and isinstance(expr.b, CConst):
                return -_const_signed(expr.b)
    return None


def _pointer_root(expr):
    """If `expr` is a simple pointer expression, return the root variable name."""
    if isinstance(expr, CVar):
        return expr.name
    if isinstance(expr, CReg):
        return expr.name
    if isinstance(expr, CBin) and expr.op in ('+', '-'):
        for side in (expr.a, expr.b):
            if isinstance(side, (CVar, CReg)):
                return side.name
            if isinstance(side, CBin) and side.op == '*':
                root = _pointer_root(side.a)
                if root:
                    return root
    return None


def _map_expr(e, fn):
    if e is None:
        return None
    mapped = fn(e)
    if mapped is not e:
        return mapped
    if isinstance(e, CBin):
        return CBin(e.op, _map_expr(e.a, fn), _map_expr(e.b, fn), e.size)
    if isinstance(e, CUn):
        return CUn(e.op, _map_expr(e.a, fn), e.size)
    if isinstance(e, CCast):
        return CCast(_map_expr(e.expr, fn), e.size, e.signed)
    if isinstance(e, CDeref):
        return CDeref(_map_expr(e.addr, fn), e.size)
    if isinstance(e, CAddr):
        return CAddr(_map_expr(e.expr, fn))
    if isinstance(e, CCmp):
        return CCmp(e.op, _map_expr(e.a, fn), _map_expr(e.b, fn), e.unsigned, e.size)
    if isinstance(e, CCall):
        return CCall(e.name, [_map_expr(x, fn) for x in e.args], e.size)
    if isinstance(e, _Conditional):
        return _Conditional(_map_expr(e.cond, fn), _map_expr(e.a, fn), _map_expr(e.b, fn))
    return e


def _map_stmt(stmt, fn, include_dst=True):
    if isinstance(stmt, CSet):
        dst = _map_expr(stmt.dst, fn) if include_dst else stmt.dst
        return CSet(dst, _map_expr(stmt.src, fn))
    if isinstance(stmt, CBranch):
        return CBranch(_map_expr(stmt.cond, fn), stmt.t, stmt.f)
    if isinstance(stmt, CRet):
        return CRet(_map_expr(stmt.value, fn) if stmt.value is not None else None)
    if isinstance(stmt, CCallStmt):
        return CCallStmt(_map_expr(stmt.call, fn), stmt.dst)
    if isinstance(stmt, CPush):
        return CPush(_map_expr(stmt.value, fn))
    if isinstance(stmt, CPop):
        return CPop(stmt.dst)
    if isinstance(stmt, CJumpIndirect):
        return CJumpIndirect(_map_expr(stmt.value, fn))
    if isinstance(stmt, CSwitch):
        return CSwitch(_map_expr(stmt.value, fn), stmt.cases, stmt.default)
    return stmt


def _subst_reads(stmt, mapping):
    if not mapping:
        return stmt
    if isinstance(stmt, CSet):
        return CSet(stmt.dst, replace_expr(stmt.src, mapping))
    if isinstance(stmt, CBranch):
        return CBranch(replace_expr(stmt.cond, mapping), stmt.t, stmt.f)
    if isinstance(stmt, CRet):
        return CRet(replace_expr(stmt.value, mapping) if stmt.value is not None else None)
    if isinstance(stmt, CCallStmt):
        return CCallStmt(CCall(stmt.call.name,
                               [replace_expr(a, mapping) for a in stmt.call.args]),
                         stmt.dst)
    if isinstance(stmt, CPush):
        return CPush(replace_expr(stmt.value, mapping))
    if isinstance(stmt, CJumpIndirect):
        return CJumpIndirect(replace_expr(stmt.value, mapping))
    if isinstance(stmt, CSwitch):
        return CSwitch(replace_expr(stmt.value, mapping), stmt.cases, stmt.default)
    return stmt


_CALLEE_SAVED = {'rbx', 'rbp', 'rsi', 'rdi', 'r12', 'r13', 'r14', 'r15'}


def func_target_is64(func):
    return bool(getattr(func, 'is64', True))


def pass_stack_frame(func):
    func.locals = OrderedDict()
    entry = func.blocks.get(func.entry)
    remove = set()
    frame = None
    rsp_adjust = 0
    if entry is not None:
        seq = entry.stmts
        push_index = None
        for i in range(min(10, len(seq))):
            s = seq[i]
            if isinstance(s, CPush) and isinstance(s.value, CReg) and s.value.name == 'rbp':
                push_index = i
                break
        if push_index is not None:
            for j in range(push_index + 1, min(push_index + 4, len(seq))):
                s = seq[j]
                if (isinstance(s, CSet) and isinstance(s.dst, CReg) and s.dst.name == 'rbp'
                        and isinstance(s.src, CReg) and s.src.name == 'rsp'):
                    frame = 'rbp'
                    func.rbp_const = 0
                    remove.update({push_index, j})
                    break
        if frame is None:
            # frame pointer built directly from rsp (lea/mov rbp, rsp [+/- k])
            for i in range(min(12, len(seq))):
                s = seq[i]
                if (isinstance(s, CSet) and isinstance(s.dst, CReg) and s.dst.name == 'rbp'
                        and expr_uses(s.src, {'rsp'})):
                    frame = 'rbp'
                    func.rbp_const = _rbp_const_from(s.src)
                    remove.add(i)
                    break
        for i, s in enumerate(seq):
            if (isinstance(s, CSet) and isinstance(s.dst, CReg) and s.dst.name == 'rsp'
                    and isinstance(s.src, CBin) and isinstance(s.src.a, CReg)
                    and s.src.a.name == 'rsp' and isinstance(s.src.b, CConst)):
                if s.src.op == '-':
                    rsp_adjust = max(rsp_adjust, _const_signed(s.src.b))
                    if frame == 'rbp':
                        remove.add(i)
                elif s.src.op == '+':
                    remove.add(i)
    # epilogue
    for blk in func.blocks.values():
        seq = blk.stmts
        for i, s in enumerate(seq):
            if (isinstance(s, CSet) and isinstance(s.dst, CReg) and s.dst.name == 'rsp'
                    and isinstance(s.src, CReg) and s.src.name == 'rbp'):
                remove.add((blk.address, i))
                if i + 1 < len(seq) and isinstance(seq[i + 1], CPop) and \
                        isinstance(seq[i + 1].dst, CReg) and seq[i + 1].dst.name == 'rbp':
                    remove.add((blk.address, i + 1))

    base = frame
    func.uses_frame = bool(frame)
    func.frame_base = base
    func.frame_size = rsp_adjust

    def stack_name(disp, size, pointer=False):
        if disp == 0:
            return None
        if base == 'rbp':
            return None
        if disp < 0:
            name = f'var_{abs(disp):X}'
        elif base == 'rsp':
            # rsp-relative frame: every slot is a local of the current frame
            name = f'var_{disp:X}'
        elif func_target_is64(func):
            if disp < 0x28:
                return None          # return address, shadow space, saved regs
            name = f'arg_{disp:X}'
        else:
            if disp < 8:
                return None          # return address
            name = f'arg_{disp:X}'
        func.locals[name] = max(func.locals.get(name, 0), 8 if pointer else size)
        return name

    def rewrite(e):
        if isinstance(e, CDeref):
            addr = _map_expr(e.addr, rewrite)
            if base:
                disp = _stack_disp(addr, base)
                if disp is not None and abs(disp) < 0x100000:
                    name = stack_name(disp, e.size)
                    if name:
                        return CVar(name, e.size)
            return CDeref(addr, e.size)
        if isinstance(e, CAddr):
            inner = _map_expr(e.expr, rewrite)
            if base:
                disp = _stack_disp(inner, base)
                if disp is not None and abs(disp) < 0x100000:
                    name = stack_name(disp, 8, pointer=True)
                    if name:
                        return CAddr(CVar(name, 8))
            return CAddr(inner)
        return e

    for blk in func.blocks.values():
        new_stmts = []
        for i, s in enumerate(blk.stmts):
            if (blk.address, i) in remove or (blk is entry and i in remove):
                continue
            if isinstance(s, CPush) and isinstance(s.value, CReg) and \
                    s.value.name in _CALLEE_SAVED:
                nxt = blk.stmts[i + 1] if i + 1 < len(blk.stmts) else None
                if not isinstance(nxt, CCallStmt):
                    continue
            if isinstance(s, CPop) and isinstance(s.dst, CReg) and s.dst.name in _CALLEE_SAVED:
                continue
            new_stmts.append(_map_stmt(s, rewrite))
        blk.stmts = new_stmts
        if blk.term is not None:
            blk.term = _map_stmt(blk.term, rewrite)

    # drop unused locals that were only touched by removed prologue code
    used = set()
    for blk in func.blocks.values():
        for s in blk.stmts + ([blk.term] if blk.term else []):
            used |= stmt_uses(s)
            used |= stmt_defs(s)
    for name in list(func.locals):
        if name not in used:
            del func.locals[name]


def _rbp_const_from(src):
    inner = src.expr if isinstance(src, CAddr) else src
    if isinstance(inner, CReg) and inner.name == 'rsp':
        return 0
    if (isinstance(inner, CBin) and isinstance(inner.a, CReg)
            and inner.a.name == 'rsp' and isinstance(inner.b, CConst)):
        value = _const_signed(inner.b)
        return value if inner.op == '+' else -value
    return 0


def _rsp_deltas(func):
    in_state = {func.entry: 0}
    work = deque([func.entry])
    deltas = {}
    while work:
        addr = work.popleft()
        blk = func.blocks.get(addr)
        if blk is None:
            continue
        d = in_state.get(addr)
        per = []
        for s in blk.stmts:
            per.append(d)
            if d is None:
                continue
            if isinstance(s, CSet) and isinstance(s.dst, CReg) and s.dst.name == 'rsp':
                if (isinstance(s.src, CBin) and isinstance(s.src.a, CReg)
                        and s.src.a.name == 'rsp' and isinstance(s.src.b, CConst)
                        and s.src.op in ('+', '-')):
                    value = _const_signed(s.src.b)
                    d = d + value if s.src.op == '+' else d - value
                else:
                    d = None
            elif isinstance(s, CPush):
                d -= 8
            elif isinstance(s, CPop):
                d += 8
        deltas[addr] = (per, d)
        for succ in blk.succ:
            if succ not in func.blocks:
                continue
            old = in_state.get(succ, 'unset')
            if old == 'unset':
                in_state[succ] = d
                work.append(succ)
            elif old != d and old is not None:
                in_state[succ] = None
                work.append(succ)
    return deltas


def pass_rsp_frame(func):
    deltas = _rsp_deltas(func)
    frame = func.uses_frame
    anchor = 0
    anchor_known = not frame
    if frame:
        entry_per, _ = deltas.get(func.entry, ([], 0))
        c = getattr(func, 'rbp_const', 0)
        d_def = None
        for i, s in enumerate(func.blocks[func.entry].stmts):
            if (isinstance(s, CSet) and isinstance(s.dst, CReg)
                    and s.dst.name == 'rbp'):
                if i < len(entry_per):
                    d_def = entry_per[i]
                break
        if d_def is None:
            d_def = -8 if c == 0 else 0
        anchor = d_def + c
        anchor_known = d_def is not None

    def rel_name(rel, size, pointer=False):
        if rel < 0:
            name = f'var_{-rel:X}'
        elif rel >= 0x28:
            name = f'arg_{rel:X}'
        else:
            return None
        func.locals[name] = max(func.locals.get(name, 0), 8 if pointer else size)
        return name

    def rel_of(addr, d):
        k = _stack_disp(addr, 'rsp')
        if k is not None:
            return None if d is None else d + k
        if frame and anchor_known:
            k = _stack_disp(addr, 'rbp')
            if k is not None:
                return anchor + k
        return None

    def rewrite(e, d):
        if isinstance(e, CDeref):
            rel = rel_of(e.addr, d)
            if rel is not None:
                name = rel_name(rel, e.size)
                if name:
                    return CVar(name, e.size)
            return e
        if isinstance(e, CAddr):
            rel = rel_of(e.expr, d)
            if rel is not None:
                name = rel_name(rel, 8, pointer=True)
                if name:
                    return CAddr(CVar(name, 8))
            return e
        return e

    for blk in func.blocks.values():
        per, end_delta = deltas.get(blk.address, ([], None))
        new_stmts = []
        for i, s in enumerate(blk.stmts):
            d = per[i] if i < len(per) else end_delta
            if isinstance(s, CPush) or isinstance(s, CPop):
                continue
            if isinstance(s, CSet) and isinstance(s.dst, CReg) and \
                    s.dst.name in ('rsp', 'rbp'):
                continue
            if isinstance(s, CSet) and isinstance(s.dst, CDeref):
                rel = rel_of(s.dst.addr, d)
                if rel is not None and 0 <= rel < 0x28:
                    continue          # saved return address
            new_stmts.append(_map_stmt(s, lambda x, dd=d: rewrite(x, dd)))
        blk.stmts = new_stmts
        if blk.term is not None:
            blk.term = _map_stmt(blk.term, lambda x, dd=end_delta: rewrite(x, dd))

    used = set()
    for blk in func.blocks.values():
        for s in blk.stmts + ([blk.term] if blk.term else []):
            used |= stmt_uses(s)
            used |= stmt_defs(s)
    for name in list(func.locals):
        if name not in used:
            del func.locals[name]


def pass_security(func):
    def is_cookie_expr(e):
        return isinstance(e, CBin) and e.op == '^' and expr_uses(e, {'rsp'})

    for blk in func.blocks.values():
        new_stmts = []
        for s in blk.stmts:
            if isinstance(s, CSet) and is_cookie_expr(s.src):
                continue
            if isinstance(s, CCallStmt):
                name = (s.call.name or '').lower()
                if 'security_check_cookie' in name or 'stack_chk' in name:
                    continue
                if any(is_cookie_expr(arg) or expr_uses(arg, {'rsp'})
                       for arg in s.call.args):
                    continue
            new_stmts.append(s)
        blk.stmts = new_stmts


def _incoming_names(func):
    use_before = {}
    defs = {}
    for addr, blk in func.blocks.items():
        u = set()
        d = set()
        for stmt in reversed(list(blk.stmts) + ([blk.term] if blk.term else [])):
            for name in stmt_uses(stmt):
                if name not in d:
                    u.add(name)
            d |= stmt_defs(stmt)
        use_before[addr] = u
        defs[addr] = d
    reach = {addr: set(u) for addr, u in use_before.items()}
    changed = True
    while changed:
        changed = False
        for addr, blk in func.blocks.items():
            if addr == func.entry:
                continue
            new = set(use_before[addr])
            for pred in blk.pred:
                if pred in reach:
                    new |= use_before[pred] | (reach[pred] - defs[pred])
            if new != reach[addr]:
                reach[addr] = new
                changed = True
    incoming = set()
    for names in reach.values():
        incoming |= names
    return incoming


def pass_abi(func, is64=True, is_pe=True):
    if is64:
        argmap = OrderedDict([('rcx', 'a1'), ('rdx', 'a2'), ('r8', 'a3'), ('r9', 'a4')])
    else:
        argmap = OrderedDict([('ecx', 'a1'), ('edx', 'a2')])

    mapping = {reg: CVar(name, 8) for reg, name in argmap.items()}
    incoming = _incoming_names(func)
    stack_args = sorted([n for n in func.locals if n.startswith('arg_')],
                        key=lambda n: int(n.split('_')[1], 16))
    next_index = len(argmap) + 1
    for name in stack_args:
        disp = int(name.split('_')[1], 16)
        if is64 and disp < 0x28:
            func.locals.pop(name, None)
            continue
        if not is64 and disp < 8:
            func.locals.pop(name, None)
            continue
        if name not in incoming:
            new_name = f'out_{disp:X}'
            mapping[name] = CVar(new_name, 8)
            func.locals[new_name] = func.locals.pop(name, 8)
            continue
        new_name = f'a{next_index}'
        next_index += 1
        mapping[name] = CVar(new_name, 8)
        func.locals.pop(name, None)

    def rename(e):
        if isinstance(e, (CReg, CVar)) and e.name in mapping:
            return mapping[e.name]
        return e

    for blk in func.blocks.values():
        blk.stmts = [_map_stmt(s, rename) for s in blk.stmts]
        if blk.term is not None:
            blk.term = _map_stmt(blk.term, rename)

    used = set()
    for blk in func.blocks.values():
        for s in blk.stmts + ([blk.term] if blk.term else []):
            used |= stmt_uses(s)
            used |= stmt_defs(s)

    indices = sorted(int(n[1:]) for n in used
                     if n and n[0] == 'a' and n[1:].isdigit())
    arg_vars = OrderedDict()
    if indices:
        for i in range(1, indices[-1] + 1):
            arg_vars[f'a{i}'] = 8
    func.arg_vars = arg_vars

    for blk in func.blocks.values():
        seq = blk.stmts
        for i in range(len(seq) - 1):
            a, b = seq[i], seq[i + 1]
            if not (isinstance(b, CRet) and isinstance(b.value, CReg)
                    and b.value.name == 'rax'):
                continue
            if (isinstance(a, CSet) and isinstance(a.dst, CReg)
                    and a.dst.name == 'rax'):
                seq[i] = CComment('')  # placeholder, stripped below
                seq[i + 1] = CRet(a.src)
            elif (isinstance(a, CCallStmt) and isinstance(a.dst, CReg)
                  and a.dst.name == 'rax'):
                seq[i] = CComment('')
                seq[i + 1] = CRet(a.call)
        blk.stmts = [s for s in seq if not (isinstance(s, CComment) and s.text == '')]
        if blk.term is not None and isinstance(blk.term, CRet) and \
                isinstance(blk.term.value, CReg) and blk.term.value.name == 'rax' and blk.stmts:
            last = blk.stmts[-1]
            if isinstance(last, CSet) and isinstance(last.dst, CReg) and last.dst.name == 'rax':
                blk.term = CRet(last.src)
                blk.stmts.pop()
            elif isinstance(last, CCallStmt) and isinstance(last.dst, CReg) and last.dst.name == 'rax':
                blk.term = CRet(last.call)
                blk.stmts.pop()

    rets = []
    for blk in func.blocks.values():
        for s in blk.stmts + ([blk.term] if blk.term else []):
            if isinstance(s, CRet):
                rets.append(s)
    if rets:
        func.ret_void = all(r.value is None for r in rets)
        sizes = {r.value.size for r in rets if r.value is not None}
        func.ret_size = 4 if sizes == {4} else 8
    else:
        func.ret_void = False
        func.ret_size = 8


def _walk_expr(expr):
    if expr is None:
        return
    yield expr
    if isinstance(expr, CBin):
        yield from _walk_expr(expr.a)
        yield from _walk_expr(expr.b)
    elif isinstance(expr, CUn):
        yield from _walk_expr(expr.a)
    elif isinstance(expr, CCast):
        yield from _walk_expr(expr.expr)
    elif isinstance(expr, CDeref):
        yield from _walk_expr(expr.addr)
    elif isinstance(expr, CAddr):
        yield from _walk_expr(expr.expr)
    elif isinstance(expr, CCmp):
        yield from _walk_expr(expr.a)
        yield from _walk_expr(expr.b)
    elif isinstance(expr, CCall):
        for arg in expr.args:
            yield from _walk_expr(arg)


def _stmt_exprs(stmt):
    if isinstance(stmt, CSet):
        yield from _walk_expr(stmt.src)
        yield from _walk_expr(stmt.dst)
    elif isinstance(stmt, CBranch):
        yield from _walk_expr(stmt.cond)
    elif isinstance(stmt, CRet) and stmt.value is not None:
        yield from _walk_expr(stmt.value)
    elif isinstance(stmt, CCallStmt):
        for arg in stmt.call.args:
            yield from _walk_expr(arg)
    elif isinstance(stmt, CPush):
        yield from _walk_expr(stmt.value)
    elif isinstance(stmt, CJumpIndirect):
        yield from _walk_expr(stmt.value)
    elif isinstance(stmt, CSwitch):
        yield from _walk_expr(stmt.value)


def pass_peephole(func):
    uses_rsp_mem = False
    for blk in func.blocks.values():
        for stmt in blk.stmts + ([blk.term] if blk.term else []):
            for expr in _stmt_exprs(stmt):
                if isinstance(expr, CDeref) and expr_uses(expr.addr, {'rsp'}):
                    uses_rsp_mem = True
                    break
    for blk in func.blocks.values():
        new_stmts = []
        for s in blk.stmts:
            s = _map_stmt(s, simplify)
            if isinstance(s, CSet) and _expr_key(s.dst) == _expr_key(s.src):
                continue
            if isinstance(s, CSet) and isinstance(s.dst, CReg) and \
                    s.dst.name in ('rsp', 'rbp'):
                continue
            new_stmts.append(s)
        blk.stmts = new_stmts
        if blk.term is not None:
            blk.term = _map_stmt(blk.term, simplify)


def _simple_value(e):
    return isinstance(e, (CConst, CReg, CVar, CAddr))


def pass_copy_prop(func):
    entry = func.blocks.get(func.entry)
    global_map = {}
    if entry is not None:
        writes = Counter()
        for blk in func.blocks.values():
            for s in blk.stmts:
                if isinstance(s, CSet) and isinstance(s.dst, CVar):
                    writes[s.dst.name] += 1
        for s in entry.stmts:
            if (isinstance(s, CSet) and isinstance(s.dst, CVar)
                    and isinstance(s.src, (CConst, CReg, CVar))
                    and writes[s.dst.name] == 1):
                global_map[s.dst.name] = s.src

    for blk in func.blocks.values():
        env = dict(global_map)
        new_stmts = []
        for s in blk.stmts:
            s = _subst_reads(s, env)
            new_stmts.append(s)
            if isinstance(s, CSet) and isinstance(s.dst, (CReg, CVar)):
                name = s.dst.name
                if name in ('rsp', 'rbp'):
                    env.pop(name, None)
                elif _simple_value(s.src) and name not in global_map:
                    env[name] = s.src
                else:
                    env.pop(name, None)
            elif isinstance(s, CCallStmt):
                env = dict(global_map)
        blk.stmts = new_stmts
        if blk.term is not None:
            blk.term = _subst_reads(blk.term, env)


def _block_live_sets(func):
    use = {}
    defs = {}
    for addr, blk in func.blocks.items():
        all_stmts = list(blk.stmts)
        if blk.term is not None:
            all_stmts.append(blk.term)
        u = set()
        d = set()
        for stmt in all_stmts:
            for name in stmt_uses(stmt):
                if name not in d:
                    u.add(name)
            d |= stmt_defs(stmt)
        use[addr] = u
        defs[addr] = d
    return use, defs


def pass_dce(func):
    use, defs = _block_live_sets(func)
    live_in = {a: set(u) for a, u in use.items()}
    live_out = {a: set() for a in func.blocks}
    changed = True
    while changed:
        changed = False
        for addr, blk in func.blocks.items():
            out = set()
            for succ in blk.succ:
                if succ in live_in:
                    out |= live_in[succ]
            new_in = use[addr] | (out - defs[addr])
            if out != live_out[addr] or new_in != live_in[addr]:
                live_out[addr] = out
                live_in[addr] = new_in
                changed = True

    keep = {'rsp', 'rbp'}
    for addr, blk in func.blocks.items():
        live = set(live_out[addr])
        if blk.term is not None:
            live |= stmt_uses(blk.term)
        new_stmts = []
        for stmt in reversed(blk.stmts):
            remove = False
            if isinstance(stmt, CSet) and isinstance(stmt.dst, (CReg, CVar)):
                name = stmt.dst.name
                if name not in live and name not in keep:
                    remove = True
            if not remove:
                new_stmts.append(stmt)
                live -= stmt_defs(stmt)
                live |= stmt_uses(stmt)
        blk.stmts = list(reversed(new_stmts))


def pass_thread(func):
    for blk in func.blocks.values():
        term = blk.term
        if isinstance(term, CJump):
            target = term.target
            seen = set()
            while (target in func.blocks and target not in seen
                   and not func.blocks[target].stmts
                   and isinstance(func.blocks[target].term, CJump)):
                seen.add(target)
                target = func.blocks[target].term.target
            if target in func.blocks and target != term.target:
                blk.term = CJump(target)
    # rebuild succ/pred
    for blk in func.blocks.values():
        blk.succ = []
    for blk in func.blocks.values():
        t = blk.term
        if isinstance(t, CJump):
            blk.succ = [t.target]
        elif isinstance(t, CBranch):
            blk.succ = [t.t] + ([t.f] if t.f is not None else [])
        elif isinstance(t, CSwitch):
            blk.succ = list(t.cases.values()) + ([t.default] if t.default is not None else [])
        elif isinstance(t, CRet) or isinstance(t, CJumpIndirect):
            blk.succ = []
        else:
            blk.succ = [blk.fallthrough] if blk.fallthrough is not None else []
        blk.succ = [s for s in dict.fromkeys(blk.succ) if s in func.blocks]
    for blk in func.blocks.values():
        blk.pred = []
    for blk in func.blocks.values():
        for s in blk.succ:
            func.blocks[s].pred.append(blk.address)


def pass_types(func):
    func.pointer_args = {}
    for blk in func.blocks.values():
        for s in blk.stmts + ([blk.term] if blk.term else []):
            kind = None
            size = None
            if isinstance(s, CSet) and isinstance(s.dst, CDeref):
                kind = s.dst.addr
                size = s.dst.size
            elif isinstance(s, CSet) and isinstance(s.src, CDeref):
                kind = s.src.addr
                size = s.src.size
            if kind is None:
                continue
            root = _pointer_root(kind)
            if root in func.arg_vars:
                current = func.pointer_args.get(root, 0)
                if size > current or current == 0:
                    func.pointer_args[root] = size



# Structure recovery

class CNode:
    __slots__ = ()


class NBlock(CNode):
    __slots__ = ('addr', 'stmts')

    def __init__(self, addr, stmts):
        self.addr = addr
        self.stmts = stmts


class NSeq(CNode):
    __slots__ = ('nodes',)

    def __init__(self, nodes=None):
        self.nodes = nodes if nodes is not None else []


class NIf(CNode):
    __slots__ = ('cond', 'then', 'els')

    def __init__(self, cond, then, els):
        self.cond = cond
        self.then = then
        self.els = els


class NWhile(CNode):
    __slots__ = ('cond', 'body', 'do_while')

    def __init__(self, cond, body, do_while=False):
        self.cond = cond
        self.body = body
        self.do_while = do_while


class NSwitch(CNode):
    __slots__ = ('value', 'cases', 'default')

    def __init__(self, value, cases, default):
        self.value = value
        self.cases = cases
        self.default = default


class NBreak(CNode):
    __slots__ = ()


class NContinue(CNode):
    __slots__ = ()


class NGoto(CNode):
    __slots__ = ('target',)

    def __init__(self, target):
        self.target = target


def _negate_cond(e):
    if isinstance(e, CCmp):
        inverse = {'==': '!=', '!=': '==', '<': '>=', '>=': '<', '>': '<=', '<=': '>'}
        op = inverse.get(e.op)
        if op:
            return CCmp(op, e.a, e.b, e.unsigned, e.size)
        return CUn('!', e, 1)
    if isinstance(e, CConst):
        return CConst(0 if e.value else 1, 1)
    if isinstance(e, CUn) and e.op == '!':
        return e.a
    return CUn('!', e, 1)


class CStructurer:
    # Recovers if/else, while, do-while and switch from the CFG.

    MAX_DEPTH = 48

    def __init__(self, func):
        self.func = func
        self.blocks = func.blocks
        self.entry = func.entry
        self.order = []
        self.dom = {}
        self.pdom = {}
        self.ipdom = {}
        self.loops = {}
        self.latches = {}
        self.loop_done = set()
        self.emitted = set()
        self.labels = set()
        self.failed = False
        self._compute_order()
        self._compute_dominators()
        self._compute_postdominators()
        self._find_loops()

    # graph algorithms

    def _compute_order(self):
        seen = set()
        post = []
        stack = [self.entry]
        while stack:
            block = stack[-1]
            if block in seen:
                stack.pop()
                post.append(block)
                continue
            seen.add(block)
            for succ in self.blocks[block].succ:
                if succ not in seen:
                    stack.append(succ)
        post.reverse()
        self.order = [a for a in post if a in self.blocks]

    def _compute_dominators(self):
        universe = set(self.blocks)
        dom = {a: set(universe) for a in universe}
        dom[self.entry] = {self.entry}
        changed = True
        while changed:
            changed = False
            for addr in self.order:
                if addr == self.entry:
                    continue
                preds = self.blocks[addr].pred
                if preds:
                    new = set(dom[preds[0]])
                    for p in preds[1:]:
                        new &= dom[p]
                else:
                    new = set()
                new.add(addr)
                if new != dom[addr]:
                    dom[addr] = new
                    changed = True
        self.dom = dom

    def _compute_postdominators(self):
        exit_marker = -1
        universe = set(self.blocks)
        universe.add(exit_marker)
        succs = {}
        for addr in self.blocks:
            succs[addr] = list(self.blocks[addr].succ) or [exit_marker]
        succs[exit_marker] = []
        pdom = {a: set(universe) for a in universe}
        pdom[exit_marker] = {exit_marker}
        changed = True
        while changed:
            changed = False
            for addr in reversed(self.order):
                new = set(universe)
                for s in succs[addr]:
                    new &= pdom[s]
                new.add(addr)
                if new != pdom[addr]:
                    pdom[addr] = new
                    changed = True
        self.pdom = pdom
        for addr in self.blocks:
            strict = [c for c in pdom[addr] if c != addr and c != exit_marker]
            if not strict:
                self.ipdom[addr] = None
                continue
            best = max(strict, key=lambda c: len(pdom[c]))
            self.ipdom[addr] = best

    def _find_loops(self):
        for addr in self.order:
            for succ in self.blocks[addr].succ:
                if succ in self.dom.get(addr, ()):
                    header = succ
                    body = {header}
                    work = [addr]
                    while work:
                        block = work.pop()
                        if block in body:
                            continue
                        body.add(block)
                        for p in self.blocks[block].pred:
                            work.append(p)
                    self.loops.setdefault(header, set()).update(body)
                    self.latches.setdefault(header, [])
                    if addr not in self.latches[header]:
                        self.latches[header].append(addr)

    # helpers

    def _exit_node(self, addr, exits):
        action = exits.get(addr, 'goto')
        if action == 'fall':
            return None
        if action == 'break':
            return NBreak()
        if action == 'continue':
            return NContinue()
        self.labels.add(addr)
        return NGoto(addr)

    def _can_struct_if(self, addr, then_block, else_block, exits):
        if then_block is None or else_block is None:
            return False
        if then_block == else_block:
            return False
        if then_block not in self.blocks or else_block not in self.blocks:
            return False
        if then_block in exits or else_block in exits:
            return False
        if then_block in self.emitted or else_block in self.emitted:
            return False
        merge = self.ipdom.get(addr)
        if merge is None:
            return self._terminal_block(then_block) and self._terminal_block(else_block)
        if merge not in self.blocks:
            return False
        if merge in self.emitted:
            return False
        if merge not in self.pdom.get(then_block, ()):
            return False
        if merge not in self.pdom.get(else_block, ()):
            return False
        return True

    def _terminal_block(self, addr, depth=0):
        if depth > 8 or addr not in self.blocks:
            return False
        term = self.blocks[addr].term
        if isinstance(term, (CRet, CJumpIndirect)):
            return True
        return False

    # loop emission

    def emit_loop(self, header, exits, depth):
        self.loop_done.add(header)
        self.emitted.add(header)
        body = self.loops.get(header, {header})
        blk = self.blocks[header]
        term = blk.term
        loop_exits = set()
        for block in body:
            for succ in self.blocks[block].succ:
                if succ not in body:
                    loop_exits.add(succ)

        # self-loop: single block ending with a conditional jump to itself
        if len(body) == 1 and isinstance(term, CBranch) and header in (term.t, term.f):
            other = term.f if term.t == header else term.t
            cond = term.cond if term.t == header else _negate_cond(term.cond)
            body_nodes = [NBlock(header, list(blk.stmts))]
            after = other
            if other is not None:
                loop_exits.discard(other)
            for e in loop_exits:
                new_exits = dict(exits)
                new_exits[e] = 'goto'
            return NWhile(cond, body_nodes, True), after

        # do-while: header has no condition, a single latch tests at the bottom
        latches = self.latches.get(header, [])
        if not isinstance(term, CBranch) and len(latches) == 1 and blk.stmts:
            latch = latches[0]
            latch_term = self.blocks[latch].term
            if (isinstance(latch_term, CBranch) and latch_term.f is not None
                    and header in (latch_term.t, latch_term.f)):
                new_exits = dict(exits)
                new_exits[header] = 'continue'
                other = latch_term.f if latch_term.t == header else latch_term.t
                if other is not None:
                    new_exits[other] = 'break'
                else:
                    return None, None
                for e in loop_exits:
                    if e != other:
                        new_exits.setdefault(e, 'goto')
                body_nodes = [NBlock(header, list(blk.stmts))]
                start = blk.fallthrough
                if start is not None and start != header:
                    body_nodes.extend(self.emit_from(start, new_exits, depth + 1))
                cond = latch_term.cond if latch_term.t == header else _negate_cond(latch_term.cond)
                return NWhile(cond, body_nodes, True), other

        # while loop with the test at the top
        if isinstance(term, CBranch) and term.f is not None:
            t_in = term.t in body
            f_in = term.f in body
            if t_in != f_in:
                primary = term.f if t_in else term.t
                cond = term.cond if t_in else _negate_cond(term.cond)
                body_start = term.t if t_in else term.f
                new_exits = dict(exits)
                new_exits[header] = 'continue'
                new_exits[primary] = 'break'
                for e in loop_exits:
                    new_exits.setdefault(e, 'goto')
                if not blk.stmts:
                    body_nodes = self.emit_from(body_start, new_exits, depth + 1)
                    return NWhile(cond, body_nodes, False), primary
                body_nodes = [NBlock(header, list(blk.stmts)),
                              NIf(_negate_cond(cond), [NBreak()], [])]
                body_nodes.extend(self.emit_from(body_start, new_exits, depth + 1))
                return NWhile(None, body_nodes, False), primary

        # generic infinite loop
        primary = None
        if loop_exits:
            primary = sorted(loop_exits)[0]
        new_exits = dict(exits)
        new_exits[header] = 'continue'
        if primary is not None:
            new_exits[primary] = 'break'
        for e in loop_exits:
            new_exits.setdefault(e, 'goto')
        body_nodes = [NBlock(header, list(blk.stmts))]
        start = blk.fallthrough
        if start is not None and start != header:
            body_nodes.extend(self.emit_from(start, new_exits, depth + 1))
        return NWhile(None, body_nodes, False), primary

    # switch emission

    def _fix_switch_tail(self, body, next_case, merge, exits):
        if not body:
            return body
        last = body[-1]
        if isinstance(last, NGoto):
            if next_case is not None and last.target == next_case:
                return body[:-1]
            if merge is not None and last.target == merge:
                return body[:-1] + [NBreak()]
            return body
        if isinstance(last, NIf) and not last.els and len(last.then) == 1:
            inner = last.then[0]
            if isinstance(inner, NGoto) and merge is not None and inner.target == merge:
                last.then = [NBreak()]
                return body
            if isinstance(inner, NGoto) and next_case is not None and inner.target == next_case:
                return body[:-1]
        return body

    def emit_switch(self, addr, exits, depth):
        blk = self.blocks[addr]
        term = blk.term
        merge = self.ipdom.get(addr)
        new_exits = dict(exits)
        if merge is not None and merge in self.blocks and merge not in self.emitted:
            new_exits[merge] = 'break'
        targets = list(term.cases.values()) + ([term.default] if term.default is not None else [])
        for t in targets:
            new_exits.setdefault(t, 'goto')

        case_nodes = []
        for value, target in term.cases.items():
            if target not in self.blocks:
                case_nodes.append((value, [NGoto(target)], target))
                continue
            if target in self.emitted:
                self.labels.add(target)
                case_nodes.append((value, [NGoto(target)], target))
                continue
            body = self.emit_from(target, new_exits, depth + 1)
            case_nodes.append((value, body, target))

        default_body = None
        if term.default is not None:
            if term.default in self.blocks and term.default not in self.emitted:
                default_body = self.emit_from(term.default, new_exits, depth + 1)
            else:
                self.labels.add(term.default)
                default_body = [NGoto(term.default)]

        fixed = []
        for i, (value, body, target) in enumerate(case_nodes):
            next_case = case_nodes[i + 1][2] if i + 1 < len(case_nodes) else None
            fixed.append((value, self._fix_switch_tail(body, next_case, merge, exits)))
        if default_body is not None:
            default_body = self._fix_switch_tail(default_body, None, merge, exits)

        after = merge if (merge is not None and merge in self.blocks
                          and merge not in self.emitted) else None
        return NSwitch(term.value, fixed, default_body), after

    # main emission

    def emit_from(self, start, exits, depth):
        out = []
        if depth > self.MAX_DEPTH:
            return self.flat_region(start, exits)
        cur = start
        steps = 0
        while cur is not None:
            steps += 1
            if steps > 100000:
                self.failed = True
                return out
            if cur in exits:
                node = self._exit_node(cur, exits)
                if node is not None:
                    out.append(node)
                return out
            if cur not in self.blocks:
                return out
            if cur in self.emitted:
                self.labels.add(cur)
                out.append(NGoto(cur))
                return out
            if cur in self.loops and cur not in self.loop_done:
                node, after = self.emit_loop(cur, exits, depth)
                if node is not None:
                    out.append(node)
                if after is None:
                    return out
                cur = after
                continue

            blk = self.blocks[cur]
            self.emitted.add(cur)
            out.append(NBlock(cur, list(blk.stmts)))
            term = blk.term

            if term is None:
                cur = blk.fallthrough
                continue
            if isinstance(term, CRet):
                out.append(NBlock(cur, [term]))
                return out
            if isinstance(term, CJumpIndirect):
                out.append(NBlock(cur, [term]))
                return out
            if isinstance(term, CSwitch):
                node, after = self.emit_switch(cur, exits, depth)
                out.append(node)
                if after is None:
                    return out
                cur = after
                continue
            if isinstance(term, CJump):
                target = term.target
                if target in exits:
                    node = self._exit_node(target, exits)
                    if node is not None:
                        out.append(node)
                    return out
                if target not in self.blocks or target in self.emitted:
                    self.labels.add(target)
                    out.append(NGoto(target))
                    return out
                cur = target
                continue
            if isinstance(term, CBranch):
                then_block = term.t
                else_block = term.f if term.f is not None else blk.fallthrough
                if self._can_struct_if(cur, then_block, else_block, exits):
                    merge = self.ipdom.get(cur)
                    new_exits = dict(exits)
                    if merge is not None:
                        new_exits[merge] = 'fall'
                    then_nodes = self.emit_from(then_block, new_exits, depth + 1)
                    else_nodes = self.emit_from(else_block, new_exits, depth + 1)
                    out.append(NIf(term.cond, then_nodes, else_nodes))
                    if merge is None:
                        return out
                    cur = merge
                    continue
                node = self._exit_node(then_block, exits)
                out.append(NIf(term.cond, [node] if node is not None else [], []))
                if else_block is None:
                    return out
                if else_block in exits:
                    node = self._exit_node(else_block, exits)
                    if node is not None:
                        out.append(node)
                    return out
                if else_block not in self.blocks or else_block in self.emitted:
                    self.labels.add(else_block)
                    out.append(NGoto(else_block))
                    return out
                cur = else_block
                continue
        return out

    def flat_region(self, start, exits):
        out = []
        cur = start
        steps = 0
        while cur is not None and steps < len(self.blocks) + 8:
            steps += 1
            if cur in exits or cur not in self.blocks:
                if cur in exits:
                    node = self._exit_node(cur, exits)
                    if node is not None:
                        out.append(node)
                return out
            if cur in self.emitted:
                self.labels.add(cur)
                out.append(NGoto(cur))
                return out
            self.emitted.add(cur)
            blk = self.blocks[cur]
            out.append(NBlock(cur, list(blk.stmts) + ([blk.term] if blk.term else [])))
            term = blk.term
            if term is None:
                cur = blk.fallthrough
            elif isinstance(term, CJump):
                cur = None
                if term.target in self.blocks:
                    self.labels.add(term.target)
                    out.append(NGoto(term.target))
            else:
                cur = None
        return out

    def flat_all(self):
        nodes = []
        for addr in self.blocks:
            self.labels.add(addr)
            blk = self.blocks[addr]
            nodes.append(NBlock(addr, list(blk.stmts) + ([blk.term] if blk.term else [])))
        return NSeq(nodes)

    def build(self):
        nodes = []
        try:
            nodes.extend(self.emit_from(self.entry, {}, 0))
            guard = 0
            while guard <= len(self.blocks):
                guard += 1
                rest = [a for a in self.blocks if a not in self.emitted]
                if not rest:
                    break
                self.labels.add(rest[0])
                nodes.extend(self.emit_from(rest[0], {}, 0))
        except Exception:
            self.failed = True
        if any(a not in self.emitted for a in self.blocks):
            self.failed = True
            return self.flat_all()
        return NSeq(nodes)


# Printer

_MEM_PREFIX = {1: 'byte', 2: 'word', 4: 'dword', 8: 'qword', 16: 'xmmword'}


def _sorted_locals(locals_dict):
    """Sort locals by kind and stack offset (var_8, var_10, ..., arg_28)."""
    def key(item):
        name = item[0]
        prefix, _, suffix = name.partition('_')
        try:
            value = int(suffix, 16)
        except ValueError:
            value = 0
        order = {'var': 0, 'out': 1, 'arg': 2}.get(prefix, 3)
        return (order, value, name)
    return sorted(locals_dict.items(), key=key)


class CPrinter:
    def __init__(self, func, labels, strings=None):
        self.func = func
        self.labels = labels
        self.strings = strings or {}
        self.lines = []
        self.indent = 1
        self.data_refs = OrderedDict()
        self.used_labels = set()
        self.printed_labels = set()

    # small helpers

    def _line(self, text=''):
        self.lines.append('    ' * self.indent + text if text else '')

    def _c_string(self, text):
        out = []
        for ch in text:
            if ch == '"':
                out.append('\\"')
            elif ch == '\\':
                out.append('\\\\')
            elif ch == '\n':
                out.append('\\n')
            elif ch == '\r':
                out.append('\\r')
            elif ch == '\t':
                out.append('\\t')
            elif 32 <= ord(ch) < 127:
                out.append(ch)
            else:
                out.append('\\x%02x' % (ord(ch) & 0xFF))
        return '"' + ''.join(out) + '"'

    def _data_name(self, va, size):
        if size not in _MEM_PREFIX:
            size = 8
        name = f'{_MEM_PREFIX[size]}_{va:X}'
        if name not in self.data_refs:
            self.data_refs[name] = size
        return name

    def _atom(self, expr):
        if isinstance(expr, (CConst, CReg, CVar, CString, CCall, CFlag)):
            return self._expr(expr)
        if isinstance(expr, CDeref):
            return self._expr(expr)
        return '(' + self._expr(expr) + ')'

    def _cast(self, expr, size, signed=False):
        return f'({_c_type(size, signed)}){self._atom(expr)}'

    # expressions

    def _cond_text(self, expr):
        text = self._expr(expr)
        if text.startswith('(') and text.endswith(')'):
            depth = 0
            for i, ch in enumerate(text):
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
                    if depth == 0:
                        if i == len(text) - 1:
                            return text[1:-1]
                        break
        return text

    def _expr(self, e):
        if e is None:
            return '0'
        if isinstance(e, CConst):
            value = e.value
            if value < 0:
                return f'-0x{-value:X}'
            if value == _mask_for(e.size) and e.size >= 8:
                return '-1'
            if value > 9:
                return f'0x{value:X}'
            return str(value)
        if isinstance(e, CString):
            return self._c_string(e.value)
        if isinstance(e, CReg):
            return reg_print(e.name, e.size)
        if isinstance(e, CVar):
            return e.name
        if isinstance(e, CFlag):
            return e.name
        if isinstance(e, CAddr):
            inner = e.expr
            if isinstance(inner, CConst):
                if inner.value in self.strings:
                    return f'(char *){self._c_string(self.strings[inner.value])}'
                return '&' + self._data_name(inner.value, 8)
            if isinstance(inner, CVar):
                return '&' + inner.name
            return self._expr(inner)
        if isinstance(e, CDeref):
            addr = e.addr
            if isinstance(addr, CConst):
                if addr.value in self.strings and e.size == 1:
                    return self._c_string(self.strings[addr.value])
                return self._data_name(addr.value, e.size)
            if isinstance(addr, CVar):
                return f'*({_c_type(e.size, False)} *){addr.name}'
            return f'*({_c_type(e.size, False)} *){self._atom(addr)}'
        if isinstance(e, CBin):
            return f'({self._expr(e.a)} {e.op} {self._expr(e.b)})'
        if isinstance(e, CUn):
            if e.op == '!':
                return f'!{self._atom(e.a)}'
            return f'({e.op}{self._atom(e.a)})'
        if isinstance(e, CCast):
            return self._cast(e.expr, e.size, e.signed)
        if isinstance(e, CCmp):
            op = e.op
            left = self._expr(e.a)
            right = self._expr(e.b)
            if e.unsigned and e.size < 8:
                left = self._cast(e.a, e.size, False)
                right = self._cast(e.b, e.size, False)
            return f'({left} {op} {right})'
        if isinstance(e, CCall):
            args = ', '.join(self._expr(a) for a in e.args)
            return f'{e.name}({args})'
        if isinstance(e, _Conditional):
            return f'({self._expr(e.cond)} ? {self._expr(e.a)} : {self._expr(e.b)})'
        return '/* ? */0'

    # statements

    def _lvalue(self, e):
        if isinstance(e, CDeref):
            return self._expr(e)
        return self._expr(e)

    def _emit_stmts(self, stmts):
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, CSet):
                self._line(f'{self._lvalue(stmt.dst)} = {self._expr(stmt.src)};')
            elif isinstance(stmt, CRet):
                if stmt.value is None:
                    self._line('return;')
                else:
                    self._line(f'return {self._expr(stmt.value)};')
            elif isinstance(stmt, CCallStmt):
                call_text = self._expr(stmt.call)
                keep = False
                if stmt.dst is not None:
                    for later in stmts[i + 1:]:
                        if expr_uses(later, {'rax'}) or expr_uses(later, {'eax'}):
                            keep = True
                            break
                        if 'rax' in stmt_defs(later):
                            break
                if keep and stmt.dst is not None:
                    self._line(f'{self._lvalue(stmt.dst)} = {call_text};')
                else:
                    self._line(f'{call_text};')
            elif isinstance(stmt, CPush):
                self._line(f'push({self._expr(stmt.value)});')
            elif isinstance(stmt, CPop):
                self._line(f'pop({self._expr(stmt.dst)});')
            elif isinstance(stmt, CJump):
                self.used_labels.add(stmt.target)
                self._line(f'goto loc_{stmt.target:X};')
            elif isinstance(stmt, CBranch):
                if stmt.f is None:
                    self.used_labels.add(stmt.t)
                    self._line(f'if ({self._cond_text(stmt.cond)}) goto loc_{stmt.t:X};')
                else:
                    self.used_labels.add(stmt.t)
                    self.used_labels.add(stmt.f)
                    self._line(f'if ({self._cond_text(stmt.cond)}) goto loc_{stmt.t:X};')
                    self._line(f'goto loc_{stmt.f:X};')
            elif isinstance(stmt, CJumpIndirect):
                self._line(f'goto *{self._atom(stmt.value)};')
            elif isinstance(stmt, CSwitch):
                self._emit_switch_statement(stmt)
            elif isinstance(stmt, CComment):
                if stmt.text:
                    self._line(stmt.text)
            else:
                self._line('/* unknown statement */')

    def _emit_switch_statement(self, stmt):
        self._line(f'switch ({self._expr(stmt.value)}) {{')
        self.indent += 1
        for value, target in stmt.cases.items():
            self.used_labels.add(target)
            self._line(f'case {value}:')
            self.indent += 1
            self._line(f'goto loc_{target:X};')
            self.indent -= 1
        if stmt.default is not None:
            self.used_labels.add(stmt.default)
            self._line('default:')
            self.indent += 1
            self._line(f'goto loc_{stmt.default:X};')
            self.indent -= 1
        self.indent -= 1
        self._line('}')

    # nodes

    def emit_node(self, node):
        if node is None:
            return
        if isinstance(node, NSeq):
            for child in node.nodes:
                self.emit_node(child)
        elif isinstance(node, NBlock):
            if node.addr in self.labels and node.addr not in self.printed_labels:
                self.printed_labels.add(node.addr)
                self.used_labels.add(node.addr)
                self._line(f'loc_{node.addr:X}:')
            self._emit_stmts(node.stmts)
        elif isinstance(node, NIf):
            self._line(f'if ({self._cond_text(node.cond)}) {{')
            self.indent += 1
            self._emit_nodes(node.then)
            self.indent -= 1
            if node.els:
                self._line('} else {')
                self.indent += 1
                self._emit_nodes(node.els)
                self.indent -= 1
            self._line('}')
        elif isinstance(node, NWhile):
            body = node.body
            while body and isinstance(body[-1], NContinue):
                body.pop()
            if node.do_while:
                self._line('do {')
                self.indent += 1
                self._emit_nodes(node.body)
                self.indent -= 1
                self._line(f'}} while ({self._cond_text(node.cond)});')
            else:
                if node.cond is None:
                    self._line('while (1) {')
                else:
                    self._line(f'while ({self._cond_text(node.cond)}) {{')
                self.indent += 1
                self._emit_nodes(node.body)
                self.indent -= 1
                self._line('}')
        elif isinstance(node, NSwitch):
            self._line(f'switch ({self._expr(node.value)}) {{')
            self.indent += 1
            for value, body in node.cases:
                self._line(f'case {value}:')
                self.indent += 1
                self._emit_nodes(body)
                self._ensure_terminated(body)
                self.indent -= 1
            if node.default is not None:
                self._line('default:')
                self.indent += 1
                self._emit_nodes(node.default)
                self._ensure_terminated(node.default)
                self.indent -= 1
            self.indent -= 1
            self._line('}')
        elif isinstance(node, NBreak):
            self._line('break;')
        elif isinstance(node, NContinue):
            self._line('continue;')
        elif isinstance(node, NGoto):
            self.used_labels.add(node.target)
            self._line(f'goto loc_{node.target:X};')

    def _emit_nodes(self, nodes):
        for node in nodes:
            self.emit_node(node)

    def _ensure_terminated(self, body):
        if not body:
            return
        last = body[-1]
        if isinstance(last, (NBreak, NContinue, NGoto)):
            return
        if isinstance(last, NIf) and last.els:
            return
        if isinstance(last, NWhile):
            return
        if isinstance(last, NBlock) and last.stmts and isinstance(last.stmts[-1], (CRet, CJumpIndirect)):
            return
        self._line('break;')

    # function

    def render(self, tree):
        body_lines = []
        self.lines = body_lines
        self.emit_node(tree)
        func = self.func

        header = []
        header.append(f'// {func.name} @ 0x{func.address:X}')
        header.append(f'// blocks: {len(func.blocks)}   instructions: {len(func.insns)}   '
                      f'frame: {"rbp" if func.uses_frame else "none"}')
        if self.data_refs:
            for name, size in self.data_refs.items():
                header.append(f'extern {_c_type(size, False)} {name};')
        ret = 'void' if func.ret_void else _c_type(func.ret_size, True)
        args = []
        for name in func.arg_vars:
            if name in func.pointer_args:
                args.append(f'void *{name}')
            else:
                args.append(f'int64_t {name}')
        if not args:
            args.append('void')
        header.append(f'{ret} __fastcall {func.name}({", ".join(args)})')
        header.append('{')
        body = []
        if func.locals:
            for name, size in _sorted_locals(func.locals):
                body.append(f'    {_c_type(size, False)} {name};')
            body.append('')
        body.extend(body_lines)
        return '\n'.join(header) + '\n' + '\n'.join(body) + '\n}\n'


def run_passes(func):
    steps = (
        pass_stack_frame,   # stack frame recovery (var_/arg_ naming)
        pass_rsp_frame,     # rsp-relative accesses -> var_/arg_
        pass_security,      # drop stack-cookie plumbing
        pass_peephole,      # constant folding / copy removal
        pass_copy_prop,     # copy propagation
        pass_types,         # light typing for pointer arguments
        pass_dce,           # liveness + dead code elimination
        pass_abi,           # calling-convention (a1..a4) and return type
        pass_thread,        # jump threading + CFG refresh
        pass_peephole,
        pass_types,
    )
    for step in steps:
        try:
            step(func)
        except Exception:
            func.pass_error = f'{step.__name__} failed'
            continue


def _tree_has_label(node, labels):
    if node is None:
        return False
    if isinstance(node, NBlock):
        return node.addr in labels
    if isinstance(node, NSeq):
        return any(_tree_has_label(c, labels) for c in node.nodes)
    if isinstance(node, NIf):
        return (_tree_has_label_nodes(node.then, labels)
                or _tree_has_label_nodes(node.els, labels))
    if isinstance(node, NWhile):
        return _tree_has_label_nodes(node.body, labels)
    if isinstance(node, NSwitch):
        return (any(_tree_has_label_nodes(b, labels) for _v, b in node.cases)
                or _tree_has_label_nodes(node.default, labels))
    return False


def _tree_has_label_nodes(nodes, labels):
    return any(_tree_has_label(n, labels) for n in (nodes or []))


def _cleanup_tree(node, labels):
    # remove empty branches
    if node is None:
        return None
    if isinstance(node, NSeq):
        node.nodes = [n for n in (_cleanup_tree(c, labels) for c in node.nodes)
                      if n is not None]
        return node
    if isinstance(node, NBlock):
        return node
    if isinstance(node, NIf):
        node.then = [n for n in (_cleanup_tree(c, labels) for c in node.then)
                     if n is not None]
        node.els = [n for n in (_cleanup_tree(c, labels) for c in (node.els or []))
                    if n is not None]
        if not node.then and not node.els:
            if _tree_has_label_nodes(node.then, labels) or \
                    _tree_has_label_nodes(node.els, labels):
                return node
            return None
        if not node.then and node.els:
            node.cond = _negate_cond(node.cond)
            node.then, node.els = node.els, []
        return node
    if isinstance(node, NWhile):
        node.body = [n for n in (_cleanup_tree(c, labels) for c in node.body)
                     if n is not None]
        if not node.body and node.cond is not None and not node.do_while:
            return None
        return node
    if isinstance(node, NSwitch):
        node.cases = [(value, [n for n in (_cleanup_tree(c, labels) for c in body)
                               if n is not None])
                      for value, body in node.cases]
        if node.default is not None:
            node.default = [n for n in (_cleanup_tree(c, labels) for c in node.default)
                            if n is not None]
        return node
    return node


def render_function(func):
    run_passes(func)
    structurer = CStructurer(func)
    tree = structurer.build()
    tree = _cleanup_tree(tree, structurer.labels)
    printer = CPrinter(func, structurer.labels, func.strings)
    text = printer.render(tree)
    return text, structurer, printer


def main():
    if len(sys.argv) > 1:
        target = sys.argv[1]
        dumper = NuitkaDumper(target)
        dumper.run()
    else:
        dumper = NuitkaDumper("")
        dumper.run()


if __name__ == "__main__":
    main()
