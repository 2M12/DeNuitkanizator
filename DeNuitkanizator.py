#!/usr/bin/env python3
import sys
import os
import re
import struct
import marshal
import zlib
import hashlib
import datetime
import shutil
import math
import string
import json
import urllib.request
import urllib.error
from pathlib import Path
from collections import Counter

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

VERSION = "1.5"
REPO = "github.com/2M12/DeNuitkanizator"
GITHUB_API = "https://api.github.com/repos/2M12/DeNuitkanizator/releases/latest"

PYTHON_MAGICS = {
    b'\x42\x0d\x0d\x0a': "3.7",
    b'\x55\x0d\x0d\x0a': "3.8",
    b'\x61\x0d\x0d\x0a': "3.9",
    b'\x6f\x0d\x0d\x0a': "3.10",
    b'\xa7\x0d\x0d\x0a': "3.11",
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

#define MEMORY_SIZE 0x1000000

bool of = 0, sf = 0, zf = 0, af = 0, pf = 0, cf = 0;

union {
    uint64_t tmp64;
    uint32_t tmp32;
    uint16_t tmp16;
    uint8_t tmp8;
} tmp;

union {
    double d;
    float f[2];
    uint64_t u64;
    uint32_t u32[2];
    uint16_t u16[4];
    uint8_t u8[8];
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
        self.rsrc_start = 0
        self.rsrc_end = 0
        self.section_ranges = {}
        self.update_status = None
        self.update_version = None
        self.iat_addresses = {}
        self.import_name_by_address = {}
        self.pyobj_count = 0
        self.has_pyobject_files = False

    def run(self):
        self._show_banner()
        target = self._prompt_path()
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

    def _init_output(self, target):
        target_path = Path(target)
        if not target_path.exists():
            self._fatal_error(1)
        if not target_path.is_file():
            self._fatal_error(1)
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
        except Exception:
            self.logger.info("Not a valid PE file, continuing with raw data")
            self.all_sections_data = self.data

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
        self._extract_python_object_headers()
        self._check_pyobject_files()
        self._detect_packager()
        self._dump_sections()
        self._dump_overlay()
        self._dump_resources()
        self._extract_all_strings()
        self._aggressive_bytecode_search()
        self._extract_frozen_modules()
        self._extract_nuitka_constants()
        self._extract_source_paths()
        self._extract_variable_names()
        self._extract_nuitka_onefile_payload()
        self._dump_info()
        self._dump_hashes()
        self._dump_entropy()
        self._dump_disasm()
        self._dump_disasm_full()
        self._dump_disasm_to_c()
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
            "Dumps/bytecode/3.7", "Dumps/bytecode/3.8", "Dumps/bytecode/3.9",
            "Dumps/bytecode/3.10", "Dumps/bytecode/3.11",
            "Dumps/memory/py_objects", "Dumps/memory/nuitka_structs",
            "Dumps/frozen_modules", "Dumps/payloads",
            "Strings/suspicious", "Info", "Disasm/xrefs", "Disasm/full", "Disasm/functions", "Disasm/code",
            "Analysis",
            "Suspicious/encrypted_blocks", "Suspicious/compressed_blocks",
            "Suspicious/obfuscated_code", "Suspicious/anti_debug",
            "Suspicious/packed_sections",
            "Recovered/source/incomplete", "Recovered/bytecode_decoded",
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

    def _detect_packager(self):
        self.logger.info("Detecting packager...")
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
        if nuitka_hits >= 1:
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
                f"  Detected: PyInstaller (NOT EXACTLY: signatures matched but no Python DLL and no PyObject files, low confidence)")
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
        last_section = self.pe.sections[-1]
        pe_end = last_section.PointerToRawData + last_section.SizeOfRawData
        if pe_end < len(self.data):
            overlay = self.data[pe_end:]
            fname = self.output_dir / "Dumps" / "overlay.bin"
            fname.write_bytes(overlay)
            self.logger.info(f"  Overlay: {len(overlay):,} bytes")
        else:
            self.logger.info("  No overlay found")

    def _dump_resources(self):
        if not self.pe:
            return
        self.logger.info("Dumping resources...")
        count = 0
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    dest = None
                    if entry.id == 3 or entry.id == 14:
                        dest = self.output_dir / "Dumps" / "resources" / "icons"
                    elif entry.id == 24:
                        dest = self.output_dir / "Dumps" / "resources" / "manifests"
                    elif entry.id == 16:
                        dest = self.output_dir / "Dumps" / "resources" / "version_info"
                    elif entry.id == 2:
                        dest = self.output_dir / "Dumps" / "resources" / "bitmaps"
                    if dest is None:
                        continue
                    dest.mkdir(parents=True, exist_ok=True)
                    if hasattr(entry, 'directory'):
                        for res in entry.directory.entries:
                            if hasattr(res, 'data'):
                                try:
                                    data = self.pe.get_data(res.data.struct.OffsetToData, res.data.struct.Size)
                                    ext = ".bin"
                                    if entry.id in [3, 14]:
                                        ext = ".ico"
                                    elif entry.id == 24:
                                        ext = ".xml"
                                    elif entry.id == 2:
                                        ext = ".bmp"
                                    fname = dest / f"resource_{res.id}{ext}"
                                    fname.write_bytes(data)
                                    count += 1
                                except:
                                    pass
        except Exception as e:
            self.logger.warning(f"  Failed to dump some resources: {e}")
        self.logger.info(f"  Resources extracted: {count}")

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
        for skip in [0, 4, 8, 12]:
            test_offset = offset + skip
            if test_offset + 4 > len(data):
                continue
            for test_size in [4096, 8192, 16384, 32768, 65536, 131072]:
                if test_offset + test_size > len(data):
                    continue
                chunk = data[test_offset:test_offset + test_size]
                try:
                    marshal.loads(chunk)
                    fname = bytecode_dir / ver_name / f"marshal_valid_{offset:08x}_skip{skip}.pyc"
                    fname.write_bytes(chunk)
                    self.logger.info(f"  [VALID MARSHAL] {ver_name} at 0x{offset:08x} skip={skip} size={test_size}")
                    return
                except:
                    continue

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
        self.logger.info("Scanning for Python object headers...")
        pyobj_dir = self.output_dir / "Dumps" / "memory" / "py_objects"
        struct_patterns = [
            b'PyObject', b'PyCode', b'PyTuple', b'PyDict', b'PyList',
            b'PyUnicode', b'PyBytes', b'PyModule',
        ]
        total = 0
        for pattern in struct_patterns:
            offset = 0
            while True:
                offset = self.data.find(pattern, offset)
                if offset == -1:
                    break
                if offset > 16 and offset + 128 <= len(self.data):
                    chunk = self.data[offset - 16:offset + 128]
                    pattern_name = pattern.decode('ascii', errors='replace')
                    fname = pyobj_dir / f"{pattern_name}_{offset:08x}.bin"
                    fname.write_bytes(chunk)
                    total += 1
                offset += len(pattern)
        self.pyobj_count = total
        self.logger.info(f"  Python object headers extracted: {total}")

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
            for window in [65536, 131072, 262144, 524288, 1048576, 2097152, 4194304]:
                if offset + window > len(data):
                    continue
                chunk = data[offset:offset + window]
                try:
                    dctx = zstd.ZstdDecompressor()
                    decompressed = dctx.decompress(chunk)
                    if len(decompressed) > 4096:
                        fname = payload_dir / f"zstd_decompressed_{offset:08x}.bin"
                        fname.write_bytes(decompressed)
                        count += 1
                        self.logger.info(f"  [PAYLOAD ZSTD] Decompressed {len(decompressed):,} bytes at 0x{offset:08x}")
                        self._scan_data_for_patterns(decompressed)
                except:
                    pass
            offset += 4
        return count

    def _try_zlib_decompress(self, data, payload_dir, source_name):
        zlib_sigs = [b'\x78\x9c', b'\x78\x01', b'\x78\xda', b'\x78\x5e']
        count = 0
        for sig in zlib_sigs:
            offset = 0
            tried = set()
            while True:
                offset = data.find(sig, offset)
                if offset == -1:
                    break
                if offset in tried:
                    offset += len(sig)
                    continue
                tried.add(offset)
                for window in [65536, 131072, 262144, 524288, 1048576]:
                    if offset + window > len(data):
                        continue
                    chunk = data[offset:offset + window]
                    try:
                        decompressed = zlib.decompress(chunk)
                        if len(decompressed) > 4096:
                            fname = payload_dir / f"zlib_decompressed_{source_name}_{offset:08x}.bin"
                            fname.write_bytes(decompressed)
                            count += 1
                            self.logger.info(
                                f"  [PAYLOAD ZLIB] Decompressed {len(decompressed):,} bytes at 0x{offset:08x}")
                            self._scan_data_for_patterns(decompressed)
                    except:
                        pass
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
                                target = int(insn.op_str, 16)
                                if target > 0 and target < self.pe.OPTIONAL_HEADER.ImageBase + 0x10000000:
                                    function_starts.add(target)
                            except:
                                pass
                        if insn.mnemonic == 'jmp':
                            try:
                                target = int(insn.op_str, 16)
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
            call_graph = []
            for section in self.pe.sections:
                if not self._is_executable_section(section):
                    continue
                try:
                    data = section.get_data()
                    for insn in md.disasm(data, section.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase):
                        if insn.mnemonic == 'call':
                            try:
                                target = int(insn.op_str, 16)
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

    def _dump_xrefs(self):
        if capstone is None:
            return
        if not self.pe:
            return
        if not hasattr(self, '_string_offsets') or not self._string_offsets:
            return
        self.logger.info("Building cross-references (xrefs)...")
        xrefs_dir = self.output_dir / "Disasm" / "xrefs"
        try:
            arch_mode = self._get_arch_mode()
            md = Cs(CS_ARCH_X86, arch_mode)
            md.detail = True
            all_xrefs = []
            for section in self.pe.sections:
                if not self._is_executable_section(section):
                    continue
                try:
                    data = section.get_data()
                    for insn in md.disasm(data, section.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase):
                        if insn.mnemonic in ['lea', 'mov', 'push']:
                            for operand in insn.operands:
                                if operand.type == X86_OP_MEM and operand.mem.disp > 0:
                                    disp = operand.mem.disp
                                    image_base = self.pe.OPTIONAL_HEADER.ImageBase
                                    target_rva = disp - image_base
                                    if 0 <= target_rva < len(self.data):
                                        for s, offsets in self._string_offsets.items():
                                            for off in offsets:
                                                if abs(off - target_rva) < 8:
                                                    all_xrefs.append(
                                                        f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str} -> STRING @ 0x{off:x}: \"{s[:60]}\"")
                except:
                    pass
            self._write_list(xrefs_dir / "string_xrefs.txt", all_xrefs[:10000])
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
            all_import_xrefs = []
            seen = set()
            for section in self.pe.sections:
                if not self._is_executable_section(section):
                    continue
                try:
                    data = section.get_data()
                    for insn in md.disasm(data, section.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase):
                        if insn.mnemonic == 'call':
                            for operand in insn.operands:
                                if operand.type == X86_OP_MEM and operand.mem.disp > 0:
                                    target_addr = operand.mem.disp
                                    if target_addr in self.import_name_by_address:
                                        key = (insn.address, target_addr)
                                        if key not in seen:
                                            seen.add(key)
                                            import_name = self.import_name_by_address[target_addr]
                                            all_import_xrefs.append(f"0x{insn.address:016x}: call -> {import_name}")
                                elif operand.type == X86_OP_IMM:
                                    target_addr = operand.imm
                                    if target_addr in self.import_name_by_address:
                                        key = (insn.address, target_addr)
                                        if key not in seen:
                                            seen.add(key)
                                            import_name = self.import_name_by_address[target_addr]
                                            all_import_xrefs.append(f"0x{insn.address:016x}: call -> {import_name}")
                        if insn.mnemonic == 'jmp':
                            for operand in insn.operands:
                                if operand.type == X86_OP_MEM and operand.mem.disp > 0:
                                    target_addr = operand.mem.disp
                                    if target_addr in self.import_name_by_address:
                                        key = (insn.address, target_addr)
                                        if key not in seen:
                                            seen.add(key)
                                            import_name = self.import_name_by_address[target_addr]
                                            all_import_xrefs.append(f"0x{insn.address:016x}: jmp -> {import_name}")
                except:
                    pass
            self._write_list(xrefs_dir / "import_xrefs.txt", all_import_xrefs[:10000])
            self.logger.info(f"  Import xrefs found: {len(all_import_xrefs)}")
        except Exception as e:
            self.logger.warning(f"  Import xrefs failed: {e}")

    def _get_insn_comment(self, insn, code):
        comments = []
        for anti_debug_pattern in ANTI_DEBUG_PATTERNS:
            offset = insn.address - (self.pe.OPTIONAL_HEADER.ImageBase if self.pe else 0)
            if offset >= 0 and offset + len(anti_debug_pattern) <= len(code):
                if code[offset:offset + len(anti_debug_pattern)] == anti_debug_pattern:
                    comments.append("[ANTI-DEBUG]")
        if insn.mnemonic == 'call':
            try:
                target = int(insn.op_str, 16)
                if target > 0:
                    comments.append("[CALL]")
            except:
                comments.append("[CALL]")
        elif insn.mnemonic in {'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jl', 'jge', 'jle'}:
            comments.append("[JMP]")
        elif insn.mnemonic == 'ret':
            comments.append("[RET]")
        return "; ".join(comments) if comments else ""

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

    def _build_jump_places(self):
        jumps = {'jmp', 'je', 'jne', 'jz', 'jnz', 'jnb', 'jb', 'jbe', 'ja', 'jae', 'jg', 'jge', 'jl', 'jle', 'jo',
                 'jno', 'js', 'jns', 'jp', 'jnp', 'jcxz', 'jecxz', 'loop', 'loope', 'loopne'}
        for insn in self.instructions:
            if insn.mnemonic in jumps:
                if len(insn.operands) > 0:
                    try:
                        target = int(insn.op_str, 16)
                        self.jump_places.add(target)
                    except (ValueError, AttributeError):
                        pass
            if insn.mnemonic == 'call':
                if len(insn.operands) > 0:
                    try:
                        target = int(insn.op_str, 16)
                        self.call_targets.add(target)
                        self.jump_places.add(target)
                    except (ValueError, AttributeError):
                        pass

    def _resolve_iat_addr(self, insn, op):
        if op.type == X86_OP_MEM and op.mem.disp:
            addr = op.mem.disp
            if addr in self.import_names:
                return self.import_names[addr]
        if op.type == X86_OP_IMM and op.imm:
            addr = op.imm
            if addr in self.import_names:
                return self.import_names[addr]
        return None

    def generate(self):
        if not self.instructions:
            return ''

        entry_point = self.instructions[0].address
        self._process_block(entry_point)

        for target in sorted(self.call_targets):
            if target not in self.visited:
                self.c_code += '\n'
                self._process_block(target)

        return self.c_code

    def _process_block(self, address):
        if address in self.visited:
            return
        self.visited.add(address)

        insn = self.insn_by_addr.get(address)
        if not insn:
            return

        if address in self.jump_places:
            self.c_code += f'_0x{address:x}:\n'

        while insn:
            mnemonic = insn.mnemonic

            if mnemonic == 'ret':
                self.c_code += '    goto _end;\n'
                return

            elif mnemonic == 'jmp':
                op = insn.operands[0] if insn.operands else None
                if op and op.type == X86_OP_MEM:
                    iat_name = self._resolve_iat_addr(insn, op)
                    if iat_name:
                        self.c_code += f'    /* jmp -> {iat_name} */\n'
                        self.commented += 1
                        return
                try:
                    target = int(insn.op_str, 16)
                    self.c_code += f'    goto _0x{target:x};\n'
                    self.translated += 1
                    self._process_block(target)
                except (ValueError, AttributeError):
                    self.c_code += f'    /* jmp {insn.op_str} */\n'
                    self.commented += 1
                return

            elif mnemonic in ['je', 'jne', 'jz', 'jnz', 'jb', 'jbe', 'ja', 'jae', 'jg', 'jge', 'jl', 'jle', 'jo', 'jno',
                              'js', 'jns', 'jp', 'jnp']:
                try:
                    target = int(insn.op_str, 16)
                    condition = self._get_condition(mnemonic)
                    self.c_code += f'    if({condition}) goto _0x{target:x};\n'
                    self.translated += 1

                    next_addr = insn.address + insn.size

                    self._process_block(target)
                    self._process_block(next_addr)
                    return
                except (ValueError, AttributeError):
                    self.c_code += f'    /* {mnemonic} {insn.op_str} */\n'
                    self.commented += 1
                    return

            elif mnemonic in ['loop', 'loope', 'loopne']:
                try:
                    target = int(insn.op_str, 16)
                    if mnemonic == 'loop':
                        self.c_code += f'    if(--rcx) goto _0x{target:x};\n'
                    elif mnemonic == 'loope':
                        self.c_code += f'    if(--rcx && zf) goto _0x{target:x};\n'
                    else:
                        self.c_code += f'    if(--rcx && !zf) goto _0x{target:x};\n'
                    self.translated += 1

                    next_addr = insn.address + insn.size
                    self._process_block(target)
                    self._process_block(next_addr)
                    return
                except:
                    self.c_code += f'    /* {mnemonic} {insn.op_str} */\n'
                    self.commented += 1
                    return

            elif mnemonic == 'call':
                op = insn.operands[0] if insn.operands else None
                if op:
                    iat_name = self._resolve_iat_addr(insn, op)
                    if iat_name:
                        self.c_code += f'    /* call -> {iat_name} */\n'
                        self.commented += 1
                    else:
                        try:
                            target = int(insn.op_str, 16)
                            self.c_code += f'    PUSH64((uint64_t)&&_ret_{insn.address:x}); goto _0x{target:x}; _ret_{insn.address:x}:;\n'
                            self.translated += 1
                            self._process_block(target)
                        except (ValueError, AttributeError):
                            self.c_code += f'    /* call {insn.op_str} */\n'
                            self.commented += 1
                else:
                    self.c_code += '    /* call */\n'
                    self.commented += 1

                next_addr = insn.address + insn.size
                next_insn = self.insn_by_addr.get(next_addr)
                if next_insn:
                    insn = next_insn
                    continue
                else:
                    return

            elif mnemonic in ('rep', 'repe', 'repne'):
                next_addr = insn.address + insn.size
                next_insn = self.insn_by_addr.get(next_addr)
                if next_insn and next_insn.mnemonic in ('stosb', 'stosw', 'stosd', 'stosq', 'movsb', 'movsw', 'movsd',
                                                        'movsq'):
                    handler = self._get_rep_handler(next_insn.mnemonic, mnemonic)
                    if handler:
                        try:
                            self.c_code += handler(next_insn, list(next_insn.operands))
                            self.translated += 1
                            insn = self.insn_by_addr.get(next_insn.address + next_insn.size)
                            continue
                        except:
                            pass
                self.c_code += f'    /* {mnemonic} */\n'
                self.commented += 1
                insn = next_insn
                continue

            else:
                handler = self._get_handler(mnemonic)
                if handler:
                    ops = list(insn.operands)
                    try:
                        self.c_code += handler(insn, ops)
                        self.translated += 1
                    except Exception:
                        self.c_code += f'    /* {mnemonic} {insn.op_str} */\n'
                        self.commented += 1
                else:
                    self.c_code += f'    /* {mnemonic} {insn.op_str} */\n'
                    self.commented += 1

            next_addr = insn.address + insn.size
            insn = self.insn_by_addr.get(next_addr)

        return

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

    def _get_handler(self, mnemonic):
        handlers = {
            'mov': self._h_mov, 'movzx': self._h_movzx, 'movsx': self._h_movsx,
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

    def _op_to_c(self, insn, op):
        if op.type == X86_OP_REG:
            return self._reg_name(insn, op.reg)
        elif op.type == X86_OP_IMM:
            return hex(op.imm) if abs(op.imm) > 9 else str(op.imm)
        elif op.type == X86_OP_MEM:
            base = self._reg_name(insn, op.mem.base) if op.mem.base else ''
            index = self._reg_name(insn, op.mem.index) if op.mem.index else ''
            scale = op.mem.scale
            disp = op.mem.disp
            parts = []
            if base:
                parts.append(base)
            if index:
                parts.append(f'{index}*{scale}')
            if disp:
                if disp < 0:
                    parts.append(f'-{abs(disp)}')
                elif disp > 0:
                    parts.append(f'+{disp}')
                elif not parts:
                    parts.append('0')
            if not parts:
                parts.append('0')
            addr = ''.join(parts)
            return f'MEMORY(uint{op.size * 8}_t, {addr})'
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
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        s = self._xmm_name(insn, ops[1].reg)
        if ops[1].type == X86_OP_REG:
            return f'    xmm[{d}].u64 = xmm[{self._xmm_idx(s)}].u64; xmm[{d}+1] = xmm[{self._xmm_idx(s)}+1];\n'
        return f'    /* movaps {insn.op_str} */\n'

    def _h_movups(self, insn, ops):
        return self._h_movaps(insn, ops)

    def _h_movdqa(self, insn, ops):
        return self._h_movaps(insn, ops)

    def _h_movdqu(self, insn, ops):
        return self._h_movaps(insn, ops)

    def _h_lea(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        src = self._op_to_c(insn, ops[1])
        return f'    {dst} = (uint64_t)&{src};\n'

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
                target = int(insn.op_str, 16)
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
            target = int(insn.op_str, 16)
            return f'    goto _0x{target:x};\n'
        except (ValueError, AttributeError):
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_je(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(zf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jne(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(!zf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jb(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(cf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jbe(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(cf || zf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_ja(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(!cf && !zf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jae(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(!cf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jg(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(!zf && sf == of) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jge(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(sf == of) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jl(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(sf != of) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jle(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(zf || sf != of) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jo(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(of) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jno(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(!of) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_js(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(sf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jns(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(!sf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jp(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(pf) goto _0x{target:x};\n'
        except:
            return f'    /* {insn.mnemonic} {insn.op_str} */\n'

    def _h_jnp(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
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
        return f'    xmm[{d}].u64 = 0; xmm[{d}+1].u64 = 0;\n'

    def _h_xorpd(self, insn, ops):
        return self._h_xorps(insn, ops)

    def _h_pxor(self, insn, ops):
        return self._h_xorps(insn, ops)

    def _h_addps(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        s = self._xmm_idx(self._xmm_name(insn, ops[1].reg))
        return f'    xmm[{d}].f[0] += xmm[{s}].f[0]; xmm[{d}].f[1] += xmm[{s}].f[1];\n'

    def _h_addpd(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        s = self._xmm_idx(self._xmm_name(insn, ops[1].reg))
        return f'    xmm[{d}].d += xmm[{s}].d;\n'

    def _h_mulps(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        s = self._xmm_idx(self._xmm_name(insn, ops[1].reg))
        return f'    xmm[{d}].f[0] *= xmm[{s}].f[0]; xmm[{d}].f[1] *= xmm[{s}].f[1];\n'

    def _h_mulpd(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        s = self._xmm_idx(self._xmm_name(insn, ops[1].reg))
        return f'    xmm[{d}].d *= xmm[{s}].d;\n'

    def _h_cvtsi2sd(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        src = self._op_to_c_val(insn, ops[1])
        return f'    xmm[{d}].d = (double)(int64_t){src};\n'

    def _h_cvttsd2si(self, insn, ops):
        dst = self._op_to_c(insn, ops[0])
        s = self._xmm_idx(self._xmm_name(insn, ops[1].reg))
        return f'    {dst} = (int{ops[0].size * 8}_t)xmm[{s}].d;\n'

    def _h_cvtsd2ss(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        s = self._xmm_idx(self._xmm_name(insn, ops[1].reg))
        return f'    xmm[{d}].f[0] = (float)xmm[{s}].d;\n'

    def _h_cvtss2sd(self, insn, ops):
        d = self._xmm_idx(self._xmm_name(insn, ops[0].reg))
        s = self._xmm_idx(self._xmm_name(insn, ops[1].reg))
        return f'    xmm[{d}].d = (double)xmm[{s}].f[0];\n'

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
            target = int(insn.op_str, 16)
            return f'    if(--rcx) goto _0x{target:x};\n'
        except:
            return f'    /* loop {insn.op_str} */\n'

    def _h_loope(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(--rcx && zf) goto _0x{target:x};\n'
        except:
            return f'    /* loope {insn.op_str} */\n'

    def _h_loopne(self, insn, ops):
        try:
            target = int(insn.op_str, 16)
            return f'    if(--rcx && !zf) goto _0x{target:x};\n'
        except:
            return f'    /* loopne {insn.op_str} */\n'


ofMask = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}


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
