#!/Users/obsaabate/Desktop/SLU/Summer 2025/pwndbg/pwndbg-env/bin/python3.11
#-------------------------------------------------------------------------------
# scripts/readelf.py
#
# A clone of 'readelf' in Python, based on the pyelftools library
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
import argparse
import os, sys
import re
import string
import traceback
import itertools
# Note: zip has different behaviour between Python 2.x and 3.x.
# - Using izip ensures compatibility.
try:
    from itertools import izip
except:
    izip = zip

# For running from development directory. It should take precedence over the
# installed pyelftools.
sys.path.insert(0, '.')


from elftools import __version__
from elftools.common.exceptions import ELFError
from elftools.common.utils import bytes2str, iterbytes
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.elf.enums import ENUM_D_TAG
from elftools.elf.segments import InterpSegment
from elftools.elf.sections import (
    NoteSection, SymbolTableSection, SymbolTableIndexSection
)
from elftools.elf.gnuversions import (
    GNUVerSymSection, GNUVerDefSection,
    GNUVerNeedSection,
    )
from elftools.elf.relocation import RelocationSection
from elftools.elf.descriptions import (
    describe_ei_class, describe_ei_data, describe_ei_version,
    describe_ei_osabi, describe_e_type, describe_e_machine,
    describe_e_version_numeric, describe_p_type, describe_p_flags,
    describe_rh_flags, describe_sh_type, describe_sh_flags,
    describe_symbol_type, describe_symbol_bind, describe_symbol_visibility,
    describe_symbol_shndx, describe_reloc_type, describe_dyn_tag,
    describe_dt_flags, describe_dt_flags_1, describe_ver_flags, describe_note,
    describe_attr_tag_arm, describe_attr_tag_riscv, describe_symbol_other
    )
from elftools.elf.constants import E_FLAGS
from elftools.elf.constants import E_FLAGS_MASKS
from elftools.elf.constants import SH_FLAGS
from elftools.elf.constants import SHN_INDICES
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.descriptions import (
    describe_reg_name, describe_attr_value, set_global_machine_arch,
    describe_CFI_instructions, describe_CFI_register_rule,
    describe_CFI_CFA_rule, describe_DWARF_expr
    )
from elftools.dwarf.constants import (
    DW_LNS_copy, DW_LNS_set_file, DW_LNE_define_file)
from elftools.dwarf.locationlists import LocationParser, LocationEntry, LocationViewPair, BaseAddressEntry as LocBaseAddressEntry, LocationListsPair
from elftools.dwarf.ranges import RangeEntry, BaseAddressEntry as RangeBaseAddressEntry, RangeListsPair
from elftools.dwarf.callframe import CIE, FDE, ZERO
from elftools.ehabi.ehabiinfo import CorruptEHABIEntry, CannotUnwindEHABIEntry, GenericEHABIEntry
from elftools.dwarf.enums import ENUM_DW_UT

def _get_cu_base(cu):
    top_die = cu.get_top_DIE()
    attr = top_die.attributes
    if 'DW_AT_low_pc' in attr:
        return attr['DW_AT_low_pc'].value
    elif 'DW_AT_entry_pc' in attr:
        return attr['DW_AT_entry_pc'].value
    elif 'DW_AT_ranges' in attr:
        # Rare case but happens: rangelist in the top DIE.
        # If there is a base or at least one absolute entry,
        # this will give us the base IP for the CU.
        rl = cu.dwarfinfo.range_lists().get_range_list_at_offset(attr['DW_AT_ranges'].value, cu)
        base_ip = None
        for r in rl:
            if isinstance(r, RangeBaseAddressEntry):
                ip = r.base_address
            elif isinstance(r, RangeEntry) and r.is_absolute:
                ip = r.begin_offset
            else:
                ip = None
            if ip is not None and (base_ip is None or ip < base_ip):
                base_ip = ip
        if base_ip is None:
            raise ValueError("Can't find the base IP (low_pc) for a CU")
        return base_ip
    else:
        raise ValueError("Can't find the base IP (low_pc) for a CU")

# Matcher for all control characters, for transforming them into "^X" form when
# formatting symbol names for display.
_CONTROL_CHAR_RE = re.compile(r'[\x01-\x1f]')

def _format_symbol_name(s):
    return _CONTROL_CHAR_RE.sub(lambda match: '^' + chr(0x40 + ord(match[0])), s)

class ReadElf(object):
    """ display_* methods are used to emit output into the output stream
    """
    def __init__(self, file, output):
        """ file:
                stream object with the ELF file to read

            output:
                output stream to write to
        """
        self.elffile = ELFFile(file)
        self.output = output

        # Lazily initialized if a debug dump is requested
        self._dwarfinfo = None

        self._versioninfo = None

        self._shndx_sections = None

    def display_file_header(self):
        """ Display the ELF file header
        """
        self._emitline('ELF Header:')
        self._emit('  Magic:   ')
        self._emit(' '.join('%2.2x' % b
                   for b in self.elffile.e_ident_raw))
        self._emitline('      ')
        header = self.elffile.header
        e_ident = header['e_ident']
        self._emitline('  Class:                             %s' %
                describe_ei_class(e_ident['EI_CLASS']))
        self._emitline('  Data:                              %s' %
                describe_ei_data(e_ident['EI_DATA']))
        self._emitline('  Version:                           %s' %
                describe_ei_version(e_ident['EI_VERSION']))
        self._emitline('  OS/ABI:                            %s' %
                describe_ei_osabi(e_ident['EI_OSABI']))
        self._emitline('  ABI Version:                       %d' %
                e_ident['EI_ABIVERSION'])
        self._emitline('  Type:                              %s' %
                describe_e_type(header['e_type'], self.elffile))
        self._emitline('  Machine:                           %s' %
                describe_e_machine(header['e_machine']))
        self._emitline('  Version:                           %s' %
                describe_e_version_numeric(header['e_version']))
        self._emitline('  Entry point address:               %s' %
                self._format_hex(header['e_entry']))
        self._emit('  Start of program headers:          %s' %
                header['e_phoff'])
        self._emitline(' (bytes into file)')
        self._emit('  Start of section headers:          %s' %
                header['e_shoff'])
        self._emitline(' (bytes into file)')
        self._emitline('  Flags:                             %s%s' %
                (self._format_hex(header['e_flags']),
                self.decode_flags(header['e_flags'])))
        self._emitline('  Size of this header:               %s (bytes)' %
                header['e_ehsize'])
        self._emitline('  Size of program headers:           %s (bytes)' %
                header['e_phentsize'])
        self._emitline('  Number of program headers:         %s' %
                header['e_phnum'])
        self._emitline('  Size of section headers:           %s (bytes)' %
                header['e_shentsize'])
        self._emit('  Number of section headers:         %s' %
                header['e_shnum'])
        if header['e_shnum'] == 0 and self.elffile.num_sections() != 0:
            self._emitline(' (%d)' % self.elffile.num_sections())
        else:
            self._emitline('')
        self._emit('  Section header string table index: %s' %
                header['e_shstrndx'])
        if header['e_shstrndx'] == SHN_INDICES.SHN_XINDEX:
            self._emitline(' (%d)' % self.elffile.get_shstrndx())
        else:
            self._emitline('')

    def decode_flags(self, flags):
        description = ""
        if self.elffile['e_machine'] == "EM_ARM":
            eabi = flags & E_FLAGS.EF_ARM_EABIMASK
            flags &= ~E_FLAGS.EF_ARM_EABIMASK

            if flags & E_FLAGS.EF_ARM_RELEXEC:
                description += ', relocatable executabl'
                flags &= ~E_FLAGS.EF_ARM_RELEXEC

            if eabi == E_FLAGS.EF_ARM_EABI_VER5:
                EF_ARM_KNOWN_FLAGS = E_FLAGS.EF_ARM_ABI_FLOAT_SOFT|E_FLAGS.EF_ARM_ABI_FLOAT_HARD|E_FLAGS.EF_ARM_LE8|E_FLAGS.EF_ARM_BE8
                description += ', Version5 EABI'
                if flags & E_FLAGS.EF_ARM_ABI_FLOAT_SOFT:
                    description += ", soft-float ABI"
                elif flags & E_FLAGS.EF_ARM_ABI_FLOAT_HARD:
                    description += ", hard-float ABI"

                if flags & E_FLAGS.EF_ARM_BE8:
                    description += ", BE8"
                elif flags & E_FLAGS.EF_ARM_LE8:
                    description += ", LE8"

                if flags & ~EF_ARM_KNOWN_FLAGS:
                    description += ', <unknown>'
            else:
                description += ', <unrecognized EABI>'

        elif self.elffile['e_machine'] == 'EM_PPC64':
            if flags & E_FLAGS.EF_PPC64_ABI_V2:
                description += ', abiv2'

        elif self.elffile['e_machine'] == "EM_MIPS":
            if flags & E_FLAGS.EF_MIPS_NOREORDER:
                description += ", noreorder"
            if flags & E_FLAGS.EF_MIPS_PIC:
                description += ", pic"
            if flags & E_FLAGS.EF_MIPS_CPIC:
                description += ", cpic"
            if (flags & E_FLAGS.EF_MIPS_ABI2):
                description += ", abi2"
            if (flags & E_FLAGS.EF_MIPS_32BITMODE):
                description += ", 32bitmode"
            if (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_O32):
                description += ", o32"
            elif (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_O64):
                description += ", o64"
            elif (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_EABI32):
                description += ", eabi32"
            elif (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_EABI64):
                description += ", eabi64"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_1:
                description += ", mips1"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_2:
                description += ", mips2"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_3:
                description += ", mips3"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_4:
                description += ", mips4"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_5:
                description += ", mips5"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_32R2:
                description += ", mips32r2"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_64R2:
                description += ", mips64r2"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_32:
                description += ", mips32"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_64:
                description += ", mips64"

        elif self.elffile['e_machine'] == "EM_RISCV":
            if flags & E_FLAGS.EF_RISCV_RVC:
                description += ", RVC"
            if (flags & E_FLAGS.EF_RISCV_RVE):
                description += ", RVE"
            if (flags & E_FLAGS.EF_RISCV_TSO):
                description += ", TSO"
            if (flags & E_FLAGS.EF_RISCV_FLOAT_ABI) == E_FLAGS.EF_RISCV_FLOAT_ABI_SOFT:
                description += ", soft-float ABI"
            if (flags & E_FLAGS.EF_RISCV_FLOAT_ABI) == E_FLAGS.EF_RISCV_FLOAT_ABI_SINGLE:
                description += ", single-float ABI"
            if (flags & E_FLAGS.EF_RISCV_FLOAT_ABI) == E_FLAGS.EF_RISCV_FLOAT_ABI_DOUBLE:
                description += ", double-float ABI"
            if (flags & E_FLAGS.EF_RISCV_FLOAT_ABI) == E_FLAGS.EF_RISCV_FLOAT_ABI_QUAD:
                description += ", quad-float ABI"

        elif self.elffile['e_machine'] == "EM_LOONGARCH":
            if (flags & E_FLAGS.EF_LOONGARCH_ABI_MODIFIER_MASK) == E_FLAGS.EF_LOONGARCH_ABI_SOFT_FLOAT:
                description += ", SOFT-FLOAT"
            if (flags & E_FLAGS.EF_LOONGARCH_ABI_MODIFIER_MASK) == E_FLAGS.EF_LOONGARCH_ABI_SINGLE_FLOAT:
                description += ", SINGLE-FLOAT"
            if (flags & E_FLAGS.EF_LOONGARCH_ABI_MODIFIER_MASK) == E_FLAGS.EF_LOONGARCH_ABI_DOUBLE_FLOAT:
                description += ", DOUBLE-FLOAT"
            if (flags & E_FLAGS.EF_LOONGARCH_OBJABI_MASK) == E_FLAGS.EF_LOONGARCH_OBJABI_V0:
                description += ", OBJ-v0"
            if (flags & E_FLAGS.EF_LOONGARCH_OBJABI_MASK) == E_FLAGS.EF_LOONGARCH_OBJABI_V1:
                description += ", OBJ-v1"

        return description

    def display_program_headers(self, show_heading=True):
        """ Display the ELF program headers.
            If show_heading is True, displays the heading for this information
            (Elf file type is...)
        """
        self._emitline()
        if self.elffile.num_segments() == 0:
            self._emitline('There are no program headers in this file.')
            return

        elfheader = self.elffile.header
        if show_heading:
            self._emitline('Elf file type is %s' %
                describe_e_type(elfheader['e_type'], self.elffile))
            self._emitline('Entry point is %s' %
                self._format_hex(elfheader['e_entry']))
            # readelf weirness - why isn't e_phoff printed as hex? (for section
            # headers, it is...)
            self._emitline('There are %s program headers, starting at offset %s' % (
                self.elffile.num_segments(), elfheader['e_phoff']))
            self._emitline()

        self._emitline('Program Headers:')

        # Now comes the table of program headers with their attributes. Note
        # that due to different formatting constraints of 32-bit and 64-bit
        # addresses, there are some conditions on elfclass here.
        #
        # First comes the table heading
        #
        if self.elffile.elfclass == 32:
            self._emitline('  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align')
        else:
            self._emitline('  Type           Offset             VirtAddr           PhysAddr')
            self._emitline('                 FileSiz            MemSiz              Flags  Align')

        # Now the entries
        #
        for segment in self.elffile.iter_segments():
            self._emit('  %-14s ' % describe_p_type(segment['p_type']))

            if self.elffile.elfclass == 32:
                self._emitline('%s %s %s %s %s %-3s %s' % (
                    self._format_hex(segment['p_offset'], fieldsize=6),
                    self._format_hex(segment['p_vaddr'], fullhex=True),
                    self._format_hex(segment['p_paddr'], fullhex=True),
                    self._format_hex(segment['p_filesz'], fieldsize=5),
                    self._format_hex(segment['p_memsz'], fieldsize=5),
                    describe_p_flags(segment['p_flags']),
                    self._format_hex(segment['p_align'])))
            else: # 64
                self._emitline('%s %s %s' % (
                    self._format_hex(segment['p_offset'], fullhex=True),
                    self._format_hex(segment['p_vaddr'], fullhex=True),
                    self._format_hex(segment['p_paddr'], fullhex=True)))
                self._emitline('                 %s %s  %-3s    %s' % (
                    self._format_hex(segment['p_filesz'], fullhex=True),
                    self._format_hex(segment['p_memsz'], fullhex=True),
                    describe_p_flags(segment['p_flags']),
                    # lead0x set to False for p_align, to mimic readelf.
                    # No idea why the difference from 32-bit mode :-|
                    self._format_hex(segment['p_align'], lead0x=False)))

            if isinstance(segment, InterpSegment):
                self._emitline('      [Requesting program interpreter: %s]' %
                    segment.get_interp_name())

        # Sections to segments mapping
        #
        if self.elffile.num_sections() == 0:
            # No sections? We're done
            return

        self._emitline('\n Section to Segment mapping:')
        self._emitline('  Segment Sections...')

        for nseg, segment in enumerate(self.elffile.iter_segments()):
            self._emit('   %2.2d     ' % nseg)

            for section in self.elffile.iter_sections():
                if (    not section.is_null() and
                        not ((section['sh_flags'] & SH_FLAGS.SHF_TLS) != 0 and
                             section['sh_type'] == 'SHT_NOBITS' and
                             segment['p_type'] != 'PT_TLS') and
                        segment.section_in_segment(section)):
                    self._emit('%s ' % section.name)

            self._emitline('')

    def display_section_headers(self, show_heading=True):
        """ Display the ELF section headers
        """
        elfheader = self.elffile.header
        if show_heading:
            self._emitline('There are %s section headers, starting at offset %s' % (
                elfheader['e_shnum'], self._format_hex(elfheader['e_shoff'])))

        if self.elffile.num_sections() == 0:
            self._emitline('There are no sections in this file.')
            return

        self._emitline('\nSection Header%s:' % (
            's' if self.elffile.num_sections() > 1 else ''))

        # Different formatting constraints of 32-bit and 64-bit addresses
        #
        if self.elffile.elfclass == 32:
            self._emitline('  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al')
        else:
            self._emitline('  [Nr] Name              Type             Address           Offset')
            self._emitline('       Size              EntSize          Flags  Link  Info  Align')

        # Now the entries
        #
        for nsec, section in enumerate(self.elffile.iter_sections()):
            self._emit('  [%2u] %-17.17s %-15.15s ' % (
                nsec, section.name, describe_sh_type(section['sh_type'])))

            if self.elffile.elfclass == 32:
                self._emitline('%s %s %s %s %3s %2s %3s %2s' % (
                    self._format_hex(section['sh_addr'], fieldsize=8, lead0x=False),
                    self._format_hex(section['sh_offset'], fieldsize=6, lead0x=False),
                    self._format_hex(section['sh_size'], fieldsize=6, lead0x=False),
                    self._format_hex(section['sh_entsize'], fieldsize=2, lead0x=False),
                    describe_sh_flags(section['sh_flags']),
                    section['sh_link'], section['sh_info'],
                    section['sh_addralign']))
            else: # 64
                self._emitline(' %s  %s' % (
                    self._format_hex(section['sh_addr'], fullhex=True, lead0x=False),
                    self._format_hex(section['sh_offset'],
                        fieldsize=16 if section['sh_offset'] > 0xffffffff else 8,
                        lead0x=False)))
                self._emitline('       %s  %s %3s      %2s   %3s     %s' % (
                    self._format_hex(section['sh_size'], fullhex=True, lead0x=False),
                    self._format_hex(section['sh_entsize'], fullhex=True, lead0x=False),
                    describe_sh_flags(section['sh_flags']),
                    section['sh_link'], section['sh_info'],
                    section['sh_addralign']))

        self._emitline('Key to Flags:')
        self._emitline('  W (write), A (alloc), X (execute), M (merge),'
                       ' S (strings), I (info),')
        self._emitline('  L (link order), O (extra OS processing required),'
                       ' G (group), T (TLS),')
        self._emitline('  C (compressed), x (unknown), o (OS specific),'
                       ' E (exclude),')
        self._emit('  ')
        if self.elffile['e_machine'] == 'EM_ARM':
            self._emit('y (purecode), ')
        self._emitline('p (processor specific)')

    def display_symbol_tables(self):
        """ Display the symbol tables contained in the file
        """
        self._init_versioninfo()

        symbol_tables = [(idx, s) for idx, s in enumerate(self.elffile.iter_sections())
                         if isinstance(s, SymbolTableSection)]

        if not symbol_tables and self.elffile.num_sections() == 0:
            self._emitline('')
            self._emitline('Dynamic symbol information is not available for'
                           ' displaying symbols.')

        for section_index, section in symbol_tables:
            if not isinstance(section, SymbolTableSection):
                continue

            if section['sh_entsize'] == 0:
                self._emitline("\nSymbol table '%s' has a sh_entsize of zero!" % (
                    section.name))
                continue

            self._emitline("\nSymbol table '%s' contains %d %s:" % (
                section.name,
                section.num_symbols(),
                'entry' if section.num_symbols() == 1 else 'entries'))

            if self.elffile.elfclass == 32:
                self._emitline('   Num:    Value  Size Type    Bind   Vis      Ndx Name')
            else: # 64
                self._emitline('   Num:    Value          Size Type    Bind   Vis      Ndx Name')

            for nsym, symbol in enumerate(section.iter_symbols()):
                version_info = ''
                # readelf doesn't display version info for Solaris versioning
                if (section['sh_type'] == 'SHT_DYNSYM' and
                        self._versioninfo['type'] == 'GNU'):
                    version = self._symbol_version(nsym)
                    if (version['name'] != symbol.name and
                        version['index'] not in ('VER_NDX_LOCAL',
                                                 'VER_NDX_GLOBAL')):
                        if version['filename']:
                            # external symbol
                            version_info = '@%(name)s (%(index)i)' % version
                        else:
                            # internal symbol
                            if version['hidden']:
                                version_info = '@%(name)s' % version
                            else:
                                version_info = '@@%(name)s' % version

                symbol_name = symbol.name
                # Print section names for STT_SECTION symbols as readelf does
                if (symbol['st_info']['type'] == 'STT_SECTION'
                    and symbol['st_shndx'] != 'SHN_UNDEF'
                    and symbol['st_shndx'] < self.elffile.num_sections()
                    and symbol['st_name'] == 0):
                    symbol_name = self.elffile.get_section(symbol['st_shndx']).name

                # symbol names are truncated to 25 chars, similarly to readelf
                self._emitline('%6d: %s %s %-7s %-6s %-7s %4s %.25s%s' % (
                    nsym,
                    self._format_hex(
                        symbol['st_value'], fullhex=True, lead0x=False),
                    "%5d" % symbol['st_size'] if symbol['st_size'] < 100000 else hex(symbol['st_size']),
                    describe_symbol_type(symbol['st_info']['type']),
                    describe_symbol_bind(symbol['st_info']['bind']),
                    describe_symbol_other(symbol['st_other']),
                    describe_symbol_shndx(self._get_symbol_shndx(symbol,
                                                                 nsym,
                                                                 section_index)),
                    _format_symbol_name(symbol_name),
                    version_info))

    def display_dynamic_tags(self):
        """ Display the dynamic tags contained in the file
        """
        has_dynamic_sections = False
        for section in self.elffile.iter_sections():
            if not isinstance(section, DynamicSection):
                continue

            has_dynamic_sections = True
            self._emitline("\nDynamic section at offset %s contains %d %s:" % (
                self._format_hex(section['sh_offset']),
                section.num_tags(),
                'entry' if section.num_tags() == 1 else 'entries'))
            self._emitline("  Tag        Type                         Name/Value")

            padding = 20 + (8 if self.elffile.elfclass == 32 else 0)
            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    parsed = 'Shared library: [%s]' % tag.needed
                elif tag.entry.d_tag == 'DT_RPATH':
                    parsed = 'Library rpath: [%s]' % tag.rpath
                elif tag.entry.d_tag == 'DT_RUNPATH':
                    parsed = 'Library runpath: [%s]' % tag.runpath
                elif tag.entry.d_tag == 'DT_SONAME':
                    parsed = 'Library soname: [%s]' % tag.soname
                elif tag.entry.d_tag.endswith(('SZ', 'ENT')):
                    parsed = '%i (bytes)' % tag['d_val']
                elif tag.entry.d_tag == 'DT_FLAGS':
                    parsed = describe_dt_flags(tag.entry.d_val)
                elif tag.entry.d_tag == 'DT_FLAGS_1':
                    parsed = 'Flags: %s' % describe_dt_flags_1(tag.entry.d_val)
                elif tag.entry.d_tag.endswith(('NUM', 'COUNT')):
                    parsed = '%i' % tag['d_val']
                elif tag.entry.d_tag == 'DT_PLTREL':
                    s = describe_dyn_tag(tag.entry.d_val)
                    if s.startswith('DT_'):
                        s = s[3:]
                    parsed = '%s' % s
                elif tag.entry.d_tag == 'DT_MIPS_FLAGS':
                    parsed = describe_rh_flags(tag.entry.d_val)
                elif tag.entry.d_tag in ('DT_MIPS_SYMTABNO',
                                         'DT_MIPS_LOCAL_GOTNO'):
                    parsed = str(tag.entry.d_val)
                elif tag.entry.d_tag == 'DT_AARCH64_BTI_PLT':
                    parsed = ''
                else:
                    parsed = '%#x' % tag['d_val']

                self._emitline(" %s %-*s %s" % (
                    self._format_hex(ENUM_D_TAG.get(tag.entry.d_tag, tag.entry.d_tag),
                        fullhex=True, lead0x=True),
                    padding,
                    '(%s)' % (tag.entry.d_tag[3:],),
                    parsed))
        if not has_dynamic_sections:
            self._emitline("\nThere is no dynamic section in this file.")

    def display_notes(self):
        """ Display the notes contained in the file
        """
        for section in self.elffile.iter_sections():
            if isinstance(section, NoteSection):
                for note in section.iter_notes():
                      self._emitline("\nDisplaying notes found in: {}".format(
                          section.name))
                      self._emitline('  Owner                Data size        Description')
                      self._emitline('  %s %s\t%s' % (
                          note['n_name'].ljust(20),
                          self._format_hex(note['n_descsz'], fieldsize=8),
                          describe_note(note, self.elffile.header.e_machine)))

    def display_relocations(self):
        """ Display the relocations contained in the file
        """
        has_relocation_sections = False
        for section in self.elffile.iter_sections():
            if not isinstance(section, RelocationSection):
                continue

            has_relocation_sections = True
            self._emitline("\nRelocation section '%.128s' at offset %s contains %d %s:" % (
                section.name,
                self._format_hex(section['sh_offset']),
                section.num_relocations(),
                'entry' if section.num_relocations() == 1 else 'entries'))
            if section.is_RELA():
                self._emitline("  Offset          Info           Type           Sym. Value    Sym. Name + Addend")
            else:
                self._emitline(" Offset     Info    Type            Sym.Value  Sym. Name")

            # The symbol table section pointed to in sh_link
            symtable = self.elffile.get_section(section['sh_link'])

            for rel in section.iter_relocations():
                hexwidth = 8 if self.elffile.elfclass == 32 else 12
                self._emit('%s  %s %-17.17s' % (
                    self._format_hex(rel['r_offset'],
                        fieldsize=hexwidth, lead0x=False),
                    self._format_hex(rel['r_info'],
                        fieldsize=hexwidth, lead0x=False),
                    describe_reloc_type(
                        rel['r_info_type'], self.elffile)))

                if rel['r_info_sym'] == 0:
                    if section.is_RELA():
                        fieldsize = 8 if self.elffile.elfclass == 32 else 16
                        addend = self._format_hex(rel['r_addend'], lead0x=False)
                        self._emit(' %s   %s' % (' ' * fieldsize, addend))
                    self._emitline()

                else:
                    symbol = symtable.get_symbol(rel['r_info_sym'])
                    # Some symbols have zero 'st_name', so instead what's used
                    # is the name of the section they point at. Truncate symbol
                    # names (excluding version info) to 22 chars, similarly to
                    # readelf.
                    if symbol['st_name'] == 0:
                        symsecidx = self._get_symbol_shndx(symbol,
                                                           rel['r_info_sym'],
                                                           section['sh_link'])
                        symsec = self.elffile.get_section(symsecidx)
                        symbol_name = symsec.name
                        version = ''
                    else:
                        symbol_name = symbol.name
                        version = self._symbol_version(rel['r_info_sym'])
                        version = (version['name']
                                   if version and version['name'] else '')
                    symbol_name = '%.22s' % symbol_name
                    if version:
                        symbol_name += '@' + version

                    self._emit(' %s %s' % (
                        self._format_hex(
                            symbol['st_value'],
                            fullhex=True, lead0x=False),
                        _format_symbol_name(symbol_name)))
                    if section.is_RELA():
                        self._emit(' %s %x' % (
                            '+' if rel['r_addend'] >= 0 else '-',
                            abs(rel['r_addend'])))
                    self._emitline()

                # Emit the two additional relocation types for ELF64 MIPS
                # binaries.
                if (self.elffile.elfclass == 64 and
                    self.elffile['e_machine'] == 'EM_MIPS'):
                    for i in (2, 3):
                        rtype = rel['r_info_type%s' % i]
                        self._emit('                    Type%s: %s' % (
                                   i,
                                   describe_reloc_type(rtype, self.elffile)))
                        self._emitline()

        if not has_relocation_sections:
            self._emitline('\nThere are no relocations in this file.')

    def display_arm_unwind(self):
        if not self.elffile.has_ehabi_info():
            self._emitline('There are no .ARM.idx sections in this file.')
            return
        for ehabi_info in self.elffile.get_ehabi_infos():
            # Unwind section '.ARM.exidx' at offset 0x203e8 contains 1009 entries:
            self._emitline("\nUnwind section '%s' at offset 0x%x contains %d %s" % (
                ehabi_info.section_name(),
                ehabi_info.section_offset(),
                ehabi_info.num_entry(),
                'entry' if ehabi_info.num_entry() == 1 else 'entries'))

            for i in range(ehabi_info.num_entry()):
                entry = ehabi_info.get_entry(i)
                self._emitline()
                self._emitline("Entry %d:" % i)
                if isinstance(entry, CorruptEHABIEntry):
                    self._emitline("    [corrupt] %s" % entry.reason)
                    continue
                self._emit("    Function offset 0x%x: " % entry.function_offset)
                if isinstance(entry, CannotUnwindEHABIEntry):
                    self._emitline("[cantunwind]")
                    continue
                elif entry.eh_table_offset:
                    self._emitline("@0x%x" % entry.eh_table_offset)
                else:
                    self._emitline("Compact (inline)")
                if isinstance(entry, GenericEHABIEntry):
                    self._emitline("    Personality: 0x%x" % entry.personality)
                else:
                    self._emitline("    Compact model index: %d" % entry.personality)
                    for mnemonic_item in entry.mnmemonic_array():
                        self._emit('    ')
                        self._emitline(mnemonic_item)

    def display_version_info(self):
        """ Display the version info contained in the file
        """
        self._init_versioninfo()

        if not self._versioninfo['type']:
            self._emitline("\nNo version information found in this file.")
            return

        for section in self.elffile.iter_sections():
            if isinstance(section, GNUVerSymSection):
                self._print_version_section_header(section, 'Version symbols')
                num_symbols = section.num_symbols()

                # Symbol version info are printed four by four entries
                for idx_by_4 in range(0, num_symbols, 4):

                    self._emit('  %03x:' % idx_by_4)

                    for idx in range(idx_by_4, min(idx_by_4 + 4, num_symbols)):

                        symbol_version = self._symbol_version(idx)
                        if symbol_version['index'] == 'VER_NDX_LOCAL':
                            version_index = 0
                            version_name = '(*local*)'
                        elif symbol_version['index'] == 'VER_NDX_GLOBAL':
                            version_index = 1
                            version_name = '(*global*)'
                        else:
                            version_index = symbol_version['index']
                            version_name = '(%(name)s)' % symbol_version

                        visibility = 'h' if symbol_version['hidden'] else ' '

                        self._emit('%4x%s%-13s' % (
                            version_index, visibility, version_name))

                    self._emitline()

            elif isinstance(section, GNUVerDefSection):
                self._print_version_section_header(
                    section, 'Version definition', indent=2)

                offset = 0
                for verdef, verdaux_iter in section.iter_versions():
                    verdaux = next(verdaux_iter)

                    name = verdaux.name
                    if verdef['vd_flags']:
                        flags = describe_ver_flags(verdef['vd_flags'])
                        # Mimic exactly the readelf output
                        flags += ' '
                    else:
                        flags = 'none'

                    self._emitline('  %s: Rev: %i  Flags: %s  Index: %i'
                                   '  Cnt: %i  Name: %s' % (
                            self._format_hex(offset, fieldsize=6,
                                             alternate=True),
                            verdef['vd_version'], flags, verdef['vd_ndx'],
                            verdef['vd_cnt'], name))

                    verdaux_offset = (
                            offset + verdef['vd_aux'] + verdaux['vda_next'])
                    for idx, verdaux in enumerate(verdaux_iter, start=1):
                        self._emitline('  %s: Parent %i: %s' %
                            (self._format_hex(verdaux_offset, fieldsize=4),
                                              idx, verdaux.name))
                        verdaux_offset += verdaux['vda_next']

                    offset += verdef['vd_next']

            elif isinstance(section, GNUVerNeedSection):
                self._print_version_section_header(section, 'Version needs')

                offset = 0
                for verneed, verneed_iter in section.iter_versions():

                    self._emitline('  %s: Version: %i  File: %s  Cnt: %i' % (
                            self._format_hex(offset, fieldsize=6,
                                             alternate=True),
                            verneed['vn_version'], verneed.name,
                            verneed['vn_cnt']))

                    vernaux_offset = offset + verneed['vn_aux']
                    for idx, vernaux in enumerate(verneed_iter, start=1):
                        if vernaux['vna_flags']:
                            flags = describe_ver_flags(vernaux['vna_flags'])
                            # Mimic exactly the readelf output
                            flags += ' '
                        else:
                            flags = 'none'

                        self._emitline(
                            '  %s:   Name: %s  Flags: %s  Version: %i' % (
                                self._format_hex(vernaux_offset, fieldsize=4),
                                vernaux.name, flags,
                                vernaux['vna_other']))

                        vernaux_offset += vernaux['vna_next']

                    offset += verneed['vn_next']

    def display_arch_specific(self):
        """ Display the architecture-specific info contained in the file.
        """
        if self.elffile['e_machine'] == 'EM_ARM':
            self._display_arch_specific_arm()
        elif self.elffile['e_machine'] == 'EM_RISCV':
            self._display_arch_specific_riscv()

    def display_hex_dump(self, section_spec):
        """ Display a hex dump of a section. section_spec is either a section
            number or a name.
        """
        section = self._section_from_spec(section_spec)
        if section is None:
            # readelf prints the warning to stderr. Even though stderrs are not compared
            # in tests, we comply with that behavior.
            sys.stderr.write('readelf: Warning: Section \'%s\' was not dumped because it does not exist!\n' % (
                section_spec))
            return
        if section['sh_type'] == 'SHT_NOBITS':
            self._emitline("\nSection '%s' has no data to dump." % (
                section_spec))
            return

        self._emitline("\nHex dump of section '%s':" % section.name)
        self._note_relocs_for_section(section)
        addr = section['sh_addr']
        data = section.data()
        dataptr = 0

        while dataptr < len(data):
            bytesleft = len(data) - dataptr
            # chunks of 16 bytes per line
            linebytes = 16 if bytesleft > 16 else bytesleft

            self._emit('  %s ' % self._format_hex(addr, fieldsize=8))
            for i in range(16):
                if i < linebytes:
                    self._emit('%2.2x' % data[dataptr + i])
                else:
                    self._emit('  ')
                if i % 4 == 3:
                    self._emit(' ')

            for i in range(linebytes):
                c = data[dataptr + i : dataptr + i + 1]
                if c[0] >= 32 and c[0] < 0x7f:
                    self._emit(bytes2str(c))
                else:
                    self._emit(bytes2str(b'.'))

            self._emitline()
            addr += linebytes
            dataptr += linebytes

        self._emitline()

    def display_string_dump(self, section_spec):
        """ Display a strings dump of a section. section_spec is either a
            section number or a name.
        """
        section = self._section_from_spec(section_spec)
        if section is None:
            # readelf prints the warning to stderr. Even though stderrs are not compared
            # in tests, we comply with that behavior.
            sys.stderr.write('readelf.py: Warning: Section \'%s\' was not dumped because it does not exist!\n' % (
                section_spec))
            return
        if section['sh_type'] == 'SHT_NOBITS':
            self._emitline("\nSection '%s' has no data to dump." % (
                section_spec))
            return

        self._emitline("\nString dump of section '%s':" % section.name)

        found = False
        data = section.data()
        dataptr = 0

        while dataptr < len(data):
            while ( dataptr < len(data) and
                    not (32 <= data[dataptr] <= 127)):
                dataptr += 1

            if dataptr >= len(data):
                break

            endptr = dataptr
            while endptr < len(data) and data[endptr] != 0:
                endptr += 1

            found = True
            self._emitline('  [%6x]  %s' % (
                dataptr, bytes2str(data[dataptr:endptr])))

            dataptr = endptr

        if not found:
            self._emitline('  No strings found in this section.')
        else:
            self._emitline()

    def display_debug_dump(self, dump_what):
        """ Dump a DWARF section
        """
        self._init_dwarfinfo()
        if self._dwarfinfo is None:
            return

        set_global_machine_arch(self.elffile.get_machine_arch())

        if dump_what == 'info':
            self._dump_debug_info()
            self._dump_debug_types()
        elif dump_what == 'decodedline':
            self._dump_debug_line_programs()
        elif dump_what == 'frames':
            self._dump_debug_frames()
        elif dump_what == 'frames-interp':
            self._dump_debug_frames_interp()
        elif dump_what == 'aranges':
            self._dump_debug_aranges()
        elif dump_what in { 'pubtypes', 'pubnames' }:
            self._dump_debug_namelut(dump_what)
        elif dump_what == 'loc':
            self._dump_debug_locations()
        elif dump_what == 'Ranges':
            self._dump_debug_ranges()
        else:
            self._emitline('debug dump not yet supported for "%s"' % dump_what)

    def _format_hex(self, addr, fieldsize=None, fullhex=False, lead0x=True,
                    alternate=False):
        """ Format an address into a hexadecimal string.

            fieldsize:
                Size of the hexadecimal field (with leading zeros to fit the
                address into. For example with fieldsize=8, the format will
                be %08x
                If None, the minimal required field size will be used.

            fullhex:
                If True, override fieldsize to set it to the maximal size
                needed for the elfclass

            lead0x:
                If True, leading 0x is added

            alternate:
                If True, override lead0x to emulate the alternate
                hexadecimal form specified in format string with the #
                character: only non-zero values are prefixed with 0x.
                This form is used by readelf.
        """
        if alternate:
            if addr == 0:
                lead0x = False
            else:
                lead0x = True
                if fieldsize is not None:
                    fieldsize -= 2

        s = '0x' if lead0x else ''
        if fullhex:
            fieldsize = 8 if self.elffile.elfclass == 32 else 16
        if fieldsize is None:
            field = '%x'
        else:
            field = '%' + '0%sx' % fieldsize
        return s + field % addr

    def _print_version_section_header(self, version_section, name, lead0x=True,
                                      indent=1):
        """ Print a section header of one version related section (versym,
            verneed or verdef) with some options to accomodate readelf
            little differences between each header (e.g. indentation
            and 0x prefixing).
        """
        if hasattr(version_section, 'num_versions'):
            num_entries = version_section.num_versions()
        else:
            num_entries = version_section.num_symbols()

        self._emitline("\n%s section '%s' contains %d %s:" % (
            name, version_section.name, num_entries,
            'entry' if num_entries == 1 else 'entries'))
        self._emitline('%sAddr: %s  Offset: %s  Link: %i (%s)' % (
            ' ' * indent,
            self._format_hex(
                version_section['sh_addr'], fieldsize=16, lead0x=lead0x),
            self._format_hex(
                version_section['sh_offset'], fieldsize=8, lead0x=True),
            version_section['sh_link'],
                self.elffile.get_section(version_section['sh_link']).name
            )
        )

    def _init_versioninfo(self):
        """ Search and initialize informations about version related sections
            and the kind of versioning used (GNU or Solaris).
        """
        if self._versioninfo is not None:
            return

        self._versioninfo = {'versym': None, 'verdef': None,
                             'verneed': None, 'type': None}

        for section in self.elffile.iter_sections():
            if isinstance(section, GNUVerSymSection):
                self._versioninfo['versym'] = section
            elif isinstance(section, GNUVerDefSection):
                self._versioninfo['verdef'] = section
            elif isinstance(section, GNUVerNeedSection):
                self._versioninfo['verneed'] = section
            elif isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag['d_tag'] == 'DT_VERSYM':
                        self._versioninfo['type'] = 'GNU'
                        break

        if not self._versioninfo['type'] and (
                self._versioninfo['verneed'] or self._versioninfo['verdef']):
            self._versioninfo['type'] = 'Solaris'

    def _symbol_version(self, nsym):
        """ Return a dict containing information on the
            or None if no version information is available
        """
        self._init_versioninfo()

        symbol_version = dict.fromkeys(('index', 'name', 'filename', 'hidden'))

        if (not self._versioninfo['versym'] or
                nsym >= self._versioninfo['versym'].num_symbols()):
            return None

        symbol = self._versioninfo['versym'].get_symbol(nsym)
        index = symbol.entry['ndx']
        if not index in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL'):
            index = int(index)

            if self._versioninfo['type'] == 'GNU':
                # In GNU versioning mode, the highest bit is used to
                # store whether the symbol is hidden or not
                if index & 0x8000:
                    index &= ~0x8000
                    symbol_version['hidden'] = True

            if (self._versioninfo['verdef'] and
                    index <= self._versioninfo['verdef'].num_versions()):
                _, verdaux_iter = \
                        self._versioninfo['verdef'].get_version(index)
                symbol_version['name'] = next(verdaux_iter).name
            else:
                verneed, vernaux = \
                        self._versioninfo['verneed'].get_version(index)
                symbol_version['name'] = vernaux.name
                symbol_version['filename'] = verneed.name

        symbol_version['index'] = index
        return symbol_version

    def _section_from_spec(self, spec):
        """ Retrieve a section given a "spec" (either number or name).
            Return None if no such section exists in the file.
        """
        try:
            num = int(spec)
            if num < self.elffile.num_sections():
                return self.elffile.get_section(num)
            else:
                return None
        except ValueError:
            # Not a number. Must be a name then
            return self.elffile.get_section_by_name(spec)

    def _get_symbol_shndx(self, symbol, symbol_index, symtab_index):
        """ Get the index into the section header table for the "symbol"
            at "symbol_index" located in the symbol table with section index
            "symtab_index".
        """
        symbol_shndx = symbol['st_shndx']
        if symbol_shndx != SHN_INDICES.SHN_XINDEX:
            return symbol_shndx

        # Check for or lazily construct index section mapping (symbol table
        # index -> corresponding symbol table index section object)
        if self._shndx_sections is None:
            self._shndx_sections = {sec.symboltable: sec for sec in self.elffile.iter_sections()
                                    if isinstance(sec, SymbolTableIndexSection)}
        return self._shndx_sections[symtab_index].get_section_index(symbol_index)

    def _note_relocs_for_section(self, section):
        """ If there are relocation sections pointing to the givne section,
            emit a note about it.
        """
        for relsec in self.elffile.iter_sections():
            if isinstance(relsec, RelocationSection):
                info_idx = relsec['sh_info']
                if self.elffile.get_section(info_idx) == section:
                    self._emitline('  Note: This section has relocations against it, but these have NOT been applied to this dump.')
                    return

    def _init_dwarfinfo(self):
        """ Initialize the DWARF info contained in the file and assign it to
            self._dwarfinfo.
            Leave self._dwarfinfo at None if no DWARF info was found in the file
        """
        if self._dwarfinfo is not None:
            return

        if self.elffile.has_dwarf_info():
            self._dwarfinfo = self.elffile.get_dwarf_info()
        else:
            self._dwarfinfo = None

    def _dump_debug_info(self):
        """ Dump the debugging info section.
        """
        if not self._dwarfinfo.has_debug_info:
            return
        self._emitline('Contents of the %s section:\n' % self._dwarfinfo.debug_info_sec.name)

        # Offset of the .debug_info section in the stream
        section_offset = self._dwarfinfo.debug_info_sec.global_offset

        for cu in self._dwarfinfo.iter_CUs():
            self._emitline('  Compilation Unit @ offset %s:' %
                self._format_hex(cu.cu_offset, alternate=True))
            self._emitline('   Length:        %s (%s)' % (
                self._format_hex(cu['unit_length']),
                '%s-bit' % cu.dwarf_format()))
            self._emitline('   Version:       %s' % cu['version'])
            if cu['version'] >= 5:
                if cu.header.get("unit_type", ''):
                    unit_type = cu.header.unit_type
                    self._emitline('   Unit Type:     %s (%d)' % (
                        unit_type, ENUM_DW_UT.get(cu.header.unit_type, 0)))
                    self._emitline('   Abbrev Offset: %s' % (
                        self._format_hex(cu['debug_abbrev_offset'], alternate=True)))
                    self._emitline('   Pointer Size:  %s' % cu['address_size'])
                    if unit_type in ('DW_UT_skeleton', 'DW_UT_split_compile'):
                        self._emitline('   Dwo id:        %s' % cu['dwo_id'])
                    elif unit_type in ('DW_UT_type', 'DW_UT_split_type'):
                        self._emitline('   Signature:     0x%x' % cu['type_signature'])
                        self._emitline('   Type Offset:   0x%x' % cu['type_offset'])
            else:
                self._emitline('   Abbrev Offset: %s' % (
                    self._format_hex(cu['debug_abbrev_offset'], alternate=True))),
                self._emitline('   Pointer Size:  %s' % cu['address_size'])

            # The nesting depth of each DIE within the tree of DIEs must be
            # displayed. To implement this, a counter is incremented each time
            # the current DIE has children, and decremented when a null die is
            # encountered. Due to the way the DIE tree is serialized, this will
            # correctly reflect the nesting depth
            #
            die_depth = 0
            current_function = None
            for die in cu.iter_DIEs():
                if die.tag == 'DW_TAG_subprogram':
                    current_function = die
                self._emitline(' <%s><%x>: Abbrev Number: %s%s' % (
                    die_depth,
                    die.offset,
                    die.abbrev_code,
                    (' (%s)' % die.tag) if not die.is_null() else ''))
                if die.is_null():
                    die_depth -= 1
                    continue

                for attr in die.attributes.values():
                    name = attr.name
                    # Unknown attribute values are passed-through as integers
                    if isinstance(name, int):
                        name = 'Unknown AT value: %x' % name

                    attr_desc = describe_attr_value(attr, die, section_offset)

                    if 'DW_OP_fbreg' in attr_desc and current_function and not 'DW_AT_frame_base' in current_function.attributes:
                        postfix = ' [without dw_at_frame_base]'
                    else:
                        postfix = ''

                    self._emitline('    <%x>   %-18s: %s%s' % (
                        attr.offset,
                        name,
                        attr_desc,
                        postfix))

                if die.has_children:
                    die_depth += 1

        self._emitline()

    def _dump_debug_types(self):
        """Dump the debug types section
        """
        if not self._dwarfinfo.has_debug_info:
            return
        if self._dwarfinfo.debug_types_sec is None:
            return
        self._emitline('Contents of the %s section:\n' % self._dwarfinfo.debug_types_sec.name)

        # Offset of the .debug_types section in the stream
        section_offset = self._dwarfinfo.debug_types_sec.global_offset

        for tu in self._dwarfinfo.iter_TUs():
            self._emitline('  Compilation Unit @ offset %s:' %
                           self._format_hex(tu.tu_offset, alternate=True))
            self._emitline('   Length:        %s (%s)' % (self._format_hex(tu['unit_length']),
                                                          '%s-bit' % tu.dwarf_format()))
            self._emitline('   Version:       %s' % tu['version'])
            self._emitline('   Abbrev Offset: %s' % (self._format_hex(tu['debug_abbrev_offset'], alternate=True)))
            self._emitline('   Pointer Size:  %s' % tu['address_size'])
            self._emitline('   Signature:     0x%x' % tu['signature'])
            self._emitline('   Type Offset:   0x%x' % tu['type_offset'])

            die_depth = 0
            for die in tu.iter_DIEs():
                self._emitline(' <%s><%x>: Abbrev Number: %s%s' % (
                    die_depth,
                    die.offset,
                    die.abbrev_code,
                    (' (%s)' % die.tag) if not die.is_null() else ''))
                if die.is_null():
                    die_depth -= 1
                    continue

                for attr in die.attributes.values():
                    name = attr.name
                    # Unknown attribute values are passed-through as integers
                    if isinstance(name, int):
                        name = 'Unknown AT value: %x' % name

                    attr_desc = describe_attr_value(attr, die, section_offset)

                    self._emitline('    <%x>   %-18s: %s' % (
                        attr.offset,
                        name,
                        attr_desc))

                if die.has_children:
                    die_depth += 1

        self._emitline()

    def _dump_debug_line_programs(self):
        """ Dump the (decoded) line programs from .debug_line
            The programs are dumped in the order of the CUs they belong to.
        """
        if not self._dwarfinfo.has_debug_info:
            return
        self._emitline('Contents of the %s section:' % self._dwarfinfo.debug_line_sec.name)
        self._emitline()
        lineprogram_list = []

        for cu in self._dwarfinfo.iter_CUs():
            # Avoid dumping same lineprogram multiple times
            lineprogram = self._dwarfinfo.line_program_for_CU(cu)

            if lineprogram is None or lineprogram in lineprogram_list:
                continue 

            lineprogram_list.append(lineprogram)
            ver5 = lineprogram.header.version >= 5

            cu_filename = bytes2str(lineprogram['file_entry'][0].name)
            if len(lineprogram['include_directory']) > 0:
                # GNU readelf 2.38 only outputs directory in wide mode
                self._emitline('%s:' % cu_filename)
            else:
                self._emitline('CU: %s:' % cu_filename)

            self._emitline('File name                            Line number    Starting address    Stmt')
            # GNU readelf has a View column that we don't try to replicate
            # The autotest has logic in place to ignore that

            # Print each state's file, line and address information. For some
            # instructions other output is needed to be compatible with
            # readelf.
            for entry in lineprogram.get_entries():
                state = entry.state
                if state is None:
                    # Special handling for commands that don't set a new state
                    if entry.command == DW_LNS_set_file:
                        file_entry = lineprogram['file_entry'][entry.args[0] - 1]
                        if file_entry.dir_index == 0:
                            # current directory
                            self._emitline('\n./%s:[++]' % (
                                bytes2str(file_entry.name)))
                        else:
                            self._emitline('\n%s/%s:' % (
                                bytes2str(lineprogram['include_directory'][file_entry.dir_index - 1]),
                                bytes2str(file_entry.name)))
                    elif entry.command == DW_LNE_define_file:
                        self._emitline('%s:' % (
                            bytes2str(lineprogram['include_directory'][entry.args[0].dir_index])))
                elif lineprogram['version'] < 4 or self.elffile['e_machine'] == 'EM_PPC64':
                    self._emitline('%-35s  %11s  %18s    %s' % (
                        bytes2str(lineprogram['file_entry'][state.file - 1].name),
                        state.line if not state.end_sequence else '-',
                        '0' if state.address == 0 else self._format_hex(state.address),
                        'x' if state.is_stmt and not state.end_sequence else ''))
                else:
                    # In readelf, on non-VLIW machines there is no op_index postfix after address.
                    # It used to be unconditional.
                    self._emitline('%-35s  %s  %18s%s %s' % (
                        bytes2str(lineprogram['file_entry'][state.file - 1].name),
                        "%11d" % (state.line,) if not state.end_sequence else '-',
                        '0' if state.address == 0 else self._format_hex(state.address),
                        '' if lineprogram.header.maximum_operations_per_instruction == 1 else '[%d]' % (state.op_index,),
                        'x' if state.is_stmt and not state.end_sequence else ''))
                if entry.command == DW_LNS_copy:
                    # Another readelf oddity...
                    self._emitline()

    def _dump_frames_info(self, section, cfi_entries):
        """ Dump the raw call frame info in a section.

            `section` is the Section instance that contains the call frame info
            while `cfi_entries` must be an iterable that yields the sequence of
            CIE or FDE instances.
        """
        self._emitline('Contents of the %s section:' % section.name)

        for entry in cfi_entries:
            if isinstance(entry, CIE):
                self._emitline('\n%08x %s %s CIE' % (
                    entry.offset,
                    self._format_hex(entry['length'], fullhex=True, lead0x=False),
                    self._format_hex(entry['CIE_id'], fieldsize=8, lead0x=False)))
                self._emitline('  Version:               %d' % entry['version'])
                self._emitline('  Augmentation:          "%s"' % bytes2str(entry['augmentation']))
                if(entry['version'] >= 4):
                    self._emitline('  Pointer Size:          %d' % entry['address_size'])
                    self._emitline('  Segment Size:          %d' % entry['segment_size'])
                self._emitline('  Code alignment factor: %u' % entry['code_alignment_factor'])
                self._emitline('  Data alignment factor: %d' % entry['data_alignment_factor'])
                self._emitline('  Return address column: %d' % entry['return_address_register'])
                if entry.augmentation_bytes:
                    self._emitline('  Augmentation data:     {}'.format(' '.join(
                        '{:02x}'.format(ord(b))
                        for b in iterbytes(entry.augmentation_bytes)
                    )))
                self._emitline()

            elif isinstance(entry, FDE):
                # Readelf bug #31973
                length = entry['length'] if entry.cie.offset < entry.offset else entry.cie['length']
                self._emitline('\n%08x %s %s FDE cie=%08x pc=%s..%s' % (
                    entry.offset,
                    self._format_hex(length, fullhex=True, lead0x=False),
                    self._format_hex(entry['CIE_pointer'], fieldsize=8, lead0x=False),
                    entry.cie.offset,
                    self._format_hex(entry['initial_location'], fullhex=True, lead0x=False),
                    self._format_hex(
                        entry['initial_location'] + entry['address_range'],
                        fullhex=True, lead0x=False)))
                if entry.augmentation_bytes:
                    self._emitline('  Augmentation data:     {}'.format(' '.join(
                        '{:02x}'.format(ord(b))
                        for b in iterbytes(entry.augmentation_bytes)
                    )))

            else: # ZERO terminator
                assert isinstance(entry, ZERO)
                self._emitline('\n%08x ZERO terminator' % entry.offset)
                continue

            self._emit(describe_CFI_instructions(entry))
        self._emitline()

    def _dump_debug_frames(self):
        """ Dump the raw frame info from .debug_frame and .eh_frame sections.
        """
        if self._dwarfinfo.has_EH_CFI():
            self._dump_frames_info(
                    self._dwarfinfo.eh_frame_sec,
                    self._dwarfinfo.EH_CFI_entries())
        self._emitline()

        if self._dwarfinfo.has_CFI():
            self._dump_frames_info(
                    self._dwarfinfo.debug_frame_sec,
                    self._dwarfinfo.CFI_entries())

    def _dump_debug_namelut(self, what):
        """
        Dump the debug pubnames section.
        """
        if what == 'pubnames':
            namelut = self._dwarfinfo.get_pubnames()
            section = self._dwarfinfo.debug_pubnames_sec
        else:
            namelut = self._dwarfinfo.get_pubtypes()
            section = self._dwarfinfo.debug_pubtypes_sec

        # readelf prints nothing if the section is not present.
        if namelut is None or len(namelut) == 0:
            return

        self._emitline('Contents of the %s section:' % section.name)
        self._emitline()

        cu_headers = namelut.get_cu_headers()

        # go over CU-by-CU first and item-by-item next.
        for (cu_hdr, (cu_ofs, items)) in izip(cu_headers, itertools.groupby(
            namelut.items(), key = lambda x: x[1].cu_ofs)):

            self._emitline('  Length:                              %d'   % cu_hdr.unit_length)
            self._emitline('  Version:                             %d'   % cu_hdr.version)
            self._emitline('  Offset into .debug_info section:     0x%x' % cu_hdr.debug_info_offset)
            self._emitline('  Size of area in .debug_info section: %d'   % cu_hdr.debug_info_length)
            self._emitline()
            self._emitline('    Offset  Name')
            for item in items:
                self._emitline('    %x          %s' % (item[1].die_ofs - cu_ofs, item[0]))
        self._emitline()

    def _dump_debug_aranges(self):
        """ Dump the aranges table
        """
        aranges_table = self._dwarfinfo.get_aranges()
        if aranges_table == None:
            return
        # Seems redundant, but we need to get the unsorted set of entries
        # to match system readelf.
        # Also, sometimes there are blank sections in aranges, but readelf
        # dumps them, so we should too.
        unordered_entries = aranges_table._get_entries(need_empty=True)

        if len(unordered_entries) == 0:
            self._emitline()
            self._emitline("Section '.debug_aranges' has no debugging data.")
            return

        self._emitline('Contents of the %s section:' % self._dwarfinfo.debug_aranges_sec.name)
        self._emitline()
        prev_offset = None
        for entry in unordered_entries:
            if prev_offset != entry.info_offset:
                if entry != unordered_entries[0]:
                    self._emitline('    %s %s' % (
                        self._format_hex(0, fullhex=True, lead0x=False),
                        self._format_hex(0, fullhex=True, lead0x=False)))
                self._emitline('  Length:                   %d' % (entry.unit_length))
                self._emitline('  Version:                  %d' % (entry.version))
                self._emitline('  Offset into .debug_info:  0x%x' % (entry.info_offset))
                self._emitline('  Pointer Size:             %d' % (entry.address_size))
                self._emitline('  Segment Size:             %d' % (entry.segment_size))
                self._emitline()
                self._emitline('    Address            Length')
            if entry.begin_addr != 0 or entry.length != 0:
                self._emitline('    %s %s' % (
                    self._format_hex(entry.begin_addr, fullhex=True, lead0x=False),
                    self._format_hex(entry.length, fullhex=True, lead0x=False)))
            prev_offset = entry.info_offset
        self._emitline('    %s %s' % (
                self._format_hex(0, fullhex=True, lead0x=False),
                self._format_hex(0, fullhex=True, lead0x=False)))

    def _dump_frames_interp_info(self, section, cfi_entries):
        """ Dump interpreted (decoded) frame information in a section.

        `section` is the Section instance that contains the call frame info
        while `cfi_entries` must be an iterable that yields the sequence of
        CIE or FDE instances.
        """
        self._emitline('Contents of the %s section:' % section.name)

        for entry in cfi_entries:
            if isinstance(entry, CIE):
                self._emitline('\n%08x %s %s CIE "%s" cf=%d df=%d ra=%d' % (
                    entry.offset,
                    self._format_hex(entry['length'], fullhex=True, lead0x=False),
                    self._format_hex(entry['CIE_id'], fieldsize=8, lead0x=False),
                    bytes2str(entry['augmentation']),
                    entry['code_alignment_factor'],
                    entry['data_alignment_factor'],
                    entry['return_address_register']))
                ra_regnum = entry['return_address_register']

            elif isinstance(entry, FDE):
                # Readelf bug #31973 - FDE length misreported if FDE precedes its CIE
                length = entry['length'] if entry.cie.offset < entry.offset else entry.cie['length']
                self._emitline('\n%08x %s %s FDE cie=%08x pc=%s..%s' % (
                    entry.offset,
                    self._format_hex(length, fullhex=True, lead0x=False),
                    self._format_hex(entry['CIE_pointer'], fieldsize=8, lead0x=False),
                    entry.cie.offset,
                    self._format_hex(entry['initial_location'], fullhex=True, lead0x=False),
                    self._format_hex(entry['initial_location'] + entry['address_range'],
                        fullhex=True, lead0x=False)))
                ra_regnum = entry.cie['return_address_register']

                # If the FDE brings adds no unwinding information compared to
                # its CIE, omit its table.
                if (len(entry.get_decoded().table) ==
                        len(entry.cie.get_decoded().table)):
                    continue

            else: # ZERO terminator
                assert isinstance(entry, ZERO)
                self._emitline('\n%08x ZERO terminator' % entry.offset)
                continue

            # Decode the table.
            decoded_table = entry.get_decoded()
            if len(decoded_table.table) == 0:
                continue

            # Print the heading row for the decoded table
            self._emit('   LOC')
            self._emit('  ' if entry.structs.address_size == 4 else '          ')
            self._emit(' CFA      ')

            # Look at the registers the decoded table describes.
            # We build reg_order here to match readelf's order. In particular,
            # registers are sorted by their number, so that the register
            # matching ra_regnum is usually listed last with a special heading.
            # (LoongArch is a notable exception in that its return register's
            # DWARF register number is not greater than other GPRs.)
            decoded_table = entry.get_decoded()
            reg_order = sorted(decoded_table.reg_order)
            if len(decoded_table.reg_order):
                # Headings for the registers
                for regnum in reg_order:
                    if regnum == ra_regnum:
                        self._emit('ra      ')
                        continue
                    self._emit('%-6s' % describe_reg_name(regnum))
            self._emitline()

            for line in decoded_table.table:
                self._emit(self._format_hex(
                    line['pc'], fullhex=True, lead0x=False))

                if line['cfa'] is not None:
                    s = describe_CFI_CFA_rule(line['cfa'])
                else:
                    s = 'u'
                self._emit(' %-9s' % s)

                for regnum in reg_order:
                    if regnum in line:
                        s = describe_CFI_register_rule(line[regnum])
                    else:
                        s = 'u'
                    self._emit('%-6s' % s)
                self._emitline()
        self._emitline()

    def _dump_debug_frames_interp(self):
        """ Dump the interpreted (decoded) frame information from .debug_frame
            and .eh_frame sections.
        """
        if self._dwarfinfo.has_EH_CFI():
            self._dump_frames_interp_info(
                    self._dwarfinfo.eh_frame_sec,
                    self._dwarfinfo.EH_CFI_entries())
        self._emitline()

        if self._dwarfinfo.has_CFI():
            self._dump_frames_interp_info(
                    self._dwarfinfo.debug_frame_sec,
                    self._dwarfinfo.CFI_entries())

    def _dump_debug_locations(self):
        """ Dump the location lists from .debug_loc/.debug_loclists section
        """
        di = self._dwarfinfo
        loc_lists_sec = di.location_lists()
        if not loc_lists_sec: # No locations section - readelf outputs nothing
            return

        if isinstance(loc_lists_sec, LocationListsPair):
            self._dump_debug_locsection(di, loc_lists_sec._loc)
            self._dump_debug_locsection(di, loc_lists_sec._loclists)
        else:
            self._dump_debug_locsection(di, loc_lists_sec)
        
    def _dump_debug_locsection(self, di, loc_lists_sec):        
        """ Dump the location lists from .debug_loc/.debug_loclists section
        """
        ver5 = loc_lists_sec.version >= 5
        section_name = (di.debug_loclists_sec if ver5 else di.debug_loc_sec).name

        # To dump a location list, one needs to know the CU.
        # Scroll through DIEs once, list the known location list offsets.
        # Don't need this CU/DIE scan if all entries are absolute or prefixed by base,
        # but let's not optimize for that yet.
        cu_map = dict() # Loc list offset => CU
        for cu in di.iter_CUs():
            for die in cu.iter_DIEs():
                for key in die.attributes:
                    attr = die.attributes[key]
                    if (LocationParser.attribute_has_location(attr, cu['version']) and
                        LocationParser._attribute_has_loc_list(attr, cu['version'])):
                        cu_map[attr.value] = cu

        addr_size = di.config.default_address_size # In bytes, 4 or 8
        addr_width = addr_size * 2 # In hex digits, 8 or 16
        line_template = "    %%08x %%0%dx %%0%dx %%s%%s" % (addr_width, addr_width)

        loc_lists = list(loc_lists_sec.iter_location_lists())
        if len(loc_lists) == 0:
            # Present but empty locations section - readelf outputs a message
            self._emitline("\nSection '%s' has no debugging data." % (section_name,))
            return
        
        # The v5 loclists section consists of CUs - small header, and 
        # an optional loclist offset table. Readelf prints out the header data dump
        # on top of every CU, so we should too. But we don't scroll through
        # the loclists section, we are effectively scrolling through the info
        # section (as to not stumble upon gaps in the secion, and not miss the
        # GNU locviews, so we have to keep track which loclists-CU we are in.
        # Same logic in v5 rnglists section dump.
        lcus = list(loc_lists_sec.iter_CUs()) if ver5 else None
        lcu_index = 0
        next_lcu_offset = 0

        self._emitline('Contents of the %s section:\n' % (section_name,))
        if not ver5:
            self._emitline('    Offset   Begin            End              Expression')

        for loc_list in loc_lists:
            # Emit CU headers before the current loclist, if we've moved to the next CU
            if ver5 and loc_list[0].entry_offset > next_lcu_offset:
                while loc_list[0].entry_offset > next_lcu_offset:
                    lcu = lcus[lcu_index]
                    self._dump_debug_loclists_CU_header(lcu)
                    next_lcu_offset = lcu.offset_after_length + lcu.unit_length
                    lcu_index += 1
                self._emitline('    Offset   Begin            End              Expression')
            self._dump_loclist(loc_list, line_template, cu_map)

    def _dump_loclist(self, loc_list, line_template, cu_map):
        in_views = False
        has_views = False
        base_ip = None
        loc_entry_count = 0
        cu = None
        for entry in loc_list:
            if isinstance(entry, LocationViewPair):
                has_views = in_views = True
                # The "v" before address is conditional in binutils, haven't figured out how
                self._emitline("    %08x v%015x v%015x location view pair" % (entry.entry_offset, entry.begin, entry.end))
            else:
                if in_views:
                    in_views = False
                    self._emitline("")

                # Readelf quirk: indexed loclists don't show the real base IP
                if cu_map is None:
                    base_ip = 0
                elif cu is None:
                    cu = cu_map.get(entry.entry_offset, False)
                    if not cu:
                        raise ValueError("Location list can't be tracked to a CU")

                if isinstance(entry, LocationEntry):
                    if base_ip is None and not entry.is_absolute:
                        base_ip = _get_cu_base(cu)

                    begin_offset = (0 if entry.is_absolute else base_ip) + entry.begin_offset
                    end_offset = (0 if entry.is_absolute else base_ip) + entry.end_offset
                    expr = describe_DWARF_expr(entry.loc_expr, cu.structs, cu.cu_offset)
                    if has_views:
                        view = loc_list[loc_entry_count]
                        postfix = ' (start == end)' if entry.begin_offset == entry.end_offset and view.begin == view.end else ''
                        self._emitline('    %08x v%015x v%015x views at %08x for:' %(
                            entry.entry_offset,
                            view.begin,
                            view.end,
                            view.entry_offset))
                        self._emitline('             %016x %016x %s%s' %(
                            begin_offset,
                            end_offset,
                            expr,
                            postfix))
                        loc_entry_count += 1
                    else:
                        postfix = ' (start == end)' if entry.begin_offset == entry.end_offset else ''
                        self._emitline(line_template % (
                            entry.entry_offset,
                            begin_offset,
                            end_offset,
                            expr,
                            postfix))
                elif isinstance(entry, LocBaseAddressEntry):
                    base_ip = entry.base_address
                    self._emitline("    %08x %016x (base address)" % (entry.entry_offset, entry.base_address))

        # Pyelftools doesn't store the terminating entry,
        # but readelf emits its offset, so this should too.
        last = loc_list[-1]
        self._emitline("    %08x <End of list>" % (last.entry_offset + last.entry_length))

    def _dump_debug_loclists_CU_header(self, cu):
        # Header slightly different from that of v5 rangelist in-section CU header dump
        self._emitline('Table at Offset %s' % self._format_hex(cu.cu_offset, alternate=True))
        self._emitline('  Length:          %s' % self._format_hex(cu.unit_length, alternate=True))
        self._emitline('  DWARF version:   %d' % cu.version)
        self._emitline('  Address size:    %d' % cu.address_size)
        self._emitline('  Segment size:    %d' % cu.segment_selector_size)
        self._emitline('  Offset entries:  %d\n' % cu.offset_count)
        if cu.offsets and len(cu.offsets):
            self._emitline('  Offsets starting at 0x%x:' % cu.offset_table_offset)
            for i_offset in enumerate(cu.offsets):
                self._emitline('    [%6d] 0x%x' % i_offset)        

    def _dump_debug_ranges(self):
        # TODO: GNU readelf format doesn't need entry_length?
        di = self._dwarfinfo
        range_lists_sec = di.range_lists()
        if not range_lists_sec: # No ranges section - readelf outputs nothing
            return

        if isinstance(range_lists_sec, RangeListsPair):
            self._dump_debug_rangesection(di, range_lists_sec._ranges)
            self._dump_debug_rangesection(di, range_lists_sec._rnglists)
        else:
            self._dump_debug_rangesection(di, range_lists_sec)

    def _dump_debug_rnglists_CU_header(self, cu):
        self._emitline(' Table at Offset: %s:' % self._format_hex(cu.cu_offset, alternate=True))
        self._emitline('  Length:          %s' % self._format_hex(cu.unit_length, alternate=True))
        self._emitline('  DWARF version:   %d' % cu.version)
        self._emitline('  Address size:    %d' % cu.address_size)
        self._emitline('  Segment size:    %d' % cu.segment_selector_size)
        self._emitline('  Offset entries:  %d\n' % cu.offset_count)
        if cu.offsets and len(cu.offsets):
            self._emitline('  Offsets starting at 0x%x:' % cu.offset_table_offset)
            for i_offset in enumerate(cu.offsets):
                self._emitline('    [%6d] 0x%x' % i_offset)

    def _dump_debug_rangesection(self, di, range_lists_sec):
        # Last amended to match readelf 2.41
        ver5 = range_lists_sec.version >= 5
        section_name = (di.debug_rnglists_sec if ver5 else di.debug_ranges_sec).name
        addr_size = di.config.default_address_size # In bytes, 4 or 8
        addr_width = addr_size * 2 # In hex digits, 8 or 16
        line_template = "    %%08x %%0%dx %%0%dx %%s" % (addr_width, addr_width)
        base_template = "    %%08x %%0%dx (base address)" % (addr_width)
        base_template_indexed = "    %%08x %%0%dx (base address index) %%0%dx (base address)" % (addr_width, addr_width)

        # In order to determine the base address of the range
        # We need to know the corresponding CU.
        cu_map = {die.attributes['DW_AT_ranges'].value : cu  # Range list offset => CU
            for cu in di.iter_CUs()
            for die in cu.iter_DIEs()
            if 'DW_AT_ranges' in die.attributes}
        
        rcus = list(range_lists_sec.iter_CUs()) if ver5 else None
        rcu_index = 0
        next_rcu_offset = 0

        range_lists = list(range_lists_sec.iter_range_lists())
        if len(range_lists) == 0:
            # Present but empty ranges section - readelf outputs a message
            self._emitline("\nSection '%s' has no debugging data." % section_name)
            return

        self._emitline('Contents of the %s section:\n\n\n' % section_name)
        if not ver5:
            self._emitline('    Offset   Begin    End')

        for range_list in range_lists:
            # Emit CU headers before the curernt rangelist
            if ver5 and range_list[0].entry_offset > next_rcu_offset:
                while range_list[0].entry_offset > next_rcu_offset:
                    rcu = rcus[rcu_index]
                    self._dump_debug_rnglists_CU_header(rcu)
                    next_rcu_offset = rcu.offset_after_length + rcu.unit_length
                    rcu_index += 1
                self._emitline('    Offset   Begin    End')
            self._dump_rangelist(range_list, cu_map, ver5, line_template, base_template, base_template_indexed, range_lists_sec)

        # TODO: trailing empty CUs, if any?

    def _dump_rangelist(self, range_list, cu_map, ver5, line_template, base_template, base_template_indexed, range_lists_sec):
        # Weird discrepancy in binutils: for DWARFv5 it outputs entry offset,
        # for DWARF<=4 list offset.
        first = range_list[0]
        base_ip = _get_cu_base(cu_map[first.entry_offset])
        raw_v5_rangelist = None
        for entry in range_list:
            if isinstance(entry, RangeEntry):
                postfix = ' (start == end)' if entry.begin_offset == entry.end_offset else ''
                self._emitline(line_template % (
                    entry.entry_offset if ver5 else first.entry_offset,
                    (0 if entry.is_absolute else base_ip) + entry.begin_offset,
                    (0 if entry.is_absolute else base_ip) + entry.end_offset,
                    postfix))
            elif isinstance(entry,RangeBaseAddressEntry):
                base_ip = entry.base_address
                # V5 base entries with index are reported differently in readelf - need to go back to the raw V5 format
                # Maybe other subtypes too, but no such cases  in the test corpus
                raw_v5_entry = None
                if ver5:
                    if not raw_v5_rangelist:
                        raw_v5_rangelist = range_lists_sec.get_range_list_at_offset_ex(range_list[0].entry_offset)
                    raw_v5_entry = next(re for re in raw_v5_rangelist if re.entry_offset == entry.entry_offset)
                if raw_v5_entry and raw_v5_entry.entry_type == 'DW_RLE_base_addressx':
                    self._emitline(base_template_indexed % (
                        entry.entry_offset,
                        raw_v5_entry.index,
                        entry.base_address))
                else:
                    self._emitline(base_template % (
                        entry.entry_offset if ver5 else first.entry_offset,
                        entry.base_address))
            else:
                raise NotImplementedError("Unknown object in a range list")
        last = range_list[-1]
        self._emitline('    %08x <End of list>' % (last.entry_offset + last.entry_length if ver5 else first.entry_offset))

    def _display_attributes(self, attr_sec, descriptor):
        """ Display the attributes contained in the section.
        """
        for s in attr_sec.iter_subsections():
            self._emitline("Attribute Section: %s" % s.header['vendor_name'])
            for ss in s.iter_subsubsections():
                h_val = "" if ss.header.extra is None else " ".join("%d" % x for x in ss.header.extra)
                self._emitline(descriptor(ss.header.tag, h_val, None))

                for attr in ss.iter_attributes():
                    self._emit('  ')
                    self._emitline(descriptor(attr.tag, attr.value, attr.extra))

    def _display_arch_specific_arm(self):
        """ Display the ARM architecture-specific info contained in the file.
        """
        attr_sec = self.elffile.get_section_by_name('.ARM.attributes')
        self._display_attributes(attr_sec, describe_attr_tag_arm)

    def _display_arch_specific_riscv(self):
        """ Display the RISC-V architecture-specific info contained in the file.
        """
        attr_sec = self.elffile.get_section_by_name('.riscv.attributes')
        self._display_attributes(attr_sec, describe_attr_tag_riscv)

    def _emit(self, s=''):
        """ Emit an object to output
        """
        self.output.write(str(s))

    def _emitline(self, s=''):
        """ Emit an object to output, followed by a newline
        """
        self.output.write(str(s).rstrip() + '\n')


SCRIPT_DESCRIPTION = 'Display information about the contents of ELF format files'
VERSION_STRING = '%%(prog)s: based on pyelftools %s' % __version__


def main(stream=None):
    # parse the command-line arguments and invoke ReadElf
    argparser = argparse.ArgumentParser(
            usage='usage: %(prog)s [options] <elf-file>',
            description=SCRIPT_DESCRIPTION,
            add_help=False, # -h is a real option of readelf
            prog='readelf.py')
    argparser.add_argument('file',
            nargs='?', default=None,
            help='ELF file to parse')
    argparser.add_argument('-v', '--version',
            action='version', version=VERSION_STRING)
    argparser.add_argument('-d', '--dynamic',
            action='store_true', dest='show_dynamic_tags',
            help='Display the dynamic section')
    argparser.add_argument('-H', '--help',
            action='store_true', dest='help',
            help='Display this information')
    argparser.add_argument('-h', '--file-header',
            action='store_true', dest='show_file_header',
            help='Display the ELF file header')
    argparser.add_argument('-l', '--program-headers', '--segments',
            action='store_true', dest='show_program_header',
            help='Display the program headers')
    argparser.add_argument('-S', '--section-headers', '--sections',
            action='store_true', dest='show_section_header',
            help="Display the sections' headers")
    argparser.add_argument('-e', '--headers',
            action='store_true', dest='show_all_headers',
            help='Equivalent to: -h -l -S')
    argparser.add_argument('-s', '--symbols', '--syms',
            action='store_true', dest='show_symbols',
            help='Display the symbol table')
    argparser.add_argument('-n', '--notes',
            action='store_true', dest='show_notes',
            help='Display the core notes (if present)')
    argparser.add_argument('-r', '--relocs',
            action='store_true', dest='show_relocs',
            help='Display the relocations (if present)')
    argparser.add_argument('-au', '--arm-unwind',
            action='store_true', dest='show_arm_unwind',
            help='Display the armeabi unwind information (if present)')
    argparser.add_argument('-x', '--hex-dump',
            action='store', dest='show_hex_dump', metavar='<number|name>',
            help='Dump the contents of section <number|name> as bytes')
    argparser.add_argument('-p', '--string-dump',
            action='store', dest='show_string_dump', metavar='<number|name>',
            help='Dump the contents of section <number|name> as strings')
    argparser.add_argument('-V', '--version-info',
            action='store_true', dest='show_version_info',
            help='Display the version sections (if present)')
    argparser.add_argument('-A', '--arch-specific',
            action='store_true', dest='show_arch_specific',
            help='Display the architecture-specific information (if present)')
    argparser.add_argument('--debug-dump',
            action='store', dest='debug_dump_what', metavar='<what>',
            help=(
                'Display the contents of DWARF debug sections. <what> can ' +
                'one of {info,decodedline,frames,frames-interp,aranges,pubtypes,pubnames,loc,Ranges}'))
    argparser.add_argument('--traceback',
                           action='store_true', dest='show_traceback',
                           help='Dump the Python traceback on ELFError'
                                ' exceptions from elftools')

    args = argparser.parse_args()

    if args.help or not args.file:
        argparser.print_help()
        sys.exit(0)

    if args.show_all_headers:
        do_file_header = do_section_header = do_program_header = True
    else:
        do_file_header = args.show_file_header
        do_section_header = args.show_section_header
        do_program_header = args.show_program_header

    with open(args.file, 'rb') as file:
        try:
            readelf = ReadElf(file, stream or sys.stdout)
            if do_file_header:
                readelf.display_file_header()
            if do_section_header:
                readelf.display_section_headers(
                        show_heading=not do_file_header)
            if do_program_header:
                readelf.display_program_headers(
                        show_heading=not do_file_header)
            if args.show_dynamic_tags:
                readelf.display_dynamic_tags()
            if args.show_symbols:
                readelf.display_symbol_tables()
            if args.show_notes:
                readelf.display_notes()
            if args.show_relocs:
                readelf.display_relocations()
            if args.show_arm_unwind:
                readelf.display_arm_unwind()
            if args.show_version_info:
                readelf.display_version_info()
            if args.show_arch_specific:
                readelf.display_arch_specific()
            if args.show_hex_dump:
                readelf.display_hex_dump(args.show_hex_dump)
            if args.show_string_dump:
                readelf.display_string_dump(args.show_string_dump)
            if args.debug_dump_what:
                readelf.display_debug_dump(args.debug_dump_what)
        except ELFError as ex:
            sys.stdout.flush()
            sys.stderr.write('ELF error: %s\n' % ex)
            if args.show_traceback:
                traceback.print_exc()
            sys.exit(1)


def profile_main():
    # Run 'main' redirecting its output to readelfout.txt
    # Saves profiling information in readelf.profile
    PROFFILE = 'readelf.profile'
    import cProfile
    cProfile.run('main(open("readelfout.txt", "w"))', PROFFILE)

    # Dig in some profiling stats
    import pstats
    p = pstats.Stats(PROFFILE)
    p.sort_stats('cumulative').print_stats(25)


#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
    #profile_main()
