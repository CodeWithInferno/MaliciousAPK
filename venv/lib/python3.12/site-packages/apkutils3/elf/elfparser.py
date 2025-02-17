from typing import List, NamedTuple, Optional, TextIO, Union
import zipfile
import io
import binascii
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from elftools.elf.sections import Section

from ..custom_typing import ElfDynsymData

try:
    from elftools.common.py3compat import byte2int  # type: ignore
except ImportError:
    try:
        from elftools.common import byte2int  # type: ignore
    except:
        from elftools.construct.lib.py3compat import byte2int  # type: ignore

from cigam import Magic


class ELF:
    def __init__(self, file_path: str):
        if Magic(file_path).get_type() != "elf":
            return

        self.elf_data: io.BufferedReader = open(file_path, "rb")
        self.elf_file: ELFFile = ELFFile(self.elf_data)

    def close(self) -> None:
        self.elf_data.close()

    def get_dynsym_datas(self, skip_import: bool = True) -> List[ElfDynsymData]:
        dynsym_datas: List[ElfDynsymData] = []

        symbol_table = self.elf_file.get_section_by_name(".dynsym")
        if not symbol_table:
            return dynsym_datas
        for symbol in symbol_table.iter_symbols():  # type: ignore
            if (
                skip_import
                and symbol.entry.st_size == 0
                or symbol.entry.st_info.type != "STT_FUNC"
            ):
                continue

            self.elf_data.seek(0)
            symbol_addr = symbol.entry.st_value & 0xFFFE
            self.elf_data.seek(symbol_addr)
            symbol_hexs = ""

            size = symbol.entry.st_size
            if symbol.entry.st_size > 80:
                size = 80

            for x in self.elf_data.read(size):
                op = str(hex(x)).upper()[2:]
                if len(op) == 1:
                    op = "0" + op
                symbol_hexs = symbol_hexs + op

            dynsym_datas.append(
                ElfDynsymData(symbol.name, hex(symbol_addr), symbol_hexs)
            )

        return dynsym_datas

    def get_rodata_strings(self) -> Optional[List[str]]:
        try:
            return self.display_string_dump(".rodata")
        except ELFError as ex:
            print("ELF error: %s\n" % ex)

    def display_string_dump(self, section_spec: str) -> Optional[List[str]]:
        """Display a strings dump of a section. section_spec is either a
        section number or a name.
        """
        section = self._section_from_spec(section_spec)
        if section is None:
            print("Section '%s' does not exist in the file!" % section_spec)
            return None

        data = section.data()
        dataptr = 0

        strs: List[str] = []
        while dataptr < len(data):
            while dataptr < len(data) and not 32 <= byte2int(data[dataptr]) <= 127:
                dataptr += 1

            if dataptr >= len(data):
                break

            endptr = dataptr
            while endptr < len(data) and byte2int(data[endptr]) != 0:
                endptr += 1

            strs.append(binascii.b2a_hex(data[dataptr:endptr]).decode().upper())
            dataptr = endptr

        return strs

    def _section_from_spec(self, spec: Union[str, int]) -> Optional[Section]:
        """
        Retrieve a section given a "spec" (either number or name).
        Return None if no such section exists in the file.
        """
        try:
            num = int(spec)
            if num < self.elf_file.num_sections():
                return self.elf_file.get_section(num)
            else:
                return None
        except ValueError:
            # Not a number. Must be a name then
            return self.elf_file.get_section_by_name(spec)


class ElfFileType(NamedTuple):
    name: str
    elf_data: io.BytesIO
    elf_file: ELFFile


def get_elf_files(apk_path: str) -> List[ElfFileType]:
    files = list()
    if zipfile.is_zipfile(apk_path):
        try:
            with zipfile.ZipFile(apk_path, mode="r") as zf:
                for name in zf.namelist():
                    try:
                        data = zf.read(name)

                        mime = Magic(data).get_type()
                        if mime == "elf":
                            elf_data = io.BytesIO(data)
                            elf_file = ELFFile(elf_data)
                            files.append((name, elf_data, elf_file))
                    except Exception as ex:
                        continue

        except Exception as ex:
            raise ex

    return files
