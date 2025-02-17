from typing import Optional, TypedDict, NamedTuple


class ChildItem(TypedDict):
    name: str
    type: Optional[str]
    time: str
    crc: str


class OpCodeItem(TypedDict):
    super_class: str
    class_name: str
    method_name: str
    method_desc: str
    proto: str
    opcodes: str


class ElfDynsymData(NamedTuple):
    name: str
    addr: str
    hexs: str
