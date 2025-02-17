from struct import pack, unpack
import collections
from typing import Any, Dict, List, Optional, Self, Set, Tuple, TypedDict, Union

from .chunk import BuffHandle, StringPoolChunk

# RES_NULL_TYPE = 0x0000
# RES_STRING_POOL_TYPE = 0x0001
# RES_TABLE_TYPE = 0x0002
# RES_XML_TYPE = 0x0003
#
# # Chunk types in RES_XML_TYPE
# RES_XML_FIRST_CHUNK_TYPE = 0x0100
# RES_XML_START_NAMESPACE_TYPE = 0x0100
# RES_XML_END_NAMESPACE_TYPE = 0x0101
# RES_XML_START_ELEMENT_TYPE = 0x0102
# RES_XML_END_ELEMENT_TYPE = 0x0103
# RES_XML_CDATA_TYPE = 0x0104
# RES_XML_LAST_CHUNK_TYPE = 0x017f
#
# # This contains a uint32_t array mapping strings in the string
# # pool back to resource identifiers.  It is optional.
# RES_XML_RESOURCE_MAP_TYPE = 0x0180
#
# Chunk types in RES_TABLE_TYPE
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202

TYPE_ATTRIBUTE = 2
TYPE_DIMENSION = 5
TYPE_FIRST_COLOR_INT = 28
TYPE_FIRST_INT = 16
TYPE_FLOAT = 4
TYPE_FRACTION = 6
TYPE_INT_BOOLEAN = 18
TYPE_INT_COLOR_ARGB4 = 30
TYPE_INT_COLOR_ARGB8 = 28
TYPE_INT_COLOR_RGB4 = 31
TYPE_INT_COLOR_RGB8 = 29
TYPE_INT_DEC = 16
TYPE_INT_HEX = 17
TYPE_LAST_COLOR_INT = 31
TYPE_LAST_INT = 31
TYPE_NULL = 0
TYPE_REFERENCE = 1
TYPE_STRING = 3

TYPE_TABLE = {
    TYPE_ATTRIBUTE: "attribute",
    TYPE_DIMENSION: "dimension",
    TYPE_FLOAT: "float",
    TYPE_FRACTION: "fraction",
    TYPE_INT_BOOLEAN: "int_boolean",
    TYPE_INT_COLOR_ARGB4: "int_color_argb4",
    TYPE_INT_COLOR_ARGB8: "int_color_argb8",
    TYPE_INT_COLOR_RGB4: "int_color_rgb4",
    TYPE_INT_COLOR_RGB8: "int_color_rgb8",
    TYPE_INT_DEC: "int_dec",
    TYPE_INT_HEX: "int_hex",
    TYPE_NULL: "null",
    TYPE_REFERENCE: "reference",
    TYPE_STRING: "string",
}


class StringResourceTypedDict(TypedDict):
    name: str
    value: str


def getPackage(i) -> str:
    if i >> 24 == 1:
        return "android:"
    raise NotImplementedError("Package identifier %d unknown" % i >> 24)
    return ""


def format_value(_type: int, _data, lookup_string=lambda ix: "<string>") -> Any:
    if _type == TYPE_STRING:
        return lookup_string(_data)

    elif _type == TYPE_ATTRIBUTE:
        return "?%s%08X" % (getPackage(_data), _data)

    elif _type == TYPE_REFERENCE:
        return "@%s%08X" % (getPackage(_data), _data)

    elif _type == TYPE_FLOAT:
        return "%f" % unpack("=f", pack("=L", _data))[0]

    elif _type == TYPE_INT_HEX:
        return "0x%08X" % _data

    elif _type == TYPE_INT_BOOLEAN:
        if _data == 0:
            return "false"
        return "true"

    elif _type == TYPE_DIMENSION:
        return "%f%s" % (
            complexToFloat(_data),
            DIMENSION_UNITS[_data & COMPLEX_UNIT_MASK],
        )

    elif _type == TYPE_FRACTION:
        return "%f%s" % (
            complexToFloat(_data) * 100,
            FRACTION_UNITS[_data & COMPLEX_UNIT_MASK],
        )

    elif _type >= TYPE_FIRST_COLOR_INT and _type <= TYPE_LAST_COLOR_INT:
        return "#%08X" % _data

    elif _type >= TYPE_FIRST_INT and _type <= TYPE_LAST_INT:
        return "%d" % int(_data)

    return "<0x%X, type 0x%02X>" % (_data, _type)


RADIX_MULTS = [0.00390625, 3.051758e-005, 1.192093e-007, 4.656613e-010]
DIMENSION_UNITS = ["px", "dip", "sp", "pt", "in", "mm"]
FRACTION_UNITS = ["%", "%p"]

COMPLEX_UNIT_MASK = 15


def complexToFloat(xcomplex) -> float:
    return (float)(xcomplex & 0xFFFFFF00) * RADIX_MULTS[(xcomplex >> 4) & 3]


class ARSCParser:
    def __init__(self, raw_buff: bytes):
        self.analyzed: bool = False
        self._resolved_strings = None
        self.buff = BuffHandle(raw_buff)

        self.header = ARSCHeader(self.buff)
        self.packageCount: int = unpack("<i", self.buff.read(4))[0]

        self.stringpool_main = StringPoolChunk(self.buff)

        self.next_header = ARSCHeader(self.buff)
        self.packages: Dict[
            str,
            List[
                Union[
                    StringPoolChunk,
                    ARSCResTablePackage,
                    ARSCHeader,
                    ARSCResTypeSpec,
                    ARSCResType,
                    ARSCResTableEntry,
                    List[Tuple[int, int]],
                ]
            ],
        ] = {}
        # one more shit lol
        self.values: Dict[str, Dict[str, Any]] = {}
        self.resource_values: collections.defaultdict[
            int, dict
        ] = collections.defaultdict(dict)
        self.resource_configs: collections.defaultdict[
            str, collections.defaultdict[ARSCResType, Set[ARSCResTableConfig]]
        ] = collections.defaultdict(lambda: collections.defaultdict(set))
        self.resource_keys: collections.defaultdict[
            str,
            collections.defaultdict[
                str,
                collections.defaultdict[str, int],
            ],
        ] = collections.defaultdict(
            lambda: collections.defaultdict(collections.defaultdict)
        )

        for i in range(0, self.packageCount):
            current_package = ARSCResTablePackage(self.buff)
            package_name = current_package.get_name()

            self.packages[package_name] = []

            mTableStrings = StringPoolChunk(self.buff)
            mKeyStrings = StringPoolChunk(self.buff)

            self.packages[package_name].append(current_package)
            self.packages[package_name].append(mTableStrings)
            self.packages[package_name].append(mKeyStrings)

            pc = PackageContext(
                current_package, self.stringpool_main, mTableStrings, mKeyStrings
            )

            current = self.buff.get_idx()
            while not self.buff.end():
                header = ARSCHeader(self.buff)
                self.packages[package_name].append(header)

                if header.type == RES_TABLE_TYPE_SPEC_TYPE:
                    self.packages[package_name].append(ARSCResTypeSpec(self.buff, pc))

                elif header.type == RES_TABLE_TYPE_TYPE:
                    a_res_type = ARSCResType(self.buff, pc)
                    self.packages[package_name].append(a_res_type)
                    self.resource_configs[package_name][a_res_type].add(
                        a_res_type.config
                    )

                    entries: List[Tuple[int, int]] = []
                    for j in range(0, a_res_type.entryCount):
                        current_package.mResId = current_package.mResId & 0xFFFF0000 | j
                        entries.append(
                            (unpack("<i", self.buff.read(4))[0], current_package.mResId)
                        )

                    self.packages[package_name].append(entries)

                    for entry, res_id in entries:
                        if self.buff.end():
                            break

                        if entry != -1:
                            ate = ARSCResTableEntry(self.buff, res_id, pc)
                            self.packages[package_name].append(ate)

                elif header.type == RES_TABLE_PACKAGE_TYPE:
                    break
                else:
                    print("unknown type")
                    break

                current += header.size
                self.buff.set_idx(current)

    def _analyse(self) -> None:
        if self.analyzed:
            return

        self.analyzed = True

        for package_name in self.packages:
            self.values[package_name] = {}

            nb = 3
            while nb < len(self.packages[package_name]):
                header = self.packages[package_name][nb]
                if isinstance(header, ARSCHeader):
                    if header.type == RES_TABLE_TYPE_TYPE:
                        a_res_type: ARSCResType = self.packages[package_name][nb + 1]  # type: ignore

                        if (
                            a_res_type.config.get_language()
                            not in self.values[package_name]
                        ):
                            self.values[package_name][
                                a_res_type.config.get_language()
                            ] = {}
                            self.values[package_name][a_res_type.config.get_language()][
                                "public"
                            ] = []

                        c_value = self.values[package_name][
                            a_res_type.config.get_language()
                        ]

                        entries = self.packages[package_name][nb + 2]
                        nb_i = 0
                        for entry, res_id in entries:  # type: ignore
                            if entry != -1:
                                ate: ARSCResTableEntry = self.packages[package_name][  # type: ignore
                                    nb + 3 + nb_i
                                ]

                                self.resource_values[ate.mResId][
                                    a_res_type.config
                                ] = ate
                                self.resource_keys[package_name][a_res_type.get_type()][
                                    ate.get_value()
                                ] = ate.mResId

                                if ate.get_index() != -1:
                                    c_value["public"].append(
                                        (
                                            a_res_type.get_type(),
                                            ate.get_value(),
                                            ate.mResId,
                                        )
                                    )

                                if a_res_type.get_type() not in c_value:
                                    c_value[a_res_type.get_type()] = []

                                if a_res_type.get_type() == "string":
                                    c_value["string"].append(
                                        self.get_resource_string(ate)
                                    )

                                elif a_res_type.get_type() == "id":
                                    if not ate.is_complex():
                                        c_value["id"].append(self.get_resource_id(ate))

                                elif a_res_type.get_type() == "bool":
                                    if not ate.is_complex():
                                        c_value["bool"].append(
                                            self.get_resource_bool(ate)
                                        )

                                elif a_res_type.get_type() == "integer":
                                    c_value["integer"].append(
                                        self.get_resource_integer(ate)
                                    )

                                elif a_res_type.get_type() == "color":
                                    c_value["color"].append(
                                        self.get_resource_color(ate)
                                    )

                                elif a_res_type.get_type() == "dimen":
                                    c_value["dimen"].append(
                                        self.get_resource_dimen(ate)
                                    )

                                nb_i += 1
                        nb += (
                            3 + nb_i - 1
                        )  # -1 to account for the nb+=1 on the next line
                nb += 1

    def get_resource_string(self, ate: "ARSCResTableEntry") -> List[str]:
        return [ate.get_value(), ate.get_key_data()]

    def get_resource_id(self, ate: "ARSCResTableEntry") -> List[str]:
        x = [ate.get_value()]
        if ate.key.get_data() == 0:
            x.append("false")
        elif ate.key.get_data() == 1:
            x.append("true")
        return x

    def get_resource_bool(self, ate: "ARSCResTableEntry") -> List[str]:
        x = [ate.get_value()]
        if ate.key.get_data() == 0:
            x.append("false")
        elif ate.key.get_data() == -1:
            x.append("true")
        return x

    def get_resource_integer(self, ate: "ARSCResTableEntry") -> List[Union[str, int]]:
        return [ate.get_value(), ate.key.get_data()]

    def get_resource_color(self, ate: "ARSCResTableEntry") -> List[Union[int, str]]:
        entry_data = ate.key.get_data()
        return [
            ate.get_value(),
            "#%02x%02x%02x%02x"
            % (
                ((entry_data >> 24) & 0xFF),
                ((entry_data >> 16) & 0xFF),
                ((entry_data >> 8) & 0xFF),
                (entry_data & 0xFF),
            ),
        ]

    def get_resource_dimen(self, ate: "ARSCResTableEntry") -> List[Union[int, str]]:
        try:
            return [
                ate.get_value(),
                "%s%s"
                % (
                    complexToFloat(ate.key.get_data()),
                    DIMENSION_UNITS[ate.key.get_data() & COMPLEX_UNIT_MASK],
                ),
            ]
        except IndexError:
            return [ate.get_value(), ate.key.get_data()]

    # FIXME
    def get_resource_style(self, ate: "ARSCResTableEntry"):
        raise NotImplementedError()
        return ["", ""]

    def get_packages_names(self) -> List[str]:
        return list(self.packages.keys())

    def get_locales(self, package_name: str) -> List[str]:
        self._analyse()
        return list(self.values[package_name].keys())

    def get_types(self, package_name: str, locale: str) -> List[str]:
        self._analyse()
        return list(self.values[package_name][locale].keys())

    def get_public_resources(
        self, package_name: str, locale: str = "\x00\x00"
    ) -> bytes:
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += "<resources>\n"

        try:
            for i in self.values[package_name][locale]["public"]:
                buff += '<public type="%s" name="%s" id="0x%08x" />\n' % (
                    i[0],
                    i[1],
                    i[2],
                )
        except KeyError:
            pass

        buff += "</resources>\n"

        return buff.encode("utf-8")

    def get_string_resources(
        self, package_name: str, locale: str = "\x00\x00"
    ) -> List[StringResourceTypedDict]:
        self._analyse()

        res: List[StringResourceTypedDict] = []

        # buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        # buff += "<resources>\n"

        try:
            import binascii

            for i in self.values[package_name][locale]["string"]:
                item: StringResourceTypedDict = {
                    "name": i[0],
                    "value": binascii.hexlify(i[1].encode("utf-8")).decode(),
                }
                res.append(item)
        except KeyError:
            pass

        return res

    def get_strings_resources(self) -> bytes:
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'

        buff += "<packages>\n"
        for package_name in self.get_packages_names():
            # holy shit.
            buff += '<package name="%s">\n' % package_name

            for locale in self.get_locales(package_name):
                buff += "<locale value=%s>\n" % repr(locale)

                buff += "<resources>\n"
                try:
                    for i in self.values[package_name][locale]["string"]:
                        buff += '<string name="%s">%s</string>\n' % (i[0], i[1])
                except KeyError:
                    pass

                buff += "</resources>\n"
                buff += "</locale>\n"

            buff += "</package>\n"

        buff += "</packages>\n"

        return buff.encode("utf-8")

    def get_id_resources(self, package_name: str, locale: str = "\x00\x00") -> bytes:
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += "<resources>\n"

        try:
            for i in self.values[package_name][locale]["id"]:
                if len(i) == 1:
                    buff += '<item type="id" name="%s"/>\n' % (i[0])
                else:
                    buff += '<item type="id" name="%s">%s</item>\n' % (i[0], i[1])
        except KeyError:
            pass

        buff += "</resources>\n"

        return buff.encode("utf-8")

    def get_bool_resources(self, package_name: str, locale: str = "\x00\x00") -> bytes:
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += "<resources>\n"

        try:
            for i in self.values[package_name][locale]["bool"]:
                buff += '<bool name="%s">%s</bool>\n' % (i[0], i[1])
        except KeyError:
            pass

        buff += "</resources>\n"

        return buff.encode("utf-8")

    def get_integer_resources(
        self, package_name: str, locale: str = "\x00\x00"
    ) -> bytes:
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += "<resources>\n"

        try:
            for i in self.values[package_name][locale]["integer"]:
                buff += '<integer name="%s">%s</integer>\n' % (i[0], i[1])
        except KeyError:
            pass

        buff += "</resources>\n"

        return buff.encode("utf-8")

    def get_color_resources(self, package_name: str, locale: str = "\x00\x00") -> bytes:
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += "<resources>\n"

        try:
            for i in self.values[package_name][locale]["color"]:
                buff += '<color name="%s">%s</color>\n' % (i[0], i[1])
        except KeyError:
            pass

        buff += "</resources>\n"

        return buff.encode("utf-8")

    def get_dimen_resources(self, package_name: str, locale: str = "\x00\x00") -> bytes:
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += "<resources>\n"

        try:
            for i in self.values[package_name][locale]["dimen"]:
                buff += '<dimen name="%s">%s</dimen>\n' % (i[0], i[1])
        except KeyError:
            pass

        buff += "</resources>\n"

        return buff.encode("utf-8")

    def get_id(
        self, package_name: str, rid: int, locale: str = "\x00\x00"
    ) -> Optional[Any]:
        self._analyse()

        try:
            for i in self.values[package_name][locale]["public"]:
                if i[2] == rid:
                    return i
        except KeyError:
            return None

    class ResourceResolver:
        def __init__(self, android_resources: "ARSCParser", config=None):
            self.resources = android_resources
            self.wanted_config = config

        def resolve(self, res_id: int) -> List[Tuple[Tuple[int, ...], Any]]:
            result: List[Tuple[Tuple[int, ...], Any]] = []
            self._resolve_into_result(result, res_id, self.wanted_config)
            return result

        def _resolve_into_result(self, result: List[Tuple[Tuple[int, ...], Any]], res_id: int, config):
            configs = self.resources.get_res_configs(res_id, config)
            if configs:
                for config, ate in configs:
                    self.put_ate_value(result, ate, config)

        def put_ate_value(self, result: List[Tuple[Tuple[int, ...], Any]], ate: "ARSCResTableEntry", config):
            if ate.is_complex():
                complex_array = []
                result.append((config, complex_array))
                for _, item in ate.item.items:
                    self.put_item_value(complex_array, item, config, complex_=True)
            else:
                self.put_item_value(result, ate.key, config, complex_=False)

        def put_item_value(self, result, item, config, complex_):
            if item.is_reference():
                res_id = item.get_data()
                if res_id:
                    self._resolve_into_result(
                        result, item.get_data(), self.wanted_config
                    )
            else:
                if complex_:
                    result.append(item.format_value())
                else:
                    result.append((config, item.format_value()))

    def get_resolved_res_configs(
        self, rid: int, config=None
    ) -> List[Tuple[Tuple[int, ...], Any]]:
        resolver = ARSCParser.ResourceResolver(self, config)
        return resolver.resolve(rid)

    def get_resolved_strings(self):
        self._analyse()
        if self._resolved_strings:
            return self._resolved_strings

        r = {}
        for package_name in self.get_packages_names():
            r[package_name] = {}
            k = {}

            for locale in self.values[package_name]:
                v_locale = locale
                if v_locale == "\x00\x00":
                    v_locale = "DEFAULT"

                r[package_name][v_locale] = {}

                try:
                    for i in self.values[package_name][locale]["public"]:
                        if i[0] == "string":
                            r[package_name][v_locale][i[2]] = None
                            k[i[1]] = i[2]
                except KeyError:
                    pass

                try:
                    for i in self.values[package_name][locale]["string"]:
                        if i[0] in k:
                            r[package_name][v_locale][k[i[0]]] = i[1]
                except KeyError:
                    pass

        self._resolved_strings = r
        return r

    def get_res_configs(self, rid: int, config=None):
        self._analyse()

        if not rid:
            raise ValueError("'rid' should be set")

        try:
            res_options = self.resource_values[rid]
            if len(res_options) > 1 and config:
                return [(config, res_options[config])]
            else:
                return list(res_options.items())

        except KeyError:
            return []

    def get_string(
        self, package_name: str, name: str, locale: str = "\x00\x00"
    ) -> Optional[Tuple[str, str]]:
        """
        :return: (name, value)
        """
        self._analyse()

        try:
            for i in self.values[package_name][locale]["string"]:
                if i[0] == name:
                    return i
        except KeyError:
            return None

    def get_res_id_by_key(
        self, package_name: str, resource_type: str, key: str
    ) -> Optional[int]:
        try:
            return self.resource_keys[package_name][resource_type][key]
        except KeyError:
            return None

    def get_items(self, package_name: str):
        self._analyse()
        return self.packages[package_name]

    def get_type_configs(self, package_name: str, type_name=None):
        if package_name is None:
            package_name = self.get_packages_names()[0]
        result = collections.defaultdict(list)

        for res_type, configs in list(self.resource_configs[package_name].items()):
            if res_type.get_package_name() == package_name and (
                type_name is None or res_type.get_type() == type_name
            ):
                result[res_type.get_type()].extend(configs)

        return result


class PackageContext:
    def __init__(
        self,
        current_package: "ARSCResTablePackage",
        stringpool_main: StringPoolChunk,
        mTableStrings: StringPoolChunk,
        mKeyStrings: StringPoolChunk,
    ):
        self.stringpool_main = stringpool_main
        self.mTableStrings = mTableStrings
        self.mKeyStrings = mKeyStrings
        self.current_package = current_package

    def get_mResId(self) -> int:
        return self.current_package.mResId

    def set_mResId(self, mResId: int) -> None:
        self.current_package.mResId = mResId

    def get_package_name(self) -> str:
        return self.current_package.get_name()


class ARSCHeader:
    def __init__(self, buff: BuffHandle):
        self.start = buff.get_idx()
        # 解析String Pool时，有可能少解析4byte
        self.type = -1
        while True:
            if self.type > -1:
                break
            tmp = buff.read(2)
            self.type: int = unpack("<h", tmp)[0]

        self.header_size: int = unpack("<h", buff.read(2))[0]
        # 文件大小
        self.size: int = unpack("<I", buff.read(4))[0]

        # print("ARSC Header:")
        # print(' - type:', self.type)
        # print(' - header_size:', self.header_size)
        # print(' - size: ', self.size)


class ARSCResTablePackage:
    """
    解析Package Header
    """

    def __init__(self, buff: BuffHandle):
        self.start: int = buff.get_idx()
        # package id
        self.id: int = unpack("<I", buff.read(4))[0]
        # package name
        self.name: bytes = buff.readNullString(256)
        # 资源类型 string pool 偏移
        self.typeStrings: int = unpack("<I", buff.read(4))[0]
        self.lastPublicType: int = unpack("<I", buff.read(4))[0]
        # 资源关键字 string pool 偏移
        self.keyStrings: int = unpack("<I", buff.read(4))[0]
        self.lastPublicKey: int = unpack("<I", buff.read(4))[0]
        self.mResId: int = self.id << 24

    def get_name(self) -> str:
        name = self.name.decode("utf-16", "replace")
        name = name[: name.find("\x00")]
        return name


class ARSCResTypeSpec:
    def __init__(self, buff: BuffHandle, parent: PackageContext):
        self.start = buff.get_idx()
        self.parent = parent
        self.id: int = unpack("<b", buff.read(1))[0]
        self.res0: int = unpack("<b", buff.read(1))[0]
        self.res1: int = unpack("<h", buff.read(2))[0]
        self.entryCount: int = unpack("<I", buff.read(4))[0]

        self.typespec_entries: List[int] = []
        for i in range(0, self.entryCount):
            self.typespec_entries.append(unpack("<I", buff.read(4))[0])


class ARSCResType:
    def __init__(self, buff: BuffHandle, parent: PackageContext):
        self.start: int = buff.get_idx()
        self.parent: PackageContext = parent
        self.id: int = unpack("<b", buff.read(1))[0]
        self.res0: int = unpack("<b", buff.read(1))[0]
        self.res1: int = unpack("<h", buff.read(2))[0]
        self.entryCount: int = unpack("<i", buff.read(4))[0]
        self.entriesStart: int = unpack("<i", buff.read(4))[0]
        self.mResId: int = (0xFF000000 & self.parent.get_mResId()) | self.id << 16
        self.parent.set_mResId(self.mResId)

        self.config: ARSCResTableConfig = ARSCResTableConfig(buff)

    def get_type(self) -> str:
        return self.parent.mTableStrings.getString(self.id - 1)

    def get_package_name(self) -> str:
        return self.parent.get_package_name()

    def __repr__(self) -> str:
        return "ARSCResType(%x, %x, %x, %x, %x, %x, %x, %s)" % (
            self.start,
            self.id,
            self.res0,
            self.res1,
            self.entryCount,
            self.entriesStart,
            self.mResId,
            "table:" + self.parent.mTableStrings.getString(self.id - 1),
        )


class ARSCResTableConfig:
    @classmethod
    def default_config(cls):
        if not hasattr(cls, "DEFAULT"):
            cls.DEFAULT = ARSCResTableConfig(None)
        return cls.DEFAULT

    def __init__(self, buff: Optional[BuffHandle] = None, **kwargs):
        if buff is not None:
            self.start = buff.get_idx()
            self.size: int = unpack("<I", buff.read(4))[0]
            self.imsi: int = unpack("<I", buff.read(4))[0]
            self.locale: int = unpack("<I", buff.read(4))[0]
            self.screenType: int = unpack("<I", buff.read(4))[0]
            self.input: int = unpack("<I", buff.read(4))[0]
            self.screenSize: int = unpack("<I", buff.read(4))[0]
            self.version: int = unpack("<I", buff.read(4))[0]

            self.screenConfig: int = 0
            self.screenSizeDp: int = 0

            if self.size >= 32:
                self.screenConfig: int = unpack("<I", buff.read(4))[0]

                if self.size >= 36:
                    self.screenSizeDp: int = unpack("<I", buff.read(4))[0]

            self.exceedingSize: int = self.size - 36
            if self.exceedingSize > 0:
                self.padding: bytes = buff.read(self.exceedingSize)
        else:
            self.start: int = 0
            self.size: int = 0
            self.imsi: int = ((kwargs.pop("mcc", 0) & 0xFFFF) << 0) + (
                (kwargs.pop("mnc", 0) & 0xFFFF) << 16
            )

            self.locale: int = 0
            for char_ix, char in kwargs.pop("locale", "")[0:4]:
                self.locale += ord(char) << (char_ix * 8)

            self.screenType: int = (
                ((kwargs.pop("orientation", 0) & 0xFF) << 0)
                + ((kwargs.pop("touchscreen", 0) & 0xFF) << 8)
                + ((kwargs.pop("density", 0) & 0xFFFF) << 16)
            )

            self.input: int = (
                ((kwargs.pop("keyboard", 0) & 0xFF) << 0)
                + ((kwargs.pop("navigation", 0) & 0xFF) << 8)
                + ((kwargs.pop("inputFlags", 0) & 0xFF) << 16)
                + ((kwargs.pop("inputPad0", 0) & 0xFF) << 24)
            )

            self.screenSize: int = ((kwargs.pop("screenWidth", 0) & 0xFFFF) << 0) + (
                (kwargs.pop("screenHeight", 0) & 0xFFFF) << 16
            )

            self.version: int = ((kwargs.pop("sdkVersion", 0) & 0xFFFF) << 0) + (
                (kwargs.pop("minorVersion", 0) & 0xFFFF) << 16
            )

            self.screenConfig: int = (
                ((kwargs.pop("screenLayout", 0) & 0xFF) << 0)
                + ((kwargs.pop("uiMode", 0) & 0xFF) << 8)
                + ((kwargs.pop("smallestScreenWidthDp", 0) & 0xFFFF) << 16)
            )

            self.screenSizeDp: int = (
                (kwargs.pop("screenWidthDp", 0) & 0xFFFF) << 0
            ) + ((kwargs.pop("screenHeightDp", 0) & 0xFFFF) << 16)

            self.exceedingSize: int = 0

    def get_language(self) -> str:
        x = self.locale & 0x0000FFFF
        return chr(x & 0x00FF) + chr((x & 0xFF00) >> 8)

    def get_country(self) -> str:
        x = (self.locale & 0xFFFF0000) >> 16
        return chr(x & 0x00FF) + chr((x & 0xFF00) >> 8)

    def get_density(self) -> int:
        x = (self.screenType >> 16) & 0xFFFF
        return x

    def _get_tuple(self) -> Tuple[int, int, int, int, int, int, int, int]:
        return (
            self.imsi,
            self.locale,
            self.screenType,
            self.input,
            self.screenSize,
            self.version,
            self.screenConfig,
            self.screenSizeDp,
        )

    def __hash__(self) -> int:
        return hash(self._get_tuple())

    def __eq__(self, other: Self) -> bool:
        return self._get_tuple() == other._get_tuple()

    def __repr__(self) -> str:
        return repr(self._get_tuple())


class ARSCResTableEntry:
    def __init__(self, buff: BuffHandle, mResId: int, parent: PackageContext):
        self.start: int = buff.get_idx()
        self.mResId: int = mResId
        self.parent: PackageContext = parent
        self.size: int = unpack("<H", buff.read(2))[0]
        self.flags: int = unpack("<H", buff.read(2))[0]
        self.index: int = unpack("<I", buff.read(4))[0]

        if self.flags & 1:
            self.item = ARSCComplex(buff, parent)
        else:
            self.key = ARSCResStringPoolRef(buff, self.parent)
            # incredibly shit

    def get_index(self) -> int:
        return self.index

    def get_value(self) -> str:
        return self.parent.mKeyStrings.getString(self.index)

    def get_key_data(self) -> str:
        return self.key.get_data_value()

    def is_public(self) -> bool:
        return self.flags == 0 or self.flags == 2

    def is_complex(self) -> bool:
        return (self.flags & 1) == 1

    def __repr__(self) -> str:
        return "ARSCResTableEntry(%x, %x, %x, %x, %x, %r)" % (
            self.start,
            self.mResId,
            self.size,
            self.flags,
            self.index,
            self.item if self.is_complex() else self.key,
        )


class ARSCComplex:
    def __init__(self, buff: BuffHandle, parent: PackageContext):
        self.start = buff.get_idx()
        self.parent = parent

        self.id_parent = unpack("<I", buff.read(4))[0]
        self.count = unpack("<I", buff.read(4))[0]

        self.items: List[Tuple[int, ARSCResStringPoolRef]] = []
        for i in range(0, self.count):
            self.items.append(
                (unpack("<I", buff.read(4))[0], ARSCResStringPoolRef(buff, self.parent))
            )

    def __repr__(self) -> str:
        return "ARSCComplex(%x, %d, %d)" % (self.start, self.id_parent, self.count)


class ARSCResStringPoolRef:
    def __init__(self, buff: BuffHandle, parent: PackageContext):
        self.start = buff.get_idx()
        self.parent = parent

        self.skip_bytes = buff.read(3)
        self.data_type: int = unpack("<B", buff.read(1))[0]
        self.data: int = unpack("<I", buff.read(4))[0]

    def get_data_value(self):
        return self.parent.stringpool_main.getString(self.data)

    def get_data(self) -> int:
        return self.data

    def get_data_type(self) -> int:
        return self.data_type

    def get_data_type_string(self) -> str:
        return TYPE_TABLE[self.data_type]

    def format_value(self) -> Any:
        return format_value(
            self.data_type, self.data, self.parent.stringpool_main.getString
        )

    def is_reference(self) -> bool:
        return self.data_type == TYPE_REFERENCE

    def __repr__(self) -> str:
        return "ARSCResStringPoolRef(%x, %s, %x)" % (
            self.start,
            TYPE_TABLE.get(self.data_type, "0x%x" % self.data_type),
            self.data,
        )
