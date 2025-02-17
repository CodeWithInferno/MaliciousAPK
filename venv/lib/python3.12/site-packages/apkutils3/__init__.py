import binascii
from pathlib import Path
import re
from typing import Dict, Final, List, Optional, Set, Union, TYPE_CHECKING
import warnings
import xml
import xmltodict
from zipfile import ZipFile

from .consts import (
    MANIFEST_XMLTODICT_FORCE_LIST,
    NAME_ATTRIBUTE_NAME,
    RESOURCE_XMLTODICT_FORCE_LIST,
)
from .axml.arscparser import ARSCParser
from .axml.axmlparser import AXML

if TYPE_CHECKING:
    from .cert import CertType
from .custom_typing import ChildItem, OpCodeItem
from .dex.dexparser import DexFile
from .manifest import Manifest
from cigam import Magic

__version__ = "2.0.14"


def make_sth_a_list_if_it_is_not_a_list(sth) -> list:
    if isinstance(sth, list):
        return sth
    return [
        sth,
    ]


class APK:
    def __init__(self, apk_path: Union[str, Path]):
        self.apk_path: str = str(apk_path)
        self._dex_files: List[DexFile] = []
        self._files_in_apk: List[ChildItem] = []
        self._orig_manifest: str = ""
        self._strings: List[str] = []
        self._orig_strings: List[bytes] = []
        self._opcodes: List[OpCodeItem] = []
        self._certs: List[CertType] = []
        self._strings_refx: Optional[Dict[str, Dict[str, Set[bytes]]]] = None
        self._app_icon: Optional[str] = None
        self._app_icons: Set[str] = set()
        self._manifest: dict = {}
        self._app_name: Optional[str] = None
        self._arsc_parser: Optional[ARSCParser] = None
        self._home_activity: Optional[str] = None
        self._home_activities: List[str] = []
        self._activities: List[str] = []
        self._activity_alias: Dict[str, str] = {}
        self._libraries_for_arch: Dict[str, List[str]] = {}
        self._library_filenames: Set[str] = set()
        self._dex_classes_for_libchecker: Set[str] = set()
        self.zipfile: ZipFile = ZipFile(self.apk_path, mode="r")
        self.apk_namelist: List[str] = self.zipfile.namelist()

    @property
    def libraries(self) -> Dict[str, List[str]]:
        if not self._libraries_for_arch:
            self._init_libraries_for_arch()
        return self._libraries_for_arch

    @property
    def library_filenames(self) -> Set[str]:
        if not self._library_filenames:
            self._init_libraries_for_arch()
        return self._library_filenames

    def _init_libraries_for_arch(self) -> None:
        for name in self.apk_namelist:
            if name.startswith("lib/") and not name.endswith("/"):
                splits = name.split("/")
                # valid: lib/arm64-v8a/xxx.so
                if len(splits) != 3:
                    continue
                arch = splits[1]
                filename = splits[-1]
                self._libraries_for_arch.setdefault(arch, []).append(filename)
                self._library_filenames.add(filename)

    @property
    def is_jetpack_compose(self) -> bool:
        # https://github.com/LibChecker/LibChecker/blob/7b0cf85b5d959b763131e20fe49a721276b7ccf4/app/src/main/kotlin/com/absinthe/libchecker/utils/extensions/PackageInfoExtensions.kt#L375
        JETPACK_COMPOSE_FILES = (
            "META-INF/androidx.compose.runtime_runtime.version",
            "META-INF/androidx.compose.ui_ui.version",
            "META-INF/androidx.compose.ui_ui-tooling-preview.version",
            "META-INF/androidx.compose.foundation_foundation.version",
            "META-INF/androidx.compose.animation_animation.version",
        )
        for jetpack_file in self.apk_namelist:
            if jetpack_file in JETPACK_COMPOSE_FILES:
                return True
        return False

    @property
    def app_names(self) -> List[str]:
        """
        获取所有可能的应用名称
        """
        if self._app_names:
            return self._app_names
        self._init_app_name()
        return self._app_names

    @property
    def app_name(self) -> Optional[str]:
        """
        获取应用名称之一
        """
        if self._app_name:
            return self._app_name
        self._init_app_name()
        return self._app_name

    def _init_app_name(self) -> None:
        """not best method:
        [
            i
            for i in self.resources.get_string_resources(self.get_manifest()["@package"])
            if i["name"] == "app_name"
        ]
        """
        label_id_str = "0x" + self.manifest_dict["application"][
            "@android:label"
        ].removeprefix("@")
        if len(label_id_str) > 100:
            raise ValueError(
                f"The label is too long ({len(label_id_str)-2+1} chars). Please check the manifest file."
            )
        label_id: int = int(label_id_str, 16)
        label_hits = self.arsc.get_resolved_res_configs(label_id)
        self._app_name: Optional[str] = label_hits[0][-1]
        self._app_names: List[str] = [i[-1] for i in label_hits]

    def _init_activities(self) -> None:
        manifest = self.manifest_dict
        activities = manifest["application"]["activity"]
        activity_alias = self.manifest_dict["application"].get("activity-alias", [])
        self._activities: List[str] = [i[NAME_ATTRIBUTE_NAME] for i in activities]
        self._activity_alias: Dict[str, str] = {
            i[NAME_ATTRIBUTE_NAME]: i["@android:targetActivity"] for i in activity_alias
        }
        self._exported_activities: List[str] = [
            i[NAME_ATTRIBUTE_NAME]
            for i in activities
            if i.get("@android:exported", "false") == "true"
        ]
        home_activities: List[str] = []
        for act in activities + activity_alias:
            for intent_filter in act.get("intent-filter", []):
                is_main = False
                for action in intent_filter.get("action", []):
                    if (
                        action.get(NAME_ATTRIBUTE_NAME, "")
                        == "android.intent.action.MAIN"
                    ):
                        is_main = True
                        break
                is_launcher = False
                for category in intent_filter.get("category", []):
                    if (
                        category.get(NAME_ATTRIBUTE_NAME, "")
                        == "android.intent.category.LAUNCHER"
                    ):
                        is_launcher = True
                        break
                if act.get("@android:enabled", "true") == "false":
                    # e.g. Spotify
                    continue
                if is_main and is_launcher:
                    home_activities.append(act[NAME_ATTRIBUTE_NAME])
        try:
            assert (
                len(home_activities) == 1
            ), f"There should be only one home activity, but found {home_activities}."
        except AssertionError as e:
            # print("Details: ")
            # print(activities, activity_alias)
            # print(manifest)
            # raise e
            warnings.warn(str(e))
        self._home_activities: List[str] = home_activities
        self._home_activity: Optional[str] = (
            home_activities[0] if home_activities else None
        )

    @property
    def home_activities(self) -> List[str]:
        if not self._home_activities:
            self._init_activities()
        return self._home_activities

    @property
    def home_activity(self) -> Optional[str]:
        if not self._home_activity:
            self._init_activities()
        return self._home_activity

    @property
    def activities(self) -> List[str]:
        if not self._activities:
            self._init_activities()
        return self._activities

    @property
    def activity_alias(self) -> Dict[str, str]:
        if not self._activity_alias:
            self._init_activities()
        return self._activity_alias

    @property
    def exported_activities(self) -> List[str]:
        if not self._exported_activities:
            self._init_activities()
        return self._exported_activities

    @property
    def all_app_icons(self) -> Set[str]:
        """
        获取应用图标对应的所有图标文件的路径
        """
        if self._app_icons:
            return self._app_icons
        self._init_app_icon()
        return self._app_icons

    @property
    def app_icon(self) -> Optional[str]:
        """
        获取应用图标对应的所有图标文件中的一个的路径
        """
        if self._app_icon:
            return self._app_icon
        self._init_app_icon()
        return self._app_icon

    def _init_app_icon(self) -> None:
        files = self.files
        result = re.search(r':icon="@(.*?)"', self.orig_manifest)
        if not result:
            return
        ids = "0x" + result.groups()[0].lower()
        try:
            self.package = self.arsc.get_packages_names()[0]
            datas = xmltodict.parse(
                self.arsc.get_public_resources(self.package),
                force_list=RESOURCE_XMLTODICT_FORCE_LIST,
            )
            for item in datas["resources"]["public"]:
                if ids != item["@id"]:
                    continue
                for f in files:
                    name = f["name"]
                    if item["@type"] in name and item["@name"] in name:
                        self._app_icon = name
                        self._app_icons.add(name)
        except Exception as ex:
            raise ex

    def _init_strings_refx(self) -> None:
        if not self._dex_files:
            self._init_dex_files()

        self._strings_refx = {}
        for dex_file in self._dex_files:
            for dexClass in dex_file.classes:
                try:
                    dexClass.parseData()
                except IndexError:
                    continue
                assert dexClass.data is not None
                for method in dexClass.data.methods:
                    if not method.code:
                        continue

                    for bc in method.code.bytecode:
                        # 1A const-string
                        # 1B const-string-jumbo
                        if bc.opcode not in {26, 27}:
                            continue

                        clsname = method.id.cname.decode()
                        mtdname = method.id.name.decode()
                        dexstr = dex_file.string(bc.args[1])
                        if clsname in self._strings_refx:
                            if mtdname in self._strings_refx[clsname]:
                                self._strings_refx[clsname][mtdname].add(dexstr)
                            else:
                                self._strings_refx[clsname][mtdname] = set()
                                self._strings_refx[clsname][mtdname].add(dexstr)
                        else:
                            self._strings_refx[clsname] = {}
                            self._strings_refx[clsname][mtdname] = set()
                            self._strings_refx[clsname][mtdname].add(dexstr)

    @property
    def strings_refx(self) -> Dict[str, Dict[str, Set[bytes]]]:
        """获取字符串索引，即字符串被那些类、方法使用了。

        :return: 字符串索引
        """
        if self._strings_refx is None:
            self._init_strings_refx()
        assert self._strings_refx is not None
        return self._strings_refx

    @property
    def dex_files(self) -> List[DexFile]:
        if not self._dex_files:
            self._init_dex_files()
        return self._dex_files

    def _init_dex_files(self) -> None:
        self._dex_files = []
        try:
            for name in self.apk_namelist:
                data = self.zipfile.read(name)
                if (
                    name.startswith("classes")
                    and name.endswith(".dex")
                    and Magic(data).get_type() == "dex"
                ):
                    dex_file = DexFile(data)
                    self._dex_files.append(dex_file)
        except Exception as ex:
            raise ex

    @property
    def dex_classes(self) -> Set[str]:
        response: Set[str] = set()
        for dex_file in self.dex_files:
            for dex_class in dex_file.classes:
                response.add(dex_class.name.decode())
        return response

    DEEP_LEVEL_3_SET: Final[Set[str]] = {
        "com.google.android",
        "com.samsung.android",
        "com.alibaba.android",
        "cn.com.chinatelecom",
        "com.github.chrisbanes",
        "com.google.thirdparty",
    }

    @property
    def dex_classes_for_libchecker(self) -> Set[str]:
        # https://github.com/LibChecker/LibChecker/blob/b1d9bb82d8d8b5645e48a53ec7a035aa30285f52/app/src/main/kotlin/com/absinthe/libchecker/utils/PackageUtils.kt#L940
        # Apache 2.0 License
        if self._dex_classes_for_libchecker:
            return self._dex_classes_for_libchecker
        response: Set[str] = set()
        for class_name in self.dex_classes:
            class_name = class_name.replace("/", ".")
            if "." not in class_name:
                continue
            if class_name.startswith("kotlin"):
                continue
            if class_name.startswith("androidx"):
                class_name = class_name[class_name.find(".") + 1 :]
            else:
                class_name = ".".join(class_name.split(".")[:4])
            if class_name:
                response.add(class_name)
        # Merge path deep level 3 classes
        response_copy = response.copy()
        for class_name in response_copy:
            if len(class_name.split(".")) == 3:
                for class_name_deeper in response_copy:
                    if class_name_deeper.startswith(class_name + "."):
                        response.remove(class_name_deeper)
        # Merge path deep level 4 classes
        for class_name in response.copy():
            if len(class_name.split(".")) == 4:
                path_level_3_item = ".".join(class_name.split(".")[:3])
                if path_level_3_item in self.DEEP_LEVEL_3_SET:
                    continue
                filter_ = [i for i in response if i.startswith(path_level_3_item + ".")]
                if filter_:
                    for item in filter_:
                        response.remove(item)
                    response.add(path_level_3_item)
        self._dex_classes_for_libchecker = response
        return response

    @property
    def strings(self) -> List[str]:
        """
        All strings in dex files, encoded in hex format (`binascii.hexlify(s).decode()`).
        """
        if not self._strings:
            self._init_strings()
        return self._strings

    @property
    def orig_strings(self) -> List[bytes]:
        """
        All bytes strings in dex files.
        """
        if not self._orig_strings:
            self._init_strings()
        return self._orig_strings

    def _init_strings(self) -> None:
        if not self._dex_files:
            self._init_dex_files()

        str_set = set()
        org_str_set = set()  # original string in hex format
        for dex_file in self._dex_files:
            for i in range(dex_file.string_ids.size):
                ostr = dex_file.string(i)
                org_str_set.add(ostr)
                str_set.add(binascii.hexlify(ostr).decode())

        self._strings = list(str_set)
        self._orig_strings = list(org_str_set)

    @property
    def files(self) -> List[ChildItem]:
        if not self._files_in_apk:
            self._init_files_in_apk()
        return self._files_in_apk

    def _init_files_in_apk(self) -> None:
        self._files_in_apk = []
        try:
            for name in self.apk_namelist:
                try:
                    data = self.zipfile.read(name)
                    mine = Magic(data).get_type()
                    info = self.zipfile.getinfo(name)
                except Exception as ex:
                    print(name, ex)
                    continue
                crc = str(hex(info.CRC)).upper()[2:]
                crc = "0" * (8 - len(crc)) + crc
                # item["sha1"] = ""
                item: ChildItem = {
                    "name": name,
                    "type": mine,
                    "time": "%d%02d%02d%02d%02d%02d" % info.date_time,
                    "crc": crc,
                }
                self._files_in_apk.append(item)
        except Exception as e:
            raise e

    @property
    def orig_manifest(self) -> str:
        # org -> original XD
        if not self._orig_manifest:
            self._init_manifest()
        return self._orig_manifest

    @property
    def package_name(self) -> str:
        manifest = self.manifest_dict
        return manifest["@package"]

    def _init_org_manifest(self) -> None:
        ANDROID_MANIFEST = "AndroidManifest.xml"
        try:
            if ANDROID_MANIFEST in self.apk_namelist:
                data = self.zipfile.read(ANDROID_MANIFEST)
                try:
                    axml = AXML(data)
                    if axml.is_valid:
                        self._orig_manifest = axml.get_xml()
                except Exception as e:
                    raise e
        except Exception as e:
            raise e

    @property
    def manifest_dict(self) -> dict:
        if not self._manifest:
            self._init_manifest()
        return self._manifest

    @property
    def manifest_object(self) -> Manifest:
        """
        Who use this?
        """
        return Manifest(self.orig_manifest)

    def _init_manifest(self) -> None:
        if not self._orig_manifest:
            self._init_org_manifest()

        if self._orig_manifest:
            try:
                self._manifest = xmltodict.parse(
                    self._orig_manifest, force_list=MANIFEST_XMLTODICT_FORCE_LIST
                )["manifest"]
            except xml.parsers.expat.ExpatError as e:
                pass
            except Exception as e:
                raise e

    def _init_arsc(self) -> None:
        ARSC_NAME = "resources.arsc"
        try:
            if ARSC_NAME in self.apk_namelist:
                data = self.zipfile.read(ARSC_NAME)
                self._arsc_parser = ARSCParser(data)
        except Exception as e:
            raise e

    @property
    def arsc(self) -> ARSCParser:
        if self._arsc_parser is None:
            self._init_arsc()
        assert self._arsc_parser is not None
        return self._arsc_parser

    @property
    def certs(self) -> List["CertType"]:
        if not self._certs:
            self._init_certs()
        return self._certs

    def _init_certs(self) -> None:
        try:
            for name in self.apk_namelist:
                if "META-INF" in name:
                    data = self.zipfile.read(name)
                    mine = Magic(data).get_type()
                    if mine != "txt":
                        from cert import Certificate

                        cert = Certificate(data)
                        self._certs = cert.get()
        except Exception as e:
            raise e

    @property
    def opcodes(self) -> List[OpCodeItem]:
        if not self._opcodes:
            self._init_opcodes()
        return self._opcodes

    def _init_opcodes(self) -> None:
        if not self._dex_files:
            self._init_dex_files()

        self._opcodes = []
        for dex_file in self._dex_files:
            for dexClass in dex_file.classes:
                try:
                    dexClass.parseData()
                except IndexError:
                    continue
                assert dexClass.data is not None
                for method in dexClass.data.methods:
                    opcodes = ""
                    if method.code:
                        for bc in method.code.bytecode:
                            opcode = str(hex(bc.opcode)).upper()[2:]
                            if len(opcode) == 2:
                                opcodes = opcodes + opcode
                            else:
                                opcodes = opcodes + "0" + opcode

                    proto = self.get_proto_string(
                        method.id.return_type, method.id.param_types
                    )
                    assert dexClass.super is not None
                    item: OpCodeItem = {
                        "super_class": dexClass.super.decode(),
                        "class_name": method.id.cname.decode(),
                        "method_name": method.id.name.decode(),
                        "method_desc": method.id.desc.decode(),
                        "proto": proto,
                        "opcodes": opcodes,
                    }
                    self._opcodes.append(item)

    @staticmethod
    def get_proto_string(return_type: bytes, param_types: List[bytes]) -> str:
        proto = return_type.decode()
        if len(proto) > 1:
            proto = "L"

        for item in param_types:
            param_type = item.decode()
            proto += "L" if len(param_type) > 1 else param_type

        return proto
