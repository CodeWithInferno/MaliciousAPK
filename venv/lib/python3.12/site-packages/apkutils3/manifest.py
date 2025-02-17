#!/usr/bin/env python
# coding: utf-8

from typing import Any, List, Optional, OrderedDict
import warnings
import xml
from xml.dom import minidom
import xmltodict

from .consts import MANIFEST_XMLTODICT_FORCE_LIST


class Manifest:
    def __init__(self, content: str):
        self._xml = content
        self._dom = minidom.parseString(content)
        self._permissions: Optional[List[str]] = None
        self._manifest: Optional[OrderedDict[str, Any]] = None

    @property
    def package_name(self) -> str:
        return self._dom.documentElement.getAttribute("package")

    @property
    def version_code(self) -> str:
        return self._dom.documentElement.getAttribute("android:versionCode")

    @property
    def version_name(self) -> str:
        return self._dom.documentElement.getAttribute("android:versionName")

    @property
    def permissions(self) -> List[str]:
        if self._permissions is not None:
            return self._permissions
        self._permissions = []
        for item in self._dom.getElementsByTagName("uses-permission"):
            self._permissions.append(str(item.getAttribute("android:name")))
        return self._permissions

    @property
    def main_activity(self) -> Optional[str]:
        """
        Returns:
            the name of the main activity
        """
        x = set()
        y = set()
        for item in self._dom.getElementsByTagName("activity"):
            for sitem in item.getElementsByTagName("action"):
                val = sitem.getAttribute("android:name")
                if val == "android.intent.action.MAIN":
                    x.add(item.getAttribute("android:name"))
            for sitem in item.getElementsByTagName("category"):
                val = sitem.getAttribute("android:name")
                if val == "android.intent.category.LAUNCHER":
                    y.add(item.getAttribute("android:name"))
        z = x.intersection(y)
        if len(z) > 0:
            return z.pop()
        return None

    def json(self) -> OrderedDict[str, Any]:
        """
        Returns:
            None or dict-form formated manifest
        """
        warnings.warn(
            "json() is deprecated. Use to_dict() instead.", DeprecationWarning
        )
        return self.to_dict()

    def to_dict(self) -> OrderedDict[str, Any]:
        """
        Returns:
            None or dict-form formated manifest
        """
        if self._manifest:
            return self._manifest

        try:
            self._manifest = xmltodict.parse(self._xml, force_list = MANIFEST_XMLTODICT_FORCE_LIST)["manifest"]
        except xml.parsers.expat.ExpatError as e:
            raise e
        except Exception as e:
            raise e
        return self._manifest
