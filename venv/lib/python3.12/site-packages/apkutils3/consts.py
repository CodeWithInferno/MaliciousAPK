from typing import Final, LiteralString, Tuple


MANIFEST_XMLTODICT_FORCE_LIST: Final[Tuple[LiteralString, ...]] = (
    "activity-alias",
    "activity",
    "receiver",
    "service",
    "provider",
    "uses-permission",
    # "uses-sdk", # only occur once
    "uses-feature",
    "permission",
    "permission-group",
    "instrumentation",
    "meta-data",
    # "uses-configuration", # once
    "uses-library",
    "uses-native-library",
    "uses-permission-sdk-23",
    "supports-gl-texture",
    "intent-filter",
    "action",
    "category",
)

RESOURCE_XMLTODICT_FORCE_LIST: Final[Tuple[LiteralString, ...]] = ("public",)
NAME_ATTRIBUTE_NAME: Final[str] = "@android:name"
