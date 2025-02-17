import argparse
import binascii
from typing import List

from . import __version__, APK


def main(args: argparse.Namespace):
    apk = APK(args.p)

    if args.m:
        import json

        if apk.manifest_dict:
            print(json.dumps(apk.manifest_dict, indent=4))
        elif apk.orig_manifest:
            print(apk.orig_manifest)

    elif args.s:
        for item in apk.strings:
            print(binascii.unhexlify(item).decode(errors="ignore"))

    elif args.f:
        for item in apk.files:
            print(item)

    elif args.c:
        for item in apk.certs:
            print(item)


if __name__ == "__main__":
    _parser = argparse.ArgumentParser(prog="apkutils", description=None)
    _parser.add_argument("p", help="path")
    _parser.add_argument(
        "-m", action="store_true", help="Show manifest", required=False
    )
    _parser.add_argument("-s", action="store_true", help="Show strings", required=False)
    _parser.add_argument("-f", action="store_true", help="Show files", required=False)
    _parser.add_argument("-c", action="store_true", help="Show certs", required=False)
    _parser.add_argument("-V", "--version", action="version", version=__version__)

    _args = _parser.parse_args()
    main(_args)
