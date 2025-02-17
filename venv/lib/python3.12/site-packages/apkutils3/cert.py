import re
from typing import List, NamedTuple, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs7


class CertType(NamedTuple):
    name: str
    fingerprint: str


class Certificate:
    def __init__(self, buff: bytes, _hash: str = "md5"):
        self.content: List[CertType] = []
        # example: [('CN=Andrew Vasiliu, OU=iOS/Android Development, O=Qbiki Networks, L=Seattle', '5de9d45fed20f9db2033e5803704d156')]
        self._parse(buff, _hash)

    def get(self) -> List[CertType]:
        return self.content

    def _parse(self, buff: bytes, _hash: str):
        h = hashes.MD5()
        if _hash == "sha256":
            h = hashes.SHA256()
        elif _hash == "sha1":
            h = hashes.SHA1()

        certificates = pkcs7.load_der_pkcs7_certificates(buff)

        for item in certificates:
            name = item.subject.rfc4514_string()
            name = re.sub(r",(\w{1,2}\=)", r", \1", name).replace("\\", "")
            fingerprint = item.fingerprint(h).hex()
            self.content.append(CertType(name, fingerprint))


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        cert = Certificate(f.read())
        print(cert.get())
