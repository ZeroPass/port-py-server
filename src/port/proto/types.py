from .utils import bytes_to_int, int_count_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import Hash, SHA512_256
from pymrtd import ef
from pymrtd.pki import x509
from typing import cast, Union

class IIntegerId(int):
    min:int
    max:int

    def __new__(cls, id: Union[int, bytes, str], *args, **kwargs):
        if isinstance(id, int):
            if not (cls.min <= id <= cls.max):
                raise ValueError("integer out of range to construct {}. id_value={}".format(cls.__name__, id))
        elif isinstance(id, bytes):
            # check if we have required number of bytes
            mn = max(abs(cls.min), abs(cls.max))
            nb = int_count_bytes(mn)
            if len(id) < nb:
                raise ValueError("not enough bytes to construct {}".format(cls.__name__))
            id = bytes_to_int(id[0:nb], signed=True)
        elif isinstance(id, str):
            id = int(id, *args)
            if not (cls.min <= id <= cls.max):
                raise ValueError("out of range to construct {}".format(cls.__name__))
        else:
            raise ValueError("invalid type to construct {}. id_type={}".format(cls.__name__, type(id)))
        return cast(cls, super().__new__(cls, id))

    @classmethod
    def fromHex(cls, hexstr: str):
        assert isinstance(hexstr, str)
        return cls(hexstr, 16)

    def hex(self):
        return hex(self)


class CertificateId(IIntegerId):
    """
    Represents x509.Certificate ID as uint64
    CertificateId is calculated by taking the first 8 bytes of SHA-512/256 hash
    over x509.Certificate ASN.1 DER encoded bytes
    """

    min = -9223372036854775808 # min 64 bit int
    max = 9223372036854775807  # max 64 bit int

    @classmethod
    def fromCertificate(cls, crt: x509.Certificate) -> "CertificateId":
        h = Hash(SHA512_256(), backend=default_backend())
        h.update(crt.dump())
        return cls(h.finalize())

class SodId(IIntegerId):
    """
    Represents ef.SOD ID as uint64
    SodId is calculated by taking the first 8 bytes of SHA-512/256 hash
    over SOD ASN.1 DER encoded bytes
    """

    min = -9223372036854775808 # min 64 bit int
    max = 9223372036854775807  # max 64 bit int

    @classmethod
    def fromSOD(cls, sod: ef.SOD) -> "SodId":
        h = Hash(SHA512_256(), backend=default_backend())
        h.update(sod.dump())
        return cls(h.finalize())

