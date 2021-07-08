from .utils import bytes_to_int, format_alpha2, int_count_bytes, sha512_256
from pymrtd import ef
from pymrtd.pki import x509
from typing import cast, Union

class IIntegerId(int):
    min:int
    max:int

    def __new__(cls, idValue: Union[int, bytes, str], *args, **kwargs): #pylint: disable=unused-argument
        if isinstance(idValue, int):
            if not (cls.min <= idValue <= cls.max): #pylint: disable=superfluous-parens
                raise ValueError("integer out of range to construct {}. id_value={}".format(cls.__name__, idValue))
        elif isinstance(idValue, bytes):
            # check if we have required number of bytes
            mn = max(abs(cls.min), abs(cls.max))
            nb = int_count_bytes(mn)
            if len(idValue) < nb:
                raise ValueError("not enough bytes to construct {}".format(cls.__name__))
            idValue = bytes_to_int(idValue[0:nb], signed=True)
        elif isinstance(idValue, str):
            idValue = int(idValue, *args)
            if not (cls.min <= idValue <= cls.max): #pylint: disable=superfluous-parens
                raise ValueError("out of range to construct {}".format(cls.__name__))
        else:
            raise ValueError("invalid type to construct {}. id_type={}".format(cls.__name__, type(idValue)))
        return cast(cls, super().__new__(cls, idValue))

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
        return sha512_256(crt.dump())

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
        return sha512_256(sod.dump())

class CountryCode(str):
    """
    Class represents ISO-3166 Alpha-2 country code
    """
    def __new__(cls, content):
        return super().__new__(cls, format_alpha2(content))
