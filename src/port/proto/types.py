import base64
import os
from asn1crypto.x509 import Name
from cryptography.hazmat.primitives.hashes import Hash, SHA512_256
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from pymrtd import ef
from pymrtd.pki import x509
from typing import cast, Union
from .utils import bytes_to_int, format_alpha2, int_count_bytes, int_to_bytes, sha512_256

class CountryCode(str):
    """
    Class represents ISO-3166 Alpha-2 country code
    """
    def __new__(cls, content):
        return super().__new__(cls, format_alpha2(content) if content is not None else None)

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
    over ASN.1 DER encoded bytes of x509.Certificate.tbs_certificate fields
    """

    min = -9223372036854775808 # min 64 bit int
    max = 9223372036854775807  # max 64 bit int

    @classmethod
    def fromCertificate(cls, crt: x509.Certificate) -> "CertificateId":
        """
        Returns `CertificateId` generated from SHA512-256(`crt`.tbs_certificate).
        Note, the reason for calculating ID from TBS certificate is to get the same ID
        when certificate signature is different but TBS certificates are the same.
        :param `crt`: X509 certificate to generate the `CertificateId` from.
        :return: New `CertificateId` object from `crt`.
        """
        assert isinstance(crt, x509.Certificate)
        return cls(sha512_256(crt['tbs_certificate'].dump())[0:8])

class CrlId(IIntegerId):
    """
    CrlId represents unique ID of country CRL based on country code and issuer DN.
    i.e. sha512-256(country_code + issuer_dn)[0:8]
    """
    min = -9223372036854775808 # min 64 bit int
    max = 9223372036854775807  # max 64 bit int

    @classmethod
    def fromCountryCodeAndIssuer(cls, country: CountryCode, issuer: str) -> "CrlId":
        assert isinstance(country, CountryCode)
        assert isinstance(issuer, str)
        h = sha512_256((country + issuer).encode('utf-8'))
        return cls(h)

    @classmethod
    def fromCrlIssuer(cls, issuer: Name) -> "CrlId":
        assert isinstance(issuer, Name)
        c = CountryCode(issuer.native['country_name'])
        i = issuer.human_friendly
        return CrlId.fromCountryCodeAndIssuer(c, i)

class SodId(IIntegerId):
    """
    Represents ef.SOD ID as uint64.
    SodId is calculated by taking the first 8 bytes of SHA-512/256 hash
    over ASN.1 DER encoded bytes of EF.SOD.ldsSecurityObject.
    """

    min = -9223372036854775808 # min 64 bit int
    max = 9223372036854775807  # max 64 bit int

    @classmethod
    def fromSOD(cls, sod: ef.SOD) -> "SodId":
        """
        Generates SodId from `sod`.
        The SodId is generated from SHA-512/256 hash of
        ASN.1 DER encoded bytes of EF.SOD.ldsSecurityObject.
        Going this way should produce exact same SodId for 2 EF.SODs
        with equal LdsSecurityObject content but different or altered signers.
        This prevents EF.SOD registration melability.

        :param sod: The EF.SOD to generate SodId.
        :return: SodId of `sod`.
        """
        assert isinstance(sod, ef.SOD)
        return cls(sha512_256(sod.ldsSecurityObject.dump()))

class UserIdError(Exception):
    pass

class UserId(bytes):
    """ Represents account userId"""

    max_size: int = 20

    def __new__(cls, userId: bytes) -> "UserId":
        if not isinstance(userId, bytes) or \
            len(userId) > UserId.max_size:
            raise UserIdError("Invalid userId data")
        return cast(UserId, super().__new__(cls, userId))  # type: ignore  # https://github.com/python/typeshed/issues/2630  # noqa: E501

    @staticmethod
    def fromBase64(b64Str: str) -> "UserId":
        assert isinstance(b64Str, str)
        return UserId(base64.b64decode(b64Str))

    def toBase64(self):
        return str(base64.b64encode(self), 'ascii')

    def __str__(self) -> str:
        try:
            return self.decode("utf-8")
        except: #pylint: disable=bare-except
            return self.hex()

    def __repr__ (self) -> str:
        return "UserId({!s})".format(self)

class CID(IIntegerId):
    """ Represents challenge id """
    min = -2147483648
    max = 2147483647

class ChallengeError(Exception):
    pass

class Challenge(bytes):
    """ Class generates and holds proto challenge """

    _hash_algo = SHA512_256

    def __new__(cls, challenge: bytes) -> "Challenge":
        if isinstance(challenge, bytes):
            if len(challenge) != cls._hash_algo.digest_size:
                raise ChallengeError("Invalid challenge length")
            return cast(Challenge, super().__new__(cls, challenge))  # type: ignore  # https://github.com/python/typeshed/issues/2630  # noqa: E501
        else:
            raise ChallengeError("Invalid challenge type")

    @property
    def id(self) -> CID:
        if not hasattr(self, "_id"):
            self._id = CID(self) #pylint: disable=attribute-defined-outside-init
        return self._id

    @staticmethod
    def fromhex(hexStr: str) -> "Challenge":
        assert isinstance(hexStr, str)
        return Challenge(bytes.fromhex(hexStr))

    @staticmethod
    def fromBase64(b64Str: str) -> "Challenge":
        assert isinstance(b64Str, str)
        return Challenge(base64.b64decode(b64Str))

    def toBase64(self):
        return str(base64.b64encode(self), 'ascii')

    @staticmethod
    def generate(time: datetime, extraData: bytes) -> "Challenge":
        assert isinstance(time, datetime)
        ts = int_to_bytes(int(time.timestamp()))
        rs = os.urandom(Challenge._hash_algo.digest_size)

        h = Hash(Challenge._hash_algo(), backend=default_backend())
        h.update(ts)
        h.update(extraData)
        h.update(rs)
        return Challenge(h.finalize())
