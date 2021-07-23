import datetime
import enum

from port.proto.types import CertificateId, CountryCode
from port.proto.utils import bytes_to_int, int_to_bytes, sha512_256

from pymrtd.pki.crl import CertificateRevocationList
from pymrtd.pki.x509 import Certificate, CscaCertificate, DocumentSignerCertificate

from typing import Optional

class CertificateStorage:
    """Storage class for """
    id: CertificateId
    country: CountryCode
    serial: bytes
    notValidBefore: datetime
    notValidAfter: datetime
    issuerId: Optional[CertificateId]
    issuer: str
    authorityKey: bytes
    subject: str
    subjectKey: bytes
    certificate: bytes

    _type = None

    def __init__(self, cert: Certificate, issuerId: Optional[CertificateId] = None):
        self.id             = CertificateId.fromCertificate(cert)
        self.country        = CountryCode(cert.issuerCountry)
        self.serial         = CertificateStorage.makeSerial(cert.serial_number)
        self.notValidBefore = cert.notValidBefore
        self.notValidAfter  = cert.notValidAfter
        self.issuerId       = issuerId
        self.issuer         = cert.issuer.human_friendly
        self.authorityKey   = cert.authorityKey
        self.subject        = cert.subject.human_friendly
        self.subjectKey     = cert.subjectKey
        self.certificate    = cert.dump()

        self._cached_crt_obj = None
        self._cached_ser_no  = None

    @property
    def serialNumber(self) -> int:
        if not hasattr(self, '_cached_ser_no') or self._cached_ser_no is None:
            self._cached_ser_no = bytes_to_int(self.serial, signed=True)
        return self._cached_ser_no

    def getCertificate(self):
        """Returns x509. Certificate object"""
        if not hasattr(self, '_cached_crt_obj') or self._cached_crt_obj is None:
            self._cached_crt_obj = self._type.load(self.certificate)
        return self._cached_crt_obj

    def isValidOn(self, dateTime: datetime):
        ''' Verifies if certificate is valid on specific date-time '''
        nvb = self.notValidBefore
        nva = self.notValidAfter
        dateTime = dateTime.replace(tzinfo=nvb.tzinfo)
        return nvb < dateTime < nva

    def isSelfIssued(self):
        return (self.subject == self.issuer or self.subjectKey == self.authorityKey) \
            and self.issuerId is None

    @staticmethod
    def makeSerial(ser: int) -> bytes:
        return int_to_bytes(ser, signed=True)


class CscaStorage(CertificateStorage):
    _type = CscaCertificate

class DscStorage(CertificateStorage):
    _type = DocumentSignerCertificate

class CrlUpdateInfo:
    """Class for interaaction between code structure and database"""
    country: CountryCode
    crlNumber: Optional[bytes]
    thisUpdate: datetime
    nextUpdate: datetime

    def __init__(self, country: CountryCode, crlNumber: Optional[bytes], thisUpdate: datetime, nextUpdate: datetime):
        assert isinstance(country, CountryCode)
        self.country    = country
        self.crlNumber  = crlNumber
        self.thisUpdate = thisUpdate
        self.nextUpdate = nextUpdate
        self._cached_ser_no  = None

    @classmethod
    def fromCrl(cls, crl: CertificateRevocationList):
        return cls(
            CountryCode(crl.issuerCountry),
            CrlUpdateInfo.makeCrlNumber(crl.crl_number_value.native),
            crl.thisUpdate,
            crl.nextUpdate
        )

    @property
    def crlNumberInt(self) -> Optional[int]:
        if self.crlNumber is not None:
            if not hasattr(self, '_cached_ser_no') or self._cached_ser_no is None:
                self._cached_ser_no = bytes_to_int(self.crlNumber, signed=True)
        return self._cached_ser_no

    @staticmethod
    def makeCrlNumber(ser: Optional[int]) -> Optional[bytes]:
        return int_to_bytes(ser, signed=True) if ser is not None else None

class CertificateRevocationInfo:
    serial: bytes                   # certificate serial no.
    country: CountryCode
    certId: Optional[CertificateId] # id of certificate beeing revoked.
                                    # It could be None due to CRL list doesn't contain ful certificate to calculate CertificateId
    revocationDate: datetime

    def __init__(self, country: CountryCode, serial: int, revocationDate: datetime, certId: Optional[CertificateId] = None):
        assert isinstance(country, CountryCode)
        self.country = country
        self.certId  = certId
        self.serial  = CertificateStorage.makeSerial(serial)
        self.revocationDate = revocationDate


class PkiDistributionUrl:
    class Type(enum.Enum):
        CSCA        = 0
        DSC         = 1
        CRL         = 2
        MasterList  = 3
        MrtdPkdLdif = 4 # e.g. ICAO mrtd public key directory ldif file

    id: int # signed 64 bit, see _gen_id
    country: CountryCode
    type: Type
    url: str

    def __init__(self, country: CountryCode, pkiType: Type, url: str) -> None:
        assert len(url) > 0
        assert isinstance(country, CountryCode)
        self.id      = PkiDistributionUrl._gen_id(country, pkiType, url)
        self.country = country
        self.type    = pkiType
        self.url     = url

    @staticmethod
    def _gen_id(country: str,  pkiType: Type, url: str) -> int:
        '''
        Generates ID from country, type and url.
        The generated ID should be unique so any duplicated entries won't be inserted.
        '''
        h = sha512_256(country.encode('utf-8') + int_to_bytes(pkiType.value) + url.encode('utf-8'))
        return bytes_to_int(h[0:8])
