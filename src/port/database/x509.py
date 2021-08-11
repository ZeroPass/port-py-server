import enum
from asn1crypto import x509
from asn1crypto.crl import RevokedCertificate
from datetime import datetime
from port.proto.types import CertificateId, CountryCode, CrlId
from port.proto.utils import bytes_to_int, int_to_bytes, sha512_256
from pymrtd.pki.crl import CertificateRevocationList
from pymrtd.pki.x509 import Certificate, CscaCertificate, DocumentSignerCertificate
from typing import Optional, Union

class CertificateStorage:
    """Storage class for """
    id: CertificateId
    country: CountryCode
    serial: bytes
    notValidBefore: datetime
    notValidAfter: datetime
    issuerId: Optional[CertificateId]
    issuer: str
    authorityKey: Optional[bytes]
    subject: str
    subjectKey: Optional[bytes]
    certificate: bytes

    _type = None # certificate type

    def __init__(self, cert: Certificate, issuerId: Optional[CertificateId] = None):
        assert isinstance(cert, Certificate)
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

    def getCertificate(self) -> "CertificateStorage._type":
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
        return (self.subjectKey == self.authorityKey or self.subject == self.issuer) \
            and self.issuerId is None

    @staticmethod
    def makeSerial(ser: int) -> bytes:
        assert isinstance(ser, int)
        return int_to_bytes(ser, signed=True)


class CscaStorage(CertificateStorage):
    _type = CscaCertificate

class DscStorage(CertificateStorage):
    _type = DocumentSignerCertificate

class CrlUpdateInfo:
    """
    Table stores CRL update information for country.
    Note, some countries issues multiple CRLs for different issuers so the table id colum is
    unique id based on country code and issuer DN.
    """
    id: CrlId
    country: CountryCode
    issuer: str
    crlNumber: Optional[bytes]
    thisUpdate: datetime
    nextUpdate: datetime

    def __init__(self, issuer: x509.Name, crlNumber: Optional[Union[int, bytes]], thisUpdate: datetime, nextUpdate: datetime):
        assert isinstance(issuer, x509.Name)
        assert crlNumber is None or isinstance(crlNumber, (bytes, int))
        if crlNumber is not None and isinstance(crlNumber, int):
            crlNumber = CrlUpdateInfo.makeCrlNumber(crlNumber)

        self.country    = CountryCode(issuer.native['country_name'])
        self.issuer     = issuer.human_friendly
        self.id         = CrlId.fromCountryCodeAndIssuer(self.country, self.issuer)
        self.crlNumber  = crlNumber
        self.thisUpdate = thisUpdate
        self.nextUpdate = nextUpdate
        self._cached_ser_no  = None

    @classmethod
    def fromCrl(cls, crl: CertificateRevocationList):
        return cls(
            crl.issuer,
            crl.crlNumber,
            crl.thisUpdate,
            crl.nextUpdate
        )

    @property
    def number(self) -> Optional[int]:
        if self.crlNumber is not None:
            if not hasattr(self, '_cached_ser_no') or self._cached_ser_no is None:
                self._cached_ser_no = bytes_to_int(self.crlNumber, signed=True)
        return self._cached_ser_no

    @staticmethod
    def makeCrlNumber(ser: Optional[int]) -> Optional[bytes]:
        return int_to_bytes(ser, signed=True) if ser is not None else None

class CertificateRevocationInfo:
    id: int                         # 64bit signed integer, assigned by db
    serial: bytes                   # certificate serial no.
    country: str
    crlId: Optional[CrlId]          # foregin key into CrlUpdateInfo.Id. If None, the entry was manually added and is not part of any CRL.
    certId: Optional[CertificateId] # id of certificate beeing revoked.
                                    # It could be None due to CRL list doesn't contain ful certificate to calculate CertificateId
    revocationDate: datetime

    def __init__(self, country: CountryCode, serial: Union[int, bytes], revocationDate: datetime, crlId: Optional[CrlId], certId: Optional[CertificateId] = None):
        assert isinstance(country, CountryCode)
        assert isinstance(serial, (bytes, int))
        assert isinstance(revocationDate, datetime)
        assert crlId is None or isinstance(crlId, CrlId)
        assert certId is None or isinstance(certId, CertificateId)
        if isinstance(serial, int):
            serial = CertificateStorage.makeSerial(serial)
        self.id      = None
        self.serial  = serial
        self.country = country
        self.crlId   = crlId
        self.certId  = certId
        self.revocationDate = revocationDate

    @classmethod
    def fromRevokedCertificate(cls, country: CountryCode, rc: RevokedCertificate) -> "CertificateRevocationInfo":
        assert isinstance(country, CountryCode)
        assert isinstance(rc, RevokedCertificate)
        serial  = rc['user_certificate'].native
        revDate = rc['revocation_date'].chosen.native
        revDate = revDate.replace(tzinfo=None)
        return cls(country, serial, revDate, crlId=None)

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
