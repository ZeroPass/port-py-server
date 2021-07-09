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
        self.serial         = int_to_bytes(cert.serial_number)
        self.notValidBefore = cert.notValidBefore
        self.notValidAfter  = cert.notValidAfter
        self.issuerId       = issuerId
        self.issuer         = cert.issuer.human_friendly
        self.authorityKey   = cert.authorityKey
        self.subject        = cert.subject.human_friendly
        self.subjectKey     = cert.subjectKey
        self.certificate    = cert.dump()

    def getCertificate(self):
        """Returns object"""
        return self._type.load(self.certificate)

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

    @classmethod
    def fromCrl(cls, crl: CertificateRevocationList):
        cn = int_to_bytes(crl.crl_number_value.native) if crl.crl_number_value is not None else None
        return cls(CountryCode(crl.issuerCountry), cn, crl.thisUpdate, crl.nextUpdate)

class CertificateRevocationInfo:
    serial: bytes
    country: CountryCode
    certId: Optional[CertificateId] # id of certificate beeing revoked.
                                    # It could be None due to CRL list doesn't contain ful certificate to calculate CertificateId
    revocationDate: datetime

    def __init__(self, country: CountryCode, serial: int, revocationDate: datetime, certId: Optional[CertificateId] = None):
        assert isinstance(country, CountryCode)
        self.country = country
        self.certId  = certId
        self.serial  = int_to_bytes(serial)
        self.revocationDate = revocationDate

class PkiDistributionUrl:
    class  Type(enum.Enum):
        CSCA = 0
        DSC  = 1
        CRL  = 2

    id: int # signed 64 bit, see _gen_id
    country: CountryCode
    type: Type
    url: str

    def __init__(self, country: CountryCode, pkiType: Type, url: str) -> None:
        assert len(url) > 0
        assert isinstance(country, CountryCode)
        self.id      = PkiDistributionUrl._gen_id(pkiType, url)
        self.country = country
        self.type    = pkiType
        self.url     = url

    @staticmethod
    def _gen_id(pkiType: Type, url: str) -> int:
        h = sha512_256(int_to_bytes(pkiType) + url.encode('utf-8'))
        return bytes_to_int(h[0:8])
