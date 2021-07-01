import datetime
import logging
from typing import List, Optional

from port.database.storage.storageManager import PortDatabaseConnection
from pymrtd.pki.x509 import Certificate, CscaCertificate, DocumentSignerCertificate
from port.proto.types import CertificateId
from port.proto.utils import format_alpha2, int_to_bytes

logger = logging.getLogger(__name__)


class CscaStorageError(Exception):
    pass

class DscStorageError(Exception):
    pass

class CertificateStorage(object):
    """Storage class for """
    id: CertificateId
    country: str
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
        self.country        = format_alpha2(cert.issuerCountry)
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



def writeToDB_CSCA(csca: CscaCertificate, connection: PortDatabaseConnection):
    """Write to database with ORM"""
    try:
        logger.info("Writing CSCA object to database. Country: " + csca.issuerCountry)
        connection.getSession().add(CscaStorage(csca))
        connection.getSession().commit()

    except Exception as e:
        raise CscaStorageError("Problem with writing the object") from e

def readFromDB_CSCA_issuer_serialNumber(issuer: str, serialNumber: int, connection: PortDatabaseConnection) -> List[CscaStorage]:
    """Reading from database"""
    try:
        logger.info("Reading CSCA object from database. Issuer:" + issuer + ", serial number: " + str(serialNumber))
        return connection.getSession() \
                         .query(CscaStorage) \
                         .filter(CscaStorage.issuer == issuer,
                                 CscaStorage.serial == str(serialNumber.native)
                         ).all()
    except Exception as e:
        raise CscaStorageError("Problem with writing the object") from e

def readFromDB_CSCA_authorityKey(authorityKey: bytes, connection: PortDatabaseConnection) -> List[CscaStorage]:
    """Reading from database"""
    try:
        logger.info("Reading CSCA object from database by authority key")
        return connection.getSession() \
                         .query(CscaStorage) \
                         .filter(CscaStorage.authorityKey == authorityKey) \
                         .all()
    except Exception as e:
        raise CscaStorageError("Problem with writing the object") from e

def deleteFromDB_CSCA(CSCAs: List[CscaStorage], connection: PortDatabaseConnection):
    """Reading from database"""
    try:
        logger.info("Delete DSCs; size:" + str(len(CSCAs)))
        if len(CSCAs) == 0:
            logger.debug("Empty array. Nothing to delete.")
        for item in CSCAs:
            try:
                connection.getSession().delete(item)
            except Exception as e:
                logger.error("Action delete failed. No item in database or object was not CSCA.")
        connection.getSession().commit()
    except Exception as e:
        raise DscStorageError("Problem with writing the object") from e

class DscStorage(CertificateStorage):
    _type = DocumentSignerCertificate
# class DscStorage(object):
#     """Class for interaction between code structure and database - DSC"""

#     def __init__(self, dsc: DocumentSignerCertificate, issuerCountry: str):
#         """Initialization class with serialization of DSC"""
#         self.serializeDSC(dsc)
#         self.issuer          = dsc.issuer.human_friendly
#         self.fingerprint     = dsc.fingerprint
#         self.subject         = dsc.subject.human_friendly
#         self.subjectKey      = dsc.subjectKey
#         self.authorityKey    = dsc.authorityKey
#         self.notValidBefore  = dsc.notValidBefore
#         self.notValidAfter   = dsc.notValidAfter
#         try:
#             self.serialNumber = str(dsc.serial_number)
#         except:
#             self.serialNumber = ""

#     def serializeDSC(self, dsc: DocumentSignerCertificate):
#         """Function serialize DSC object to sequence"""
#         self.object = dsc.dump()

#     def getObject(self) -> DocumentSignerCertificate:
#         """Returns DSC object"""
#         return DocumentSignerCertificate.load(self.object)


def writeToDB_DSC(dsc: DocumentSignerCertificate, connection: PortDatabaseConnection):
    """Write to database with ORM"""
    try:
        logger.info("Writing DSC object to database. Country: " + dsc.issuerCountry)
        a = DscStorage(dsc)
        connection.getSession().add(a)
        connection.getSession().commit()

    except Exception as e:
        raise DscStorageError("Couldn't write DSC storage to DB") from e

def readFromDB_DSC_issuer_serialNumber(issuer: str, serialNumber: int, connection: PortDatabaseConnection) -> List[DscStorage]:
    """Reading from database"""
    try:
        logger.info("Reading DSC object from database. Issuer:" + issuer + ", serial number: " + str(serialNumber))
        return connection.getSession() \
            .query(DscStorage) \
            .filter(DscStorage.issuer == issuer,
                    DscStorage.serial == str(serialNumber.native)
            ).all()
    except Exception as e:
        raise DscStorageError("Problem with writing the object") from e

def readFromDB_DSC_issuer(issuer: str, connection: PortDatabaseConnection) -> List[DscStorage]:
    """Reading from database"""
    try:
        logger.info("Reading DSC object from database. Issuer:" + issuer)
        return connection.getSession() \
                         .query(DscStorage) \
                         .filter(DscStorage.issuer == issuer) \
                         .all()
    except Exception as e:
        raise DscStorageError("Problem with writing the object") from e

def readFromDB_DSC_authorityKey(authorityKey: bytes, connection: PortDatabaseConnection) -> List[DscStorage]:
    """Reading from database"""
    try:
        logger.info("Reading DSC object from database with authority key.")
        return connection.getSession() \
                         .query(DscStorage) \
                         .filter(DscStorage.authorityKey == authorityKey) \
                         .all()
    except Exception as e:
        raise DscStorageError("Problem with writing the object") from e

def deleteFromDB_DSC(dscs: List[DscStorage],connection: PortDatabaseConnection):
    """Reading from database"""
    try:
        logger.info("Delete DSCs; size:" + str(len(dscs)))
        if len(dscs) == 0:
            logger.debug("Empty array. Nothing to delete.")

        for item in dscs:
            try:
                connection.getSession().delete(item)
            except Exception as e:
                logger.error("Action delete failed. No item in database or object was not DSC. error={}".format(str(e)))
        connection.getSession().commit()
    except Exception as e:
        raise DscStorageError("Problem with writing the object. error={}".format(str(e))) from e
