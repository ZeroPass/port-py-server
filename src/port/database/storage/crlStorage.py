import logging

from port.database.storage.storageManager import Connection
from port.settings import *

from pymrtd.pki.crl import CertificateRevocationList
from typing import List

logger = logging.getLogger(__name__)

class CrlStorageError(Exception):
    pass

class CrlStorage(object):
    """Class for interaaction between code structure and database"""
    _object = None
    _issuerCountry = None
    _size = None
    _thisUpdate = None
    _nextUpdate = None
    _signatureAlgorithm = None
    _signatureHashAlgorithm = None
    _fingerprint = None

    def __init__(self, crl: CertificateRevocationList, issuerCountry: str):
        """Initialization class with serialization of CRL"""
        self.size = crl.size
        self.issuerCountry = issuerCountry
        self.thisUpdate = crl.thisUpdate
        self.nextUpdate = crl.nextUpdate
        self.signatureAlgorithm = crl.signatureAlgorithm
        self.signatureHashAlgorithm = crl.signatureHashAlgorithm
        self.serializeCRL(crl)

    def serializeCRL(self, crl: CertificateRevocationList):
        """Function serialize CRL object to sequence"""
        self.object = crl.dump()

    def getObject(self) -> CertificateRevocationList:
        """Returns crl object"""
        return CertificateRevocationList.load(self.object)

#
#Storage management functions
#

def writeToDB_CRL(crl: CertificateRevocationList, issuerCountry: str, connection: Connection):
    """Write to database with ORM"""
    try:
        logger.info("Writing CRL object to database. Country: " + crl.issuerCountry)
        crls = CrlStorage(crl, issuerCountry)
        connection.getSession().add(crls)
        connection.getSession().commit()

    except Exception as e:
        raise CrlStorageError("Problem with writing the object: " + str(e))

def readFromDB_CRL(connection: Connection) -> List[CrlStorage]:
    """Reading from database"""
    try:
        logger.info("Reading CRL objects from database.")
        if connection.getSession().query(CrlStorage).count() > 0:
            return connection.getSession().query(CrlStorage).all()
        raise CrlStorageError("There is no CRL in database.")

    except Exception as e:
        raise CrlStorageError("Problem with reading the object: " + str(e))
