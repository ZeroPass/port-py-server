import logging
from asn1crypto.cms import CertificateRevocationLists
from port.proto.utils import bytes_to_int

from port.settings import *
from port.database.storage.storageManager import PortDatabaseConnection
from port.database.storage.x509Storage import CrlUpdateInfo, CscaStorage, DscStorage
from port.proto.types import CountryCode

from pymrtd.pki.crl import CertificateRevocationList
from pymrtd.pki.x509 import CscaCertificate, DocumentSignerCertificate
from typing import List


#
#Storage management functions
#

logger = logging.getLogger(__name__)

class CscaStorageError(Exception):
    pass

class DscStorageError(Exception):
    pass

class CrlStorageError(Exception):
    pass

def writeToDB_CSCA(csca: CscaCertificate, connection: PortDatabaseConnection):
    """Write to database with ORM"""
    try:
        logger.info("Writing CSCA object to database. Country: " + CountryCode(csca.issuerCountry))
        connection.getSession().add(CscaStorage(csca))
        connection.getSession().commit()

    except Exception as e:
        raise CrlStorageError("Problem with writing the object") from e

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

def writeToDB_CRL(crl: CertificateRevocationList, connection: PortDatabaseConnection):
    """Write to database with ORM"""
    try:
        logger.info("Writing CRL object to database. Country: " + CountryCode(crl.issuerCountry))
        country = CountryCode(crl.issuerCountry)
        crlInfo = connection.getSession() \
            .query(CrlUpdateInfo) \
            .filter(CrlUpdateInfo.country == country) \
            .first()

        exists = crlInfo is not None
        if exists:
            doUpdate = crl.thisUpdate >= crlInfo.nextUpdate
            if crl.crl_number_value is not None and crlInfo.crlNumber is not None:
                doUpdate = doUpdate and (crl.crl_number_value.native > bytes_to_int(crlInfo.crlNumber))
            if not doUpdate:
                logger.info("Skipping CRL update, provided CRL is same or older than current")
                return

        crlInfo = CrlUpdateInfo.fromCrl(crl) #TODO: check that this updates the entry in the database
        if not exists:
            connection.getSession().add(crlInfo)

        if crl.revokedCertificates is not None:
            for rci in crl.revokedCertificates:
                serial  = rci['user_certificate'].native
                revDate = rci['revocation_date'].chosen.native

                #TODO: find certificate id in the database

                #TODO: the CertificateRevocationInfo should be merged rather than added since the existing entry could be already present
                #TODO: verify status since the certificate could be unrevoked
                connection.getSession().add(CertificateRevocationLists(country, serial, revDate))

        connection.getSession().commit()

    except Exception as e:
        raise CrlStorageError("Problem with writing the object") from e

def readFromDB_CRL(connection: PortDatabaseConnection) -> List[CrlUpdateInfo]:
    """Reading from database"""
    try:
        logger.info("Reading CRL objects from database.")
        if connection.getSession().query(CrlUpdateInfo).count() > 0:
            return connection.getSession().query(CrlUpdateInfo).all()
        raise CrlStorageError("There is no CRL in database.")

    except Exception as e:
        raise CrlStorageError("Problem with reading the object") from e


def writeToDB_DSC(dsc: DocumentSignerCertificate, connection: PortDatabaseConnection):
    """Write to database with ORM"""
    try:
        logger.info("Writing DSC object to database. Country: " + CountryCode(dsc.issuerCountry))
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


class FilterError(Exception):
    pass

class Filter:
    """Filtration of CSCA, eCSCA and DSCs"""

    def __init__(self, crl: CertificateRevocationList, connection: PortDatabaseConnection):
        """Start the process"""
        try:
            self._log = logging.getLogger(Filter.__name__)
            issuer = self.getIssuer(crl)
            for item in crl['tbs_cert_list']['revoked_certificates']:
                self.deleteCertificateByIssuerAndSerialNumber(issuer, item["user_certificate"], connection)
        except Exception as e:
            raise FilterError("Error in iterateCRL function: " + e) from e


    def getIssuer(self, crl: CertificateRevocationList):
        """Get human readable issuer"""
        return crl.issuer.human_friendly

    def findConnectedCertificatesUnderCSCA(self, CSCA, connection: PortDatabaseConnection) -> List[DscStorage]:
        """Find connected certificates by both modes"""
        DSCsMode1 = self.checkByIssuerDSC(CSCA.subject, connection)
        DSCsMode2 = self.checkBySubjectKeyDSC(CSCA.subjectKey, connection)
        return DSCsMode1 + DSCsMode2

    def findConnectedCertificatesCSCAtoLCSCA(self, CSCA, connection: PortDatabaseConnection):
        """Find connected certificates: if two CSCA have the same subjectKey"""
        return readFromDB_CSCA_authorityKey(CSCA.subjectKey, connection)

    def checkByIssuerDSC(self, issuer: str, connection: PortDatabaseConnection) -> List[DscStorage]:
        """Check connection between certificates by first mode (issuer and serial number)"""
        return readFromDB_DSC_issuer(issuer, connection)

    def checkBySubjectKeyDSC(self, subjectKey: bytes, connection: PortDatabaseConnection) -> List[DscStorage]:
        """Check connection between certificate by second mode (CSCA subject key t0 DSC authority key) //subject key is actually authority key in the DSC"""
        return readFromDB_DSC_authorityKey(subjectKey, connection)


    def deleteCertificateByIssuerAndSerialNumber(self, issuer, serialNumber, connection: PortDatabaseConnection) -> None:
        """Find in database certificates with selected issuer and serial number"""
        self._log.debug("Find linked certificates with issuer: " + issuer + " and serial number:" + str(serialNumber))

        dataDSC = readFromDB_DSC_issuer_serialNumber(issuer, serialNumber, connection)
        dataCSCA = readFromDB_CSCA_issuer_serialNumber(issuer, serialNumber, connection)

        lengthDSC = len(dataDSC)
        lengthCSCA = len(dataCSCA)
        if lengthDSC and lengthCSCA == 0:
            self._log.debug("Linked certificate not found.")
            return

        if lengthDSC > 0:
            deleteFromDB_DSC(dataDSC, connection)

        foundItemsLCSCA = []
        if lengthCSCA > 0:
            # Add other CSCAs that are connected to first one
            foundItemsLCSCA = self.findConnectedCertificatesCSCAtoLCSCA(dataCSCA[0], connection)
            # merge first CSCA with connected ones
            foundItemsLCSCA.append(dataCSCA[0])

        for item in foundItemsLCSCA:
            #delete from database all CSCAs and belonging DSCAs to it
            foundItemsDSC = self.findConnectedCertificatesUnderCSCA(item, connection)

            if len(foundItemsDSC) > 0:
                # Delete DSCs
                deleteFromDB_DSC(foundItemsDSC, connection)

            # delete CSCA
            deleteFromDB_CSCA([item], connection)
