from collections import defaultdict
import logging

from abc import ABC, abstractmethod
from asn1crypto import x509
from datetime import datetime

from port.database.storage.storageManager import PortDatabaseConnection
from port.database.storage.challengeStorage import ChallengeStorage
from port.database.storage.accountStorage import AccountStorage
from port.database.storage.x509Storage import CertificateRevocationInfo, CertificateStorage, PkiDistributionUrl, CrlUpdateInfo, DscStorage, CscaStorage

from pymrtd.pki.x509 import Certificate, CscaCertificate, DocumentSignerCertificate
from sqlalchemy import or_
from sqlalchemy.orm.scoping import scoped_session
from typing import Final, List, NoReturn, Optional, Tuple, TypeVar, Union

from .challenge import CID, Challenge
from .user import UserId
from .types import CertificateId, CountryCode

class StorageAPIError(Exception):
    pass

class SeEntryNotFound(StorageAPIError):
    pass

class SeEntryAlreadyExists(StorageAPIError):
    pass

seAccountNotFound: Final   = SeEntryNotFound("Account not found")
seChallengeExists: Final   = SeEntryAlreadyExists("Challenge already exists")
seChallengeNotFound: Final = SeEntryNotFound("Challenge not found")
seCscaExists: Final        = SeEntryAlreadyExists("CSCA already exists")
seDscExists: Final         = SeEntryAlreadyExists("DSC already exists")

class StorageAPI(ABC):
    ''' Abstract storage interface for user data and MRTD trustchain certificates (CSCA, DSC) '''

    # Proto challenge methods
    @abstractmethod
    def getChallenge(self, cid: CID) -> Tuple[Challenge, datetime]:
        """
        Function fetches proto challenge from db and returns
        challenge and expiration time.

        :param cid: Challenge id
        :return: Tuple[Challenge, datetime]
        :raises:
            DatabaseAPIError: If challenge is not found
        """

    @abstractmethod
    def findChallengeByUID(self, uid: UserId) -> Optional[Tuple[Challenge, datetime]]:
        """
        Function tries to find proto challenge by user ID in the db, and returns
        challenge and expiration time.

        :param uid: User ID to searche the challenge for
        :return: Optional[Tuple[Challenge, datetime]]
        """

    @abstractmethod
    def addChallenge(self, uid: UserId, challenge: Challenge, expires: datetime) -> None:
        """
        Add challenge to storage.
        :param uid: User ID for which the challenge was created
        :param challenge:
        :param expires: The challenge expiration datetime.
        :raises: SeEntryAlreadyExists if challenge already exists for user
        """

    @abstractmethod
    def deleteChallenge(self, cid: CID) -> None:
        pass

    @abstractmethod
    def deleteExpiredChallenges(self, time: datetime) -> None:
        """
        Deletes all expired challenges from storage.
        :param time: Challenges that have expiration time less then time are deleted.
        """

    # User methods
    @abstractmethod
    def accountExists(self, uid: UserId) -> bool:
        pass

    @abstractmethod
    def addOrUpdateAccount(self, account: AccountStorage) -> None:
        pass

    @abstractmethod
    def deleteAccount(self, uid: UserId) -> None:
        pass

    @abstractmethod
    def getAccount(self, uid: UserId) -> AccountStorage:
        """ Get account """

    @abstractmethod
    def getAccountExpiry(self, uid: UserId) -> datetime:
        """ Get account's credentials expiry """

    # eMRTD PKI certificates methods
    @abstractmethod
    def addCsca(self, csca: CscaCertificate, issuerId: Optional[CertificateId] = None) -> CertificateId:
        """
        Inserts new CSCA certificate into database
        :param csca: CSCA certificate to insert into database.
        :param issuerId: The CSCA issuerId in case the CSCA is linked (Optional).
        :return: The CSCA CertificateId
        """


    @abstractmethod
    def addCscaStorage(self, csca: CscaStorage) -> None:
        """
        Inserts new CSCA certificate storage into database
        :param csca: CscaStorage to insert into database.
        :param issuerId: The CSCA issuerId in case the CSCA is linked (Optional).
        """

    @abstractmethod
    def findCsca(self, certId: CertificateId)-> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the id.
        :param certId: The certificate id to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """

    @abstractmethod
    def findCscaBySerial(self, issuer: x509.Name, serial: int) -> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the certificate serial number.
        :param issuer: CSCA issuer name.
        :param serial: CSCA serial number to search for.
        :return: CscaStorage, or None if no CSCA certificate was found.
        """

    @abstractmethod
    def findCscaCertificates(self, subject: x509.Name, subjectKey: Optional[bytes])-> Optional[List[CscaStorage]]:
        """
        Returns list of CSCA certificate storage objects that match eather the subject param or country code and subjectKey param.
        If the subjectKey is provided then the function first tries to query for the CSCAs by searching for CSCAs with specific
        subject country code and subjectKey. The reason for this is that querying by subject column might return invalid CSCA
        i.e. valid CSCAs for the country but invalid public key - invalid subjectKey, as the subject field can be the same between country's CSCAs.

        :param subject: Certificate subject name to search for.
        :param subjectKey: Certificate subject key to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """

    @abstractmethod
    def findCscaCertificatesBySubject(self, subject: x509.Name) -> Optional[List[CscaStorage]]:
        """
        Returns list of CSCA certificate storage objects that match the subject param.
        :param subject: Certificate subject name to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """

    @abstractmethod
    def findCscaCertificatesBySubjectKey(self, country: CountryCode, subjectKey: bytes) -> Optional[List[CscaStorage]]:
        """
        Returns list of CSCA certificate storage objects that match subjectKey.
        :param country: iso alpha-2 country code of the country that issued the CSCA.
        :param subjectKey: Certificate subject key to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """

    @abstractmethod
    def addDsc(self, dsc: DocumentSignerCertificate, issuerId: CertificateId) -> CertificateId:
        """
        Inserts new DSC certificate into database
        :param dsc: DSC certificate to insert into database.
        :param issuerId: The DSC issuerId.
        :return: The dsc CertificateId
        """

    @abstractmethod
    def findDsc(self, certId: CertificateId) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the certificate id.
        :param certId: The DSC certificate id.
        :return: DscStorage
        """

    @abstractmethod
    def findDscBySerial(self, issuer: x509.Name, serial: int) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the issuer name and serial number.
        :param issuer: The DSC certificate issuer.
        :param serial: The DSC certificate serial number.
        :return: DscStorage
        """

    @abstractmethod
    def findDscBySubjectKey(self, subjectKey: bytes) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the subjectKey.
        :param subjectKey: The DSC certificate subject key.
        :return: DscStorage
        """

    @abstractmethod
    def updateCrlInfo(self, crlui: CrlUpdateInfo) -> None:
        """
        Adds or updates CRL update info for country.
        :param crlui: CrlUpdateInfo
        """

    @abstractmethod
    def findCrlInfo(self, country: CountryCode) -> Optional[CrlUpdateInfo]:
        """
        Returns CRL update info for country.
        :param country: iso alpha-2 country code to retrieve the CRL update info.
        :return: Optional[CrlUpdateInfo]
        """

    @abstractmethod
    def updateCrl(self, country: CountryCode, crl: List[CertificateRevocationInfo]) -> None:
        """
        Replaces existing or/and adds new list of certificate revocation infos for country.
        Empty crl list param will delete all entries in the DB for the country.
        Note: Internally the list is updated with country param i.e.crl[idx].country = country

        :param country: The iso alpha-2 country code to merge the list of certificate revocation infos.
        :param crl: The list of CertificateRevocationInfo being revoked.
        """

    @abstractmethod
    def findCrl(self, country: CountryCode) -> Optional[List[CertificateRevocationInfo]]:
        """
        Returns list of infos about revoked certificates for country.
        :param country: The iso alpha-2 country code to get the list of certificate revocation infos for.
        :return: List of countries revoked certificate infos or None
        """

    @abstractmethod
    def isCertificateRevoked(self, crt: Union[Certificate, CertificateStorage]) -> bool:
        """
        Verifies in the DB if certificate is revoked.
        :param crt: The certificate or CertificateStorage to verify.
        :return: Returns True if certificate is revoked, otherwise False.
        """

    @abstractmethod
    def addPkiDistributionUrl(self, pkidUrl: PkiDistributionUrl) -> None:
        """
        Adds eeMRTD PKI distribution point URL address if it doesn't exist yet.
        :param pkidUrl: PkiDistributionUrl
        """

    @abstractmethod
    def findPkiDistributionUrls(self, country: CountryCode) -> Optional[List[PkiDistributionUrl]]:
        """
        Returns list of emRTD PKI distribution urls for country.
        :param country: The ios alpha-2 country code to retrieve the list of.
        :return: Optional[List[PkiDistributionUrl]]
        """

    @abstractmethod
    def deletePkiDistributionUrl(self, pkidId: int) -> None:
        """
        Deletes eMRTD PKI distribution url from DB.
        :param pkidId: The PkiDistributionUrl ID.
        """


class DatabaseAPIError(StorageAPIError):
    pass

class DatabaseAPI(StorageAPI):
    '''
    DatabaseAPI implements StorageAPI as persistent storage.
    It's defined as abstraction layer over class Connection (which uses PostgreSQL)
    to expose Connection interface to StorageAPI without mixing two interfaces.
    '''

    def __init__(self, dialect:str, host:str, db: str, username: str, password: str):
        '''
        Creates new ORM database connection.
        :param dialect: The database dialect e.g.:  mariadb, mysql, oracle, postgresql, sqlite.
        :param host: The database urlhost. Can be empty string in case of sqlite.
        :param db: The database path.
        :param username: The database username.
        :param password: The database password.
        :raises: PortDbConnectionError on error.
        '''
        self._log = logging.getLogger('proto.db.api')
        self._dbc = PortDatabaseConnection(dialect, host, db, username, password)

    @property
    def __db(self) -> scoped_session:
        return self._dbc.session

    def __handle_exception(self, e) -> NoReturn:
        if isinstance(e, StorageAPIError):
            raise e from e
        self._log.error('An exception was encountered while trying to transact with DB!')
        self._log.exception(e)
        raise DatabaseAPIError(e) from None

    def getChallenge(self, cid: CID) -> Tuple[Challenge, datetime]:
        """
        Function fetches challenge from db and returns
        challenge and expiration time.

        :param cid: Challenge id
        :return: Tuple[Challenge, datetime]
        :raises: DatabaseAPIError if challenge is not found, or DB connection error.
        """
        assert isinstance(cid, CID)
        try:
            cs = self.__db \
               .query(ChallengeStorage) \
               .filter(ChallengeStorage.id == cid) \
               .first()

            if cs is None:
                raise seChallengeNotFound
            c = cs.challenge
            t = cs.expires
            return (c, t)
        except Exception as e:
            self.__handle_exception(e)

    def findChallengeByUID(self, uid: UserId) -> Optional[Tuple[Challenge, datetime]]:
        """
        Function tries to find proto challenge by user ID in the db, and returns
        challenge and expiration time.

        :param uid: User ID to searche the challenge for
        :return: Optional[Tuple[Challenge, datetime]]
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(uid, UserId)
        try:
            cs = self.__db \
               .query(ChallengeStorage) \
               .filter(ChallengeStorage.uid == uid) \
               .first()

            if cs is None:
                return None
            c = cs.challenge
            t = cs.expires
            return (c, t)
        except Exception as e:
            self.__handle_exception(e)

    def addChallenge(self, uid: UserId, challenge: Challenge, expires: datetime) -> None:
        """
        Add challenge to storage.
        :param uid: User ID for which the challenge was created
        :param challenge:
        :param expires: The challenge expiration datetime.
        :raises:
            SeEntryAlreadyExists if challenge already exists for user
            DatabaseAPIError on DB connection errors.
        """
        assert isinstance(challenge, Challenge)
        assert isinstance(expires, datetime)
        try:
            cs = ChallengeStorage(uid, challenge, expires)

            if self.__db.query(ChallengeStorage) \
                .filter(or_(ChallengeStorage.id == challenge.id, ChallengeStorage.uid == uid))\
                .count() > 0:
                raise seChallengeExists

            self.__db.add(cs)
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def deleteChallenge(self, cid: CID) -> None:
        """
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(cid, CID)
        try:
            self.__db \
                .query(ChallengeStorage) \
                .filter(ChallengeStorage.id == cid) \
                .delete()
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def deleteExpiredChallenges(self, time: datetime) -> None:
        """
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(time, datetime)
        try:
            self.__db \
                .query(ChallengeStorage) \
                .filter(ChallengeStorage.expires < time) \
                .delete()
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def accountExists(self, uid: UserId) -> bool:
        """
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(uid, UserId)
        try:
            return self.__db \
                .query(AccountStorage) \
                .filter(AccountStorage.uid == uid) \
                .count() > 0
        except Exception as e:
            self.__handle_exception(e)

    def addOrUpdateAccount(self, account: AccountStorage) -> None:
        """
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(account, AccountStorage)
        self._log.debug("Adding or updating account in DB. uid=%s", account.uid)
        try:
            accnts = self.__db \
                .query(AccountStorage) \
                .filter(AccountStorage.uid == account.uid)
            if accnts.count() > 0:
                accnts[0].uid         = account.uid
                accnts[0].sod         = account.sod
                accnts[0].aaPublicKey = account.aaPublicKey
                accnts[0].sod         = account.sod
                accnts[0].dg1         = account.dg1
                accnts[0].session     = account.session
                accnts[0].validUntil  = account.validUntil
                accnts[0].loginCount  = account.loginCount
                accnts[0].isValid     = account.isValid
            else:
                self.__db.add(account)
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def getAccount(self, uid: UserId) -> AccountStorage:
        """
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(uid, UserId)
        try:
            accnt = self.__db \
                .query(AccountStorage) \
                .filter(AccountStorage.uid == uid) \
                .first()
            if accnt is None:
                raise seAccountNotFound
            assert isinstance(accnt, AccountStorage)
            return accnt
        except Exception as e:
            self.__handle_exception(e)

    def deleteAccount(self, uid: UserId) -> None:
        """
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(uid, UserId)
        try:
            self.__db \
                .query(AccountStorage) \
                .filter(AccountStorage.uid == uid) \
                .delete()
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def getAccountExpiry(self, uid: UserId) -> datetime:
        """
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(uid, UserId)
        try:
            accnt = self.__db \
                .query(AccountStorage) \
                .filter(AccountStorage.uid == uid) \
                .first()
            if accnt is None:
                self._log.debug(":getAccountExpiry(): Account not found")
                raise seAccountNotFound
            return accnt.validUntil
        except Exception as e:
            self.__handle_exception(e)

    def addCsca(self, csca: CscaCertificate, issuerId: Optional[CertificateId] = None) -> CertificateId:
        """
        Inserts new CSCA into database
        :param csca: CSCA certificate to insert into database.
        :param issuerId: The CSCA issuerId in case the CSCA is linked (Optional).
        :return: The csca CertificateId
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(csca, CscaCertificate)
        assert issuerId is None or isinstance(issuerId, CertificateId)
        try:
            cs = CscaStorage(csca, issuerId)
            self.addCscaStorage(cs)
            return cs.id
        except Exception as e:
            self.__handle_exception(e)

    def addCscaStorage(self, csca: CscaStorage) -> None: #pylint: disable=arguments-differ
        """
        Inserts new CSCA certificate storage into database
        :param csca: CscaStorage to insert into database.
        :param issuerId: The CSCA issuerId in case the CSCA is linked (Optional).
        :raises: DatabaseAPIError on DB connection errors.
                 SeEntryAlreadyExists if the same CSCA storage already exists.
        """
        assert isinstance(csca, CscaStorage)
        self._log.debug("Inserting new CSCA into database C=%s serial=%s", csca.country, csca.serial.hex())
        try:
            if self.__db.query(CscaStorage).filter(CscaStorage.id == csca.id).count() > 0:
                raise seCscaExists
            self.__db.add(csca)
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def findCsca(self, certId: CertificateId)-> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the id.
        :param certId: The certificate certId to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(certId, CertificateId)
        try:
            return self.__db \
                .query(CscaStorage) \
                .filter(CscaStorage.id == certId) \
                .first()
        except Exception as e:
            self.__handle_exception(e)

    def findCscaBySerial(self, issuer: x509.Name, serial: int) -> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the certificate serial number.
        :param issuer: CSCA issuer name.
        :param serial: CSCA serial number to search for.
        :return: CscaStorage, or None if no CSCA certificate was found.
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(issuer, x509.Name)
        assert isinstance(serial, int)
        try:
            serial = CertificateStorage.makeSerial(serial)
            return self.__db \
                .query(CscaStorage) \
                .filter(CscaStorage.issuer == issuer.human_friendly, CscaStorage.serial == serial) \
                .first()
        except Exception as e:
            self.__handle_exception(e)

    def findCscaCertificates(self, subject: x509.Name, subjectKey: Optional[bytes])-> Optional[List[CscaStorage]]:
        """
        Returns list of CSCA certificate storage objects that match eather the subject param or country code and subjectKey param.
        If the subjectKey is provided then the function first tries to query for the CSCAs by searching for CSCAs with specific
        subject country code and subjectKey. The reason for this is that querying by subject column might return invalid CSCA
        i.e. valid CSCAs for the country but invalid public key - invalid subjectKey, as the subject field can be the same between country's CSCAs.

        :param subject: Certificate subject name to search for.
        :param subjectKey: Certificate subject key to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(subject, x509.Name)
        try:
            # Try first to find CSCAs by subjectKey because
            # searching for subject might return invalid CSCAs
            cscas: Optional[List[CscaStorage]] = None
            if subjectKey is not None:
                assert isinstance(subjectKey, bytes)
                country = CountryCode(subject.native['country_name'])
                cscas = self.__db \
                    .query(CscaStorage) \
                    .filter(CscaStorage.country == country, CscaStorage.subjectKey == subjectKey) \
                    .all()

            if cscas is None:
                cscas = self.__db \
                    .query(CscaStorage) \
                    .filter(CscaStorage.subject == subject.human_friendly) \
                    .all()
            return cscas if len(cscas) != 0 else None
        except Exception as e:
            self.__handle_exception(e)

    def findCscaCertificatesBySubject(self, subject: x509.Name) -> Optional[List[CscaStorage]]:
        """
        Returns list of CSCA certificate storage objects that match the subject param.
        :param subject: Certificate subject name to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(subject, x509.Name)
        try:
            cscas = self.__db \
                .query(CscaStorage) \
                .filter(CscaStorage.subject == subject.human_friendly) \
                .all()
            return cscas if len(cscas) != 0 else None
        except Exception as e:
            self.__handle_exception(e)

    def findCscaCertificatesBySubjectKey(self, country: CountryCode, subjectKey: bytes) -> Optional[List[CscaStorage]]:
        """
        Returns list of CSCA certificate storage objects that match subjectKey.
        :param country: iso alpha-2 country code of the country that issued the CSCA.
        :param subjectKey: Certificate subject key to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(subjectKey, bytes)
        assert isinstance(country, CountryCode)
        try:
            cscas = self.__db \
                .query(CscaStorage) \
                .filter(CscaStorage.country == country, CscaStorage.subjectKey == subjectKey) \
                .all()
            return cscas if len(cscas) != 0 else None
        except Exception as e:
            self.__handle_exception(e)

    def addDsc(self, dsc: DocumentSignerCertificate, issuerId: CertificateId) -> CertificateId:
        """
        Inserts new DSC certificate into database
        :param dsc: DSC certificate to insert into database.
        :param issuerId: The DSC issuerId.
        :return: The dsc CertificateId
        :raises: DatabaseAPIError on DB connection errors.
        """
        self._log.debug("Inserting new DSC into database C={} serial={}"
            .format(CountryCode(dsc.issuerCountry), dsc.serial_number))

        assert isinstance(dsc, DocumentSignerCertificate)
        assert isinstance(issuerId, CertificateId)
        try:
            ds = DscStorage(dsc, issuerId)
            if self.__db.query(DscStorage).filter(DscStorage.id == ds.id).count() > 0:
                raise seDscExists

            self.__db.add(ds)
            self.__db.commit()
            return ds.id
        except Exception as e:
            self.__handle_exception(e)

    def findDsc(self, certId: CertificateId) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the certificate id.
        :param certId: The DSC certificate id.
        :return: DscStorage
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(certId, CertificateId)
        try:
            return self.__db \
                .query(DscStorage) \
                .filter(DscStorage.id == certId) \
                .first()
        except Exception as e:
            self.__handle_exception(e)

    def findDscBySerial(self, issuer: x509.Name, serial: int) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the issuer name and serial number.
        :param issuer: The DSC certificate issuer.
        :param serial: The DSC certificate serial number.
        :return: DscStorage
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(issuer, x509.Name)
        assert isinstance(serial, int)
        try:
            serial = CertificateStorage.makeSerial(serial)
            return self.__db \
                .query(DscStorage) \
                .filter(DscStorage.issuer == issuer.human_friendly, DscStorage.serial == serial) \
                .first()
        except Exception as e:
            self.__handle_exception(e)

    def findDscBySubjectKey(self, subjectKey: bytes) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the subjectKey.
        :param subjectKey: The DSC certificate subject key.
        :return: DscStorage
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(subjectKey, bytes)
        try:
            return self.__db \
                .query(DscStorage) \
                .filter(DscStorage.subjectKey == subjectKey) \
                .first()
        except Exception as e:
            self.__handle_exception(e)

    def updateCrlInfo(self, crlui: CrlUpdateInfo) -> None:
        """
        Adds or updates CRL update info for country.
        :param crlui: CrlUpdateInfo
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(crlui, CrlUpdateInfo)
        self._log.debug("Updating CRL update info for C=%s", crlui.country)
        try:
            ci = self.__db \
                .query(CrlUpdateInfo) \
                .filter(CrlUpdateInfo.country == crlui.country) \
                .first()
            if ci is None:
                self.__db.add(crlui)
            else:
                ci = crlui
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def findCrlInfo(self, country: CountryCode) -> Optional[CrlUpdateInfo]:
        """
        Returns CRL update info for country.
        :param country: iso alpha-2 country code to retrieve the CRL update info.
        :return: Optional[CrlUpdateInfo]
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(country, CountryCode)
        try:
            return self.__db \
                .query(CrlUpdateInfo) \
                .filter(CrlUpdateInfo.country == country) \
                .first()
        except Exception as e:
            self.__handle_exception(e)

    def updateCrl(self, country: CountryCode, crl: List[CertificateRevocationInfo]) -> None:
        """
        Replaces existing or/and adds new list of certificate revocation infos for country.
        Empty crl list param will delete all entries in the DB for the country.
        Note: Internally the list is updated with country param i.e.crl[idx].country = country

        :param country: The iso alpha-2 country code to merge the list of certificate revocation infos.
        :param crl: The list of CertificateRevocationInfo being revoked.
        :raises: DatabaseAPIError on DB connection errors.
                 AssertionError if assert failed and enabled when python not run with -O or -OO flag.
        """
        assert isinstance(crl, List) and all(isinstance(x, CertificateRevocationInfo) for x in crl)
        self._log.debug("Updating CRL for C=%s", country)
        try:
            # First delete any existing entry for country
            self.__db \
                .query(CertificateRevocationInfo) \
                .filter(CertificateRevocationInfo.country == country) \
                .delete()

            # Set country and check certId (debug mode)
            for c in crl:
                c.country = country
                # Debug sanity check for certId
                # This should not execute in production mode, i.e. when run python with -O or -OO flag
                if __debug__ is not None and __debug__ == True:
                    if c.certId is not None:
                        d = self.findDsc(c.certId)
                        assert d is None or d.country == country

            self.__db.add_all(crl)
            self.__db.commit()
        except AssertionError:
            raise
        except Exception as e:
            self.__handle_exception(e)

    def findCrl(self, country: CountryCode) -> Optional[List[CertificateRevocationInfo]]:
        """
        Returns list of infos about revoked certificates for country.
        :param country: The iso alpha-2 country code to get the list of certificate revocation infos for.
        :return: List of countries revoked certificate infos or None
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(country, CountryCode)
        try:
            crl = self.__db \
                .query(CertificateRevocationInfo) \
                .filter(CertificateRevocationInfo.country == country) \
                .all()
            return crl if len(crl) != 0 else None
        except Exception as e:
            self.__handle_exception(e)

    def isCertificateRevoked(self, crt: Union[Certificate, CertificateStorage]) -> bool:
        """
        Verifies in the DB if certificate is revoked.
        :param crt: The certificate or CertificateStorage to verify.
        :return: Returns True if certificate is revoked, otherwise False.
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(crt, Certificate) or isinstance(crt, CertificateStorage)
        try:
            q = self.__db.query(CertificateRevocationInfo)
            if isinstance(crt, Certificate):
                certId = CertificateId.fromCertificate(crt)
                serial = CertificateStorage.makeSerial(crt.serial_number)
                q.filter_by(country = CountryCode(crt.issuerCountry)) \
                 .filter(or_(CertificateRevocationInfo.certId == certId,
                             CertificateRevocationInfo.serial == serial))
            else: # CertificateStorage
                q.filter_by(country = crt.country) \
                 .filter(or_(CertificateRevocationInfo.certId == crt.id,
                             CertificateRevocationInfo.serial == crt.serial))

            return q.first() is not None
        except Exception as e:
            self.__handle_exception(e)

    def addPkiDistributionUrl(self, pkidUrl: PkiDistributionUrl) -> None:
        """
        Adds eMRTD PKI distribution point URL address if it doesn't exist yet.
        :param pkidUrl: PkiDistributionUrl
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(pkidUrl, PkiDistributionUrl)
        self._log.debug("Adding PKI distribution URL. C=%s id=%s", pkidUrl.country, pkidUrl.id)
        try:
            self.__db.merge(pkidUrl)
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def findPkiDistributionUrls(self, country: CountryCode) -> Optional[List[PkiDistributionUrl]]:
        """
        Returns list of emRTD PKI distribution urls for country.
        :param country: The ios alpha-2 country code to retrieve the list of.
        :return: Optional[List[PkiDistributionUrl]]
        """
        assert isinstance(country, CountryCode)
        try:
            crl = self.__db \
                .query(PkiDistributionUrl) \
                .filter_by(country = country) \
                .all()
            return crl if len(crl) != 0 else None
        except Exception as e:
            self.__handle_exception(e)

    def deletePkiDistributionUrl(self, pkidId: int) -> None:
        """
        Deletes eMRTD PKI distribution url from DB.
        :param pkidId: The PkiDistributionUrl ID.
        """
        assert isinstance(pkidId, int)
        self._log.debug("Deleting PKI distribution URL from DB. id=%s", pkidId)
        try:
            self.__db \
                .query(PkiDistributionUrl) \
                .filter(PkiDistributionUrl.id == pkidId) \
                .delete()
        except Exception as e:
            self.__handle_exception(e)


class MemoryDBError(StorageAPIError):
    pass

class MemoryDB(StorageAPI):
    '''
    MemoryDB implements StorageAPI as non-peristent database.
    The data is stored in memory (RAM) and gets deleted as instance of MemoryDB is destroyed.
    The purpose of MemoryDB is testing of port proto without needing to set up (or reset) proper database.
    Internally data is stored as dictionary in 4 categories:
        proto_challenges -> Dictionary[CID, Tuple[UserId, Challenge, datetime - expires]]
        accounts         -> Dictionary[UserId, AccountStorage]
        cscas            -> Set[List[CscaStorage]]
        dscs             -> Set[DscStorage]
    '''

    def __init__(self):
        self._log = logging.getLogger(MemoryDB.__name__)
        self._d = {
            'proto_challenges' : {},
            'accounts' : {},
            'cscas' : defaultdict(list), # <country, List[CscaStorage]>
            'dscs' : set(),
            'crlui' : {},
            'crt' : {},
            'pkidurl' : {}
        }

    def getChallenge(self, cid: CID) -> Tuple[Challenge, datetime]:
        """
        Function fetches challenge from db and returns
        challenge and expiration time.

        :param cid: Challenge id
        :return: Tuple[Challenge, datetime]
        :raises: SeEntryAlreadyExists if challenge is not found
        """
        assert isinstance(cid, CID)
        try:
            _, c, et = self._d['proto_challenges'][cid]
            return (c, et)
        except Exception as e:
            raise seChallengeNotFound from e

    def findChallengeByUID(self, uid: UserId) -> Optional[Tuple[Challenge, datetime]]:
        """
        Function tries to find proto challenge by user ID in the db, and returns
        challenge and expiration time.

        :param uid: User ID to searche the challenge for
        :return: Optional[Tuple[Challenge, datetime]]
        """
        assert isinstance(uid, UserId)
        for _, (suid, c, et) in self._d['proto_challenges'].items():
            if suid == uid:
                return (c, et)
        return None

    def addChallenge(self, uid: UserId, challenge: Challenge, expires: datetime) -> None:
        """
        Add challenge to storage.
        :param uid: User ID for which the challenge was created
        :param challenge:
        :param expires: The challenge expiration datetime.
        :raises: SeEntryAlreadyExists if challenge already exists for user
        """
        assert isinstance(challenge, Challenge)
        assert isinstance(expires, datetime)
        if challenge.id in self._d['proto_challenges']:
            raise seChallengeExists

        for _, (suid, _, _) in self._d['proto_challenges'].items():
            if suid == uid:
                raise seChallengeExists
        self._d['proto_challenges'][challenge.id] = (uid, challenge, expires)

    def deleteChallenge(self, cid: CID) -> None:
        assert isinstance(cid, CID)
        if cid in self._d['proto_challenges']:
            self._d['proto_challenges'].pop(cid)

    def deleteExpiredChallenges(self, time: datetime) -> None:
        assert isinstance(time, datetime)
        d = { cid:(uid, c, cet)
            for cid, (uid, c, cet) in self._d['proto_challenges'].items()
            if cet >= time }
        self._d['proto_challenges'] = d

    def accountExists(self, uid: UserId) -> bool:
        assert isinstance(uid, UserId)
        return uid in self._d['accounts']

    def addOrUpdateAccount(self, account: AccountStorage) -> None:
        assert isinstance(account, AccountStorage)
        self._d['accounts'][account.uid] = account

    def getAccount(self, uid: UserId) -> AccountStorage:
        assert isinstance(uid, UserId)
        if uid not in self._d['accounts']:
            raise seAccountNotFound
        return self._d['accounts'][uid]

    def deleteAccount(self, uid: UserId) -> None:
        assert isinstance(uid, UserId)
        if uid in self._d['accounts']:
            del self._d['accounts'][uid]

    def getAccountExpiry(self, uid: UserId) -> datetime:
        assert isinstance(uid, UserId)
        if uid not in self._d['accounts']:
            raise seAccountNotFound
        a = self.getAccount(uid)
        return a.validUntil

    def addCsca(self, csca: CscaCertificate, issuerId: Optional[CertificateId] = None) -> CertificateId:
        """
        Adds new CSCA into database
        :param csca: CSCA certificate to insert into database.
        :param issuerId: The CSCA issuerId in case the CSCA is linked (Optional).
        :return: The csca CertificateId
        """
        assert isinstance(csca, CscaCertificate)
        assert issuerId is None or isinstance(issuerId, CertificateId)

        cs = CscaStorage(csca, issuerId)
        self.addCscaStorage(cs)
        return cs.id

    def addCscaStorage(self, csca: CscaStorage) -> None: #pylint: disable=arguments-differ
        """
        Inserts new CSCA certificate storage into database
        :param csca: CscaStorage to insert into database.
        :param issuerId: The CSCA issuerId in case the CSCA is linked (Optional).
        :raises: DatabaseAPIError on DB connection errors.
                 SeEntryAlreadyExists if the same CSCA storage already exists.
        """
        assert isinstance(csca, CscaStorage)
        self._log.debug("Inserting new CSCA into database C=%s serial=%s", csca.country, csca.serial.hex())
        for c in self._d['cscas'][csca.country]:
            if c.id == csca.id:
                raise seCscaExists
        self._d['cscas'][csca.country].append(csca)

    def findCsca(self, certId: CertificateId)-> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the id.
        :param certId: The certificate id to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """
        assert isinstance(certId, CertificateId)
        for _, cscas in self._d['cscas'].items():
            for csca in cscas:
                if csca.id == certId:
                    return csca
        return None

    def findCscaBySerial(self, issuer: x509.Name, serial: int) -> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the certificate serial number.
        :param issuer: CSCA issuer name.
        :param serial: CSCA serial number to search for.
        :return:
        """
        country = CountryCode(issuer.native['country_name'])
        for csca in self._d['cscas'][country]:
            if csca.issuer == issuer.human_friendly and csca.serialNumber == serial:
                return csca
        return None

    def findCscaCertificates(self, subject: x509.Name, subjectKey: Optional[bytes])-> Optional[List[CscaStorage]]:
        """
        Returns list of CSCA certificate storage objects that match eather the subject param or country code and subjectKey param.
        If the subjectKey is provided then the function first tries to query for the CSCAs by searching for CSCAs with specific
        subject country code and subjectKey. The reason for this is that querying by subject column might return invalid CSCA
        i.e. valid CSCAs for the country but invalid public key - invalid subjectKey, as the subject field can be the same between country's CSCAs.

        :param subject: Certificate subject name to search for.
        :param subjectKey: Certificate subject key to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """
        assert isinstance(subject, x509.Name)
        if subjectKey is None:
            subjectKey = b''
        cscas = []
        country = CountryCode(subject.native['country_name'])
        for csca in self._d['cscas'][country]:
            if csca.subject == subject.human_friendly or \
               csca.subjectKey == subjectKey:
                cscas.append(csca)

        # Filter out cscas with different subject key
        if len(subjectKey) > 0:
            cscas = [ c for c in cscas if c.subjectKey == subjectKey]
        return cscas if len(cscas) != 0 else None

    def findCscaCertificatesBySubject(self, subject: x509.Name) -> Optional[List[CscaStorage]]:
        """
        Returns list of CSCA storage objects that match the subject param.
        :param subject: Certificate subject name to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """
        assert isinstance(subject, x509.Name)
        cscas = []
        country = CountryCode(subject.native['country_name'])
        for csca in self._d['cscas'][country]:
            if csca.subject == subject.human_friendly:
                cscas.append(csca)
        return cscas if len(cscas) != 0 else None

    def findCscaCertificatesBySubjectKey(self, country: CountryCode, subjectKey: bytes) -> Optional[List[CscaStorage]]:
        """
        Returns list of CSCA storage objects that match subjectKey.
        :param country: iso alpha-2 country code of the country that issued the CSCA.
        :param subjectKey: Certificate subject key to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """
        assert isinstance(subjectKey, bytes)
        assert isinstance(country, CountryCode)
        cscas = []
        for csca in self._d['cscas'][country]:
            if csca.subjectKey == subjectKey:
                cscas.append(csca)
        return cscas if len(cscas) != 0 else None

    def addDsc(self, dsc: DocumentSignerCertificate, issuerId: CertificateId) -> CertificateId:
        """
        Adds new DSC certificate into database
        :param csca: DSC certificate to insert into database.
        :param issuerId: The DSC issuerId in case the CSCA is linked (Optional).
        :return: The dsc CertificateId
        """
        self._log.debug("Inserting new CSCA into database C={} serial={}"
            .format(CountryCode(dsc.issuerCountry), dsc.serial_number))

        assert isinstance(dsc, DocumentSignerCertificate)
        assert issuerId is None or isinstance(issuerId, CertificateId)

        ds = DscStorage(dsc, issuerId)
        for c in self._d['dscs']:
            if c.id == ds.id:
                raise seDscExists
        self._d['dscs'].add(ds)
        return ds.id

    def findDsc(self, certId: CertificateId) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the certificate id.
        :param certId: The DSC certificate id.
        :return: DscStorage
        """
        assert isinstance(certId, CertificateId)
        for dsc in self._d['dscs']:
            if dsc.id == certId:
                return dsc
        return None

    def findDscBySerial(self, issuer: x509.Name, serial: int) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the issuer name and serial number.
        :param issuer: The DSC certificate issuer.
        :param serial: The DSC certificate serial number.
        :return: DscStorage
        """
        assert isinstance(issuer, x509.Name)
        assert isinstance(serial, int)
        for dsc in self._d['dscs']:
            if dsc.issuer == issuer and dsc.serialNumber == serial:
                return dsc
        return None

    def findDscBySubjectKey(self, subjectKey: bytes) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the subjectKey.
        :param subjectKey: The DSC certificate subject key.
        :return: DscStorage
        """
        assert isinstance(subjectKey, bytes)
        for dsc in self._d['dscs']:
            if dsc.subjectKey == subjectKey:
                return dsc
        return None

    def updateCrlInfo(self, crlui: CrlUpdateInfo) -> None:
        """
        Adds or updates CRL update info for country.
        :param crlui: CrlUpdateInfo
        """
        assert isinstance(crlui, CrlUpdateInfo)
        self._d['crlui'][crlui.country] = crlui

    def findCrlInfo(self, country: CountryCode) -> Optional[CrlUpdateInfo]:
        """
        Returns CRL update info for country.
        :param country: iso alpha-2 country code to retrieve the CRL update info.
        :return: Optional[CrlUpdateInfo]
        """
        assert isinstance(country, CountryCode)
        if country in self._d['crlui']:
            return self._d['crlui'][country]
        return None

    def updateCrl(self, country: CountryCode, crl: List[CertificateRevocationInfo]) -> None:
        """
        Replaces existing or/and adds new list of certificate revocation infos for country.
        Empty crl list param will delete all entries in the DB for the country.
        Note: Internally the list is updated with country param i.e.crl[idx].country = country

        :param country: The iso alpha-2 country code to merge the list of certificate revocation infos.
        :param crl: The list of CertificateRevocationInfo being revoked.
        """
        assert isinstance(country, CountryCode)
        assert isinstance(crl, List) and all(isinstance(x, CertificateRevocationInfo) for x in crl)
        for c in crl:
            c.country = country
            # Debug sanity check for certId
            # This should not execute in production mode, i.e. when run python with -O or -OO flag
            if __debug__ is not None and __debug__ == True:
                if c.certId is not None:
                    d = self.findDsc(c.certId)
                    assert d is None or d.country == country
        self._d['crt'][country] = crl

    def findCrl(self, country: CountryCode) -> Optional[List[CertificateRevocationInfo]]:
        """
        Returns list of infos about revoked certificates for country.
        :param country: The iso alpha-2 country code to get the list of certificate revocation infos for.
        """
        assert isinstance(country, CountryCode)
        if country in self._d['crt']:
            return self._d['crt'][country]
        return None

    def isCertificateRevoked(self, crt: TypeVar("T",Certificate, CertificateStorage)) -> bool:
        """
        Verifies in the DB if certificate is revoked.
        :param crt: The certificate to verify.
        :return: Returns True if certificate is revoked, otherwise False.
        """
        assert isinstance(crt, Certificate) or isinstance(crt, CertificateStorage)
        if isinstance(crt, Certificate):
            certId = CertificateId.fromCertificate(crt)
            serial = CertificateStorage.makeSerial(crt.serial_number)
            country = CountryCode(crt.issuerCountry)
        else: # CertificateStorage
            country = crt.country
            certId = crt.id
            serial = crt.serial

        if country in self._d['crt']:
            for cr in self._d['crt'][country]:
                if cr.certId == certId or serial == cr.serial:
                    return True
        return False

    def addPkiDistributionUrl(self, pkidUrl: PkiDistributionUrl) -> None:
        """
        Adds eMRTD PKI distribution point URL address if it doesn't exist yet.
        :param pkidUrl: PkiDistributionUrl
        """
        assert isinstance(pkidUrl, PkiDistributionUrl)
        if pkidUrl.id not in self._d['pkidurl']:
            self._d['pkidurl'][pkidUrl.id] = pkidUrl

    def findPkiDistributionUrls(self, country: CountryCode) -> Optional[List[PkiDistributionUrl]]:
        """
        Returns list of emRTD PKI distribution urls for country.
        :param country: The ios alpha-2 country code to retrieve the list of.
        :return: Optional[List[PkiDistributionUrl]]
        """
        assert isinstance(country, CountryCode)
        urlList = []
        for _, pkiUrl in self._d['pkidurl'].items():
            if pkiUrl.country == country:
                urlList.append(pkiUrl)
        return urlList

    def deletePkiDistributionUrl(self, pkidId: int) -> None:
        """
        Deletes eMRTD PKI distribution url from DB.
        :param pkidId: The PkiDistributionUrl ID.
        """
        if pkidId in self._d['pkidurl']:
            self._d['pkidurl'].pop(pkidId)
