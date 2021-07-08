import logging

from abc import ABC, abstractmethod
from asn1crypto import x509
from datetime import datetime

from port.database.storage.storageManager import PortDatabaseConnection
from port.database.storage.challengeStorage import ChallengeStorage
from port.database.storage.accountStorage import AccountStorage
from port.database.storage.x509Storage import DscStorage, CscaStorage
from port.proto.utils import int_to_bytes

from pymrtd.pki.x509 import Certificate, CscaCertificate, DocumentSignerCertificate
from sqlalchemy import or_
from sqlalchemy.orm.scoping import scoped_session
from typing import Final, List, NoReturn, Optional, Tuple

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
        :returns: DscStorage
        """

    @abstractmethod
    def findDscBySerial(self, issuer: x509.Name, serial: int) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the issuer name and serial number.
        :param issuer: The DSC certificate issuer.
        :param serial: The DSC certificate serial number.
        :returns: DscStorage
        """

    @abstractmethod
    def findDscBySubjectKey(self, subjectKey: bytes) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the subjectKey.
        :param subjectKey: The DSC certificate subject key.
        :returns: DscStorage
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
        self._log.debug("Inserting new CSCA into database C={} serial={}"
            .format(CountryCode(csca.issuerCountry), csca.serial_number))

        assert isinstance(csca, CscaCertificate)
        assert issuerId is None or isinstance(issuerId, CertificateId)
        try:
            cs = CscaStorage(csca, issuerId)
            if self.__db.query(CscaStorage).filter(CscaStorage.id == cs.id).count() > 0:
                raise seCscaExists
            self.__db.add(cs)
            self.__db.commit()
            return cs.id
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
            serial = int_to_bytes(serial)
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
        :returns: DscStorage
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
        :returns: DscStorage
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(issuer, x509.Name)
        assert isinstance(serial, int)
        try:
            serial = int_to_bytes(serial)
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
        :returns: DscStorage
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
            'cscas' : set(),
            'dscs' : set(),
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
        self._log.debug("Inserting new CSCA into database C={} serial={}"
            .format(CountryCode(csca.issuerCountry), csca.serial_number))

        assert isinstance(csca, CscaCertificate)
        assert issuerId is None or isinstance(issuerId, CertificateId)

        cs = CscaStorage(csca, issuerId)
        for c in self._d['cscas']:
            if c.id == cs.id:
                raise seCscaExists
        self._d['cscas'].add(cs)
        return cs.id

    def findCsca(self, certId: CertificateId)-> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the id.
        :param certId: The certificate id to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """
        assert isinstance(certId, CertificateId)
        for csca in self._d['cscas']:
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
        serial = int_to_bytes(serial)
        for csca in self._d['cscas']:
            if csca.issuer == issuer and csca.serial == serial:
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
        for csca in self._d['cscas']:
            if csca.subject == subject.human_friendly or \
               (csca.country == country and csca.subjectKey == subjectKey):
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
        for csca in self._d['cscas']:
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
        for csca in self._d['cscas']:
            if csca.country == country and csca.subjectKey == subjectKey:
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
        :returns: DscStorage
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
        :returns: DscStorage
        """
        assert isinstance(issuer, x509.Name)
        assert isinstance(serial, int)
        for dsc in self._d['dscs']:
            if dsc.issuer == issuer and dsc.serial_number == serial:
                return dsc
        return None

    def findDscBySubjectKey(self, subjectKey: bytes) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the subjectKey.
        :param subjectKey: The DSC certificate subject key.
        :returns: DscStorage
        """
        assert isinstance(subjectKey, bytes)
        for dsc in self._d['dscs']:
            if dsc.subjectKey == subjectKey:
                return dsc
        return None
