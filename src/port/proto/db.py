import logging

from .challenge import CID, Challenge
from .user import UserId
from .types import CertificateId, CountryCode

from abc import ABC, abstractmethod
from asn1crypto import x509
from datetime import datetime

from port.database.storage.storageManager import PortDatabaseConnection
from port.database.storage.challengeStorage import *
from port.database.storage.accountStorage import AccountStorage
from port.database.storage.x509Storage import DscStorage, CscaStorage
from port.proto.utils import int_to_bytes

from pymrtd.pki.x509 import Certificate, CscaCertificate, DocumentSignerCertificate
from sqlalchemy import or_
from typing import List, Optional, Tuple

class StorageAPIError(Exception):
    pass

class SeEntryNotFound(StorageAPIError):
    pass

class SeEntryAlreadyExists(StorageAPIError):
    pass

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
        pass

    @abstractmethod
    def addChallenge(self, uid: UserId, challenge: Challenge, expires: datetime) -> None:
        """
        Add challenge to storage.
        :param uid: User ID for which the challenge was created
        :param challenge:
        :param expires: The challenge expiration datetime.
        :raise: SeEntryAlreadyExists if challenge already exists for user
        """
        pass

    @abstractmethod
    def deleteChallenge(self, cid: CID) -> None:
        pass

    @abstractmethod
    def deleteExpiredChallenges(self, time: datetime) -> None:
        """
        Deletes all expired challenges from storage.
        :param time: Challenges that have expiration time less then time are deleted.
        """
        pass

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
        pass

    @abstractmethod
    def getAccountExpiry(self, uid: UserId) -> datetime:
        """ Get account's credentials expiry """
        pass

    # EMRTD PKI certificates methods
    @abstractmethod
    def addCsca(self, csca: CscaCertificate, issuerId: Optional[CertificateId] = None) -> CertificateId:
        """
        Inserts new CSCA certificate into database
        :param csca: CSCA certificate to insert into database.
        :param issuerId: The CSCA issuerId in case the CSCA is linked (Optional).
        :return: The CSCA CertificateId
        """
        pass

    @abstractmethod
    def findCsca(self, id: CertificateId)-> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the id.
        :param id: The certificate id to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """
        pass

    @abstractmethod
    def findCscaBySerial(self, issuer: x509.Name, serial: int) -> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the certificate serial number.
        :param issuer: CSCA issuer name.
        :param serial: CSCA serial number to search for.
        :return: CscaStorage, or None if no CSCA certificate was found.
        """
        pass

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
        pass

    @abstractmethod
    def findCscaCertificatesBySubject(self, subject: x509.Name) -> Optional[List[CscaStorage]]:
        """
        Returns list of CSCA certificate storage objects that match the subject param.
        :param subject: Certificate subject name to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """
        pass

    @abstractmethod
    def findCscaCertificatesBySubjectKey(self, country: CountryCode, subjectKey: bytes) -> Optional[List[CscaStorage]]:
        """
        Returns list of CSCA certificate storage objects that match subjectKey.
        :param country: iso alpha-2 country code of the country that issued the CSCA.
        :param subjectKey: Certificate subject key to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """
        pass

    @abstractmethod
    def addDsc(self, dsc: DocumentSignerCertificate, issuerId: CertificateId) -> CertificateId:
        """
        Inserts new DSC certificate into database
        :param dsc: DSC certificate to insert into database.
        :param issuerId: The DSC issuerId.
        :return: The dsc CertificateId
        """
        pass

    @abstractmethod
    def findDsc(self, id: CertificateId) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the certificate id.
        :param id: The DSC certificate id.
        :returns: DscStorage
        """
        pass

    @abstractmethod
    def findDscBySerial(self, issuer: x509.Name, serial: int) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the issuer name and serial number.
        :param issuer: The DSC certificate issuer.
        :param serial: The DSC certificate serial number.
        :returns: DscStorage
        """
        pass

    @abstractmethod
    def findDscBySubjectKey(self, subjectKey: bytes) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the subjectKey.
        :param subjectKey: The DSC certificate subject key.
        :returns: DscStorage
        """
        pass


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
        self._log = logging.getLogger(DatabaseAPI.__name__)
        self._dbc = PortDatabaseConnection(dialect, host, db, username, password)

    def _commit(self):
        try:
            self._dbc.getSession().commit()
        except Exception as e:
            self._log.error("An exception was encountered while tryping to commit to db!")
            self._log.exception(e)
            self._dbc.getSession().rollback()
            raise DatabaseAPIError(e) from None

    def getChallenge(self, cid: CID) -> Tuple[Challenge, datetime]:
        """
        Function fetches challenge from db and returns
        challenge and expiration time.

        :param cid: Challenge id
        :return: Tuple[Challenge, datetime]
        :raises:
            DatabaseAPIError: If challenge is not found
        """
        assert isinstance(cid, CID)
        cs = self._dbc.getSession() \
           .query(ChallengeStorage) \
           .filter(ChallengeStorage.id == cid) \
           .first()

        if cs is None:
            raise SeEntryNotFound("Challenge not found")
        c = cs.challenge
        t = cs.expires
        return (c, t)

    def findChallengeByUID(self, uid: UserId) -> Optional[Tuple[Challenge, datetime]]:
        """
        Function tries to find proto challenge by user ID in the db, and returns
        challenge and expiration time.

        :param uid: User ID to searche the challenge for
        :return: Optional[Tuple[Challenge, datetime]]
        """
        assert isinstance(uid, UserId)
        cs = self._dbc.getSession() \
           .query(ChallengeStorage) \
           .filter(ChallengeStorage.uid == uid) \
           .first()

        if cs is None:
            return None
        c = cs.challenge
        t = cs.expires
        return (c, t)

    def addChallenge(self, uid: UserId, challenge: Challenge, expires: datetime) -> None:
        """
        Add challenge to storage.
        :param uid: User ID for which the challenge was created
        :param challenge:
        :param expires: The challenge expiration datetime.
        :raise: SeEntryAlreadyExists if challenge already exists for user
        """
        assert isinstance(challenge, Challenge)
        assert isinstance(expires, datetime)
        cs = ChallengeStorage(uid, challenge, expires)

        if self._dbc.getSession().query(ChallengeStorage) \
            .filter(or_(ChallengeStorage.id == challenge.id, ChallengeStorage.uid == uid))\
            .count() > 0:
            raise SeEntryAlreadyExists("Challenge already exists")

        self._dbc.getSession().add(cs)
        self._commit()

    def deleteChallenge(self, cid: CID) -> None:
        assert isinstance(cid, CID)
        self._dbc.getSession() \
                 .query(ChallengeStorage) \
                 .filter(ChallengeStorage.id == cid) \
                 .delete()
        self._commit()

    def deleteExpiredChallenges(self, time: datetime) -> None:
        assert isinstance(time, datetime)
        self._dbc.getSession() \
                 .query(ChallengeStorage) \
                 .filter(ChallengeStorage.expires < time) \
                 .delete()
        self._commit()

    def accountExists(self, uid: UserId) -> bool:
        assert isinstance(uid, UserId)
        return self._dbc.getSession() \
            .query(AccountStorage) \
            .filter(AccountStorage.uid == uid) \
            .count() > 0

    def addOrUpdateAccount(self, account: AccountStorage) -> None:
        assert isinstance(account, AccountStorage)
        accnts = self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == account.uid)
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
            self._dbc.getSession().add(account)
        self._commit()

    def getAccount(self, uid: UserId) -> AccountStorage:
        assert isinstance(uid, UserId)
        accnt = self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == uid).all()
        if accnt is None:
            self._log.debug(":getAccountExpiry(): Account not found")
            raise SeEntryNotFound("Account not found.")
        assert isinstance(accnt, AccountStorage)
        return accnt

    def deleteAccount(self, uid: UserId) -> None:
        assert isinstance(uid, UserId)
        self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == uid).delete()
        self._dbc.getSession().commit()
        self._commit()

    def getAccountExpiry(self, uid: UserId) -> datetime:
        assert isinstance(uid, UserId)
        accnt = self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == uid).first()
        if accnt is None:
            self._log.debug(":getAccountExpiry(): Account not found")
            raise SeEntryNotFound("Account not found.")

        assert isinstance(accnt.getValidUntil(), datetime)
        return accnt.getValidUntil()

    def addCsca(self, csca: CscaCertificate, issuerId: Optional[CertificateId] = None) -> CertificateId:
        """
        Inserts new CSCA into database
        :param csca: CSCA certificate to insert into database.
        :param issuerId: The CSCA issuerId in case the CSCA is linked (Optional).
        :return: The csca CertificateId
        """
        self._log.debug("Inserting new CSCA into database C={} serial={}"
            .format(CountryCode(csca.issuerCountry), csca.serial_number))

        assert isinstance(csca, CscaCertificate)
        assert issuerId is None or isinstance(issuerId, CertificateId)

        cs = CscaStorage(csca, issuerId)
        if self._dbc.getSession().query(CscaStorage).filter(CscaStorage.id == cs.id).count() > 0:
            raise SeEntryAlreadyExists("CSCA already exists")

        self._dbc.getSession().add(cs)
        self._commit()
        return cs.id

    def findCsca(self, id: CertificateId)-> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the id.
        :param id: The certificate id to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """
        assert isinstance(id, CertificateId)
        return self._dbc.getSession() \
            .query(CscaStorage) \
            .filter(CscaStorage.id == id) \
            .first()

    def findCscaBySerial(self, issuer: x509.Name, serial: int) -> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the certificate serial number.
        :param issuer: CSCA issuer name.
        :param serial: CSCA serial number to search for.
        :return: CscaStorage, or None if no CSCA certificate was found.
        """
        assert isinstance(issuer, x509.Name)
        assert isinstance(serial, int)
        serial = int_to_bytes(serial)
        return self._dbc.getSession() \
            .query(CscaStorage) \
            .filter(CscaStorage.issuer == issuer.human_friendly, CscaStorage.serial == serial) \
            .first()

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

        # Try first to find CSCAs by subjectKey because
        # searching for subject might return invalid CSCAs
        cscas: Optional[List[CscaStorage]] = None
        if subjectKey is not None:
            assert isinstance(subjectKey, bytes)
            country = CountryCode(subject.native['country_name'])
            cscas = self._dbc.getSession() \
                .query(CscaStorage) \
                .filter(CscaStorage.country == country, CscaStorage.subjectKey == subjectKey) \
                .all()

        if cscas is None:
            cscas = self._dbc.getSession() \
                .query(CscaStorage) \
                .filter(CscaStorage.subject == subject.human_friendly) \
                .all()
        return cscas if len(cscas) != 0 else None

    def findCscaCertificatesBySubject(self, subject: x509.Name) -> Optional[List[CscaStorage]]:
        """
        Returns list of CSCA certificate storage objects that match the subject param.
        :param subject: Certificate subject name to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """
        assert isinstance(subject, x509.Name)
        cscas = self._dbc.getSession() \
            .query(CscaStorage) \
            .filter(CscaStorage.subject == subject.human_friendly) \
            .all()
        return cscas if len(cscas) != 0 else None

    def findCscaCertificatesBySubjectKey(self, country: CountryCode, subjectKey: bytes) -> Optional[List[CscaStorage]]:
        """
        Returns list of CSCA certificate storage objects that match subjectKey.
        :param country: iso alpha-2 country code of the country that issued the CSCA.
        :param subjectKey: Certificate subject key to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """
        assert isinstance(subjectKey, bytes)
        country = format_alpha2(country)
        cscas = self._dbc.getSession() \
            .query(CscaStorage) \
            .filter(CscaStorage.country == country, CscaStorage.subjectKey == subjectKey) \
            .all()
        return cscas if len(cscas) != 0 else None

    def addDsc(self, dsc: DocumentSignerCertificate, issuerId: CertificateId) -> CertificateId:
        """
        Inserts new DSC certificate into database
        :param dsc: DSC certificate to insert into database.
        :param issuerId: The DSC issuerId.
        :return: The dsc CertificateId
        """
        self._log.debug("Inserting new DSC into database C={} serial={}"
            .format(CountryCode(dsc.issuerCountry), dsc.serial_number))

        assert isinstance(dsc, DocumentSignerCertificate)
        assert isinstance(issuerId, CertificateId)

        ds = DscStorage(dsc, issuerId)
        if self._dbc.getSession().query(DscStorage).filter(DscStorage.id == ds.id).count() > 0:
            raise SeEntryAlreadyExists("DSC already exists")

        self._dbc.getSession().add(ds)
        self._commit()
        return ds.id

    def findDsc(self, id: CertificateId) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the certificate id.
        :param id: The DSC certificate id.
        :returns: DscStorage
        """
        assert isinstance(id, CertificateId)
        return self._dbc.getSession() \
            .query(DscStorage) \
            .filter(DscStorage.id == id) \
            .first()

    def findDscBySerial(self, issuer: x509.Name, serial: int) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the issuer name and serial number.
        :param issuer: The DSC certificate issuer.
        :param serial: The DSC certificate serial number.
        :returns: DscStorage
        """
        assert isinstance(issuer, x509.Name)
        assert isinstance(serial, int)
        serial = int_to_bytes(serial)
        return self._dbc.getSession() \
            .query(DscStorage) \
            .filter(DscStorage.issuer == issuer.human_friendly, DscStorage.serial == serial) \
            .first()

    def findDscBySubjectKey(self, subjectKey: bytes) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the subjectKey.
        :param subjectKey: The DSC certificate subject key.
        :returns: DscStorage
        """
        pass
        assert isinstance(subjectKey, bytes)
        return self._dbc.getSession() \
            .query(DscStorage) \
            .filter(DscStorage.subjectKey == subjectKey) \
            .first()


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
            raise SeEntryNotFound("Challenge not found") from e

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
        :raise: SeEntryAlreadyExists if challenge already exists for user
        """
        assert isinstance(challenge, Challenge)
        assert isinstance(expires, datetime)
        if challenge.id in self._d['proto_challenges']:
            raise SeEntryAlreadyExists("Challenge already exists")

        for _, (suid, _, _) in self._d['proto_challenges'].items():
            if suid == uid:
                raise SeEntryAlreadyExists("Challenge already exists")
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
            raise SeEntryNotFound("Account not found")
        return self._d['accounts'][uid]

    def deleteAccount(self, uid: UserId) -> None:
        assert isinstance(uid, UserId)
        if uid in self._d['accounts']:
            del self._d['accounts'][uid]

    def getAccountExpiry(self, uid: UserId) -> datetime:
        assert isinstance(uid, UserId)
        if uid not in self._d['accounts']:
            raise SeEntryNotFound("Account not found")
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
                raise SeEntryAlreadyExists("CSCA already exists")
        self._d['cscas'].add(cs)
        return cs.id

    def findCsca(self, id: CertificateId)-> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the id.
        :param id: The certificate id to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """
        assert isinstance(id, CertificateId)
        for csca in self._d['cscas']:
            if csca.id == id:
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
                raise SeEntryAlreadyExists("DSC already exists")
        self._d['dscs'].add(ds)
        return ds.id

    def findDsc(self, id: CertificateId) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the certificate id.
        :param id: The DSC certificate id.
        :returns: DscStorage
        """
        assert isinstance(id, CertificateId)
        for dsc in self._d['dscs']:
            if dsc.id == id:
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
