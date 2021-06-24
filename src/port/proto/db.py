import logging

from asn1crypto.core import InstanceOf
from port.database.utils import formatAlpha2

from port.proto.types import CertificateId

from .challenge import CID, Challenge
from .user import UserId

from abc import ABC, abstractmethod
from asn1crypto.x509 import Name
from datetime import datetime

from port.database.storage.storageManager import Connection
from port.database.storage.challengeStorage import *
from port.database.storage.accountStorage import AccountStorage, AccountStorageError
from port.database.storage.x509Storage import DscStorage, CSCAStorage

from pymrtd.pki import x509
from typing import Optional, Tuple

class StorageAPIError(Exception):
    pass

class SeEntryNotFound(StorageAPIError):
    pass

class SeEntryAlreadyExists(StorageAPIError):
    pass

class StorageAPI(ABC):
    ''' Abstract storage interface for user data and MRTD trustchain certificates (CSCA, DSC) '''

    @abstractmethod
    def getChallenge(self, cid: CID) -> Tuple[Challenge, datetime]:
        """
        Function fetches challenge from db and returns
        challenge and time of creation.

        :param cid: Challenge id
        :return: Tuple[Challenge, datetime]
        :raises:
            DatabaseAPIError: If challenge is not found
        """

    # Proto challenge methods
    @abstractmethod
    def addChallenge(self, challenge: Challenge, timedate: datetime) -> None:
        """
        Add challenge to storage.
        :param challenge:
        :param timdate: Challenge crate Date and time
        """
        pass

    @abstractmethod
    def deleteChallenge(self, cid: CID) -> None:
        pass

    @abstractmethod
    def deleteExpiredChallenges(self, time: datetime) -> None:
        """
        Deletes expired challenges that have createTime less than time.
        :param time:
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

    @abstractmethod
    def addCscaCertificate(self, csca: x509.CscaCertificate, issuerId: Optional[CertificateId] = None) -> CertificateId:
        """
        Inserts new CSCA certificate into database
        :param csca: CSCA certificate to insert into database.
        :param issuerId: The CSCA issuerId in case the CSCA is linked (Optional).
        :return: The csca CertificateId
        """
        pass

    @abstractmethod
    def getCSCAbySubject(self, subject: Name) -> Optional[x509.CscaCertificate]:
        pass

    @abstractmethod
    def getCSCAbySubjectKey(self, subjectKey: bytes) -> Optional[x509.CscaCertificate]:
        """Get CSCA"""
        pass

    @abstractmethod
    def addDscCertificate(self, dsc: x509.DocumentSignerCertificate, issuerId: CertificateId) -> CertificateId:
        """
        Inserts new DSC certificate into database
        :param dsc: DSC certificate to insert into database.
        :param issuerId: The DSC issuerId.
        :return: The dsc CertificateId
        """
        pass

    @abstractmethod
    def getDSCbySerialNumber(self, issuer: Name, serialNumber: int) -> Optional[x509.DocumentSignerCertificate]:
        """Get DSC"""
        pass

    @abstractmethod
    def getDSCbySubjectKey(self, subjectKey: bytes) -> Optional[x509.DocumentSignerCertificate]:
        """Get DSC"""
        pass




class DatabaseAPIError(StorageAPIError):
    pass

class DatabaseAPI(StorageAPI):
    '''
    DatabaseAPI implements StorageAPI as persistent storage.
    It's defined as abstraction layer over class Connection (which uses PostgreSQL)
    to expose Connection interface to StorageAPI without mixing two interfaces.
    '''

    def __init__(self, user: str, pwd: str, db: str):
        """Creating connection to the database and initialization of main structures"""
        self._log = logging.getLogger(DatabaseAPI.__name__)
        self._dbc = Connection(user, pwd, db)

    def getChallenge(self, cid: CID) -> Tuple[Challenge, datetime]:
        """
        Function fetches challenge from db and returns
        challenge and time of creation.

        :param cid: Challenge id
        :return: Tuple[Challenge, datetime]
        :raises:
            DatabaseAPIError: If challenge is not found
        """
        assert isinstance(cid, CID)
        result = self._dbc.getSession() \
           .query(ChallengeStorage) \
           .filter(ChallengeStorage.id == str(cid)) \
           .all()

        if len(result) == 0:
            raise SeEntryNotFound("Challenge not found")

        cs = result[0]
        c = cs.getChallenge()
        t = cs.createTime
        return (c, t)

    def addChallenge(self, challenge: Challenge, timedate: datetime) -> None:
        assert isinstance(challenge, Challenge)
        assert isinstance(timedate, datetime)
        cs = ChallengeStorage.fromChallenge(challenge, timedate)

        if self._dbc.getSession().query(ChallengeStorage).filter(ChallengeStorage.id == challenge.id).count() > 0:
            raise SeEntryAlreadyExists("Challenge already exists")

        self._dbc.getSession().add(cs)
        self._dbc.getSession().commit()

    def deleteChallenge(self, cid: CID) -> None:
        assert isinstance(cid, CID)
        self._dbc.getSession() \
                 .query(ChallengeStorage) \
                 .filter(ChallengeStorage.id == cid) \
                 .delete()
        self._dbc.getSession().commit()

    def deleteExpiredChallenges(self, time: datetime) -> None:
        assert isinstance(time, datetime)
        self._dbc.getSession() \
                 .query(ChallengeStorage) \
                 .filter(ChallengeStorage.createTime < time) \
                 .delete()
        self._dbc.getSession().commit()

    def accountExists(self, uid: UserId) -> bool:
        assert isinstance(uid, UserId)
        return self._dbc.getSession() \
            .query(AccountStorage) \
            .filter(AccountStorage.uid == uid) \
            .count() > 0

    def addOrUpdateAccount(self, account: AccountStorage) -> None:
        assert isinstance(account, AccountStorage)
        s = self._dbc.getSession()
        accnts = s.query(AccountStorage).filter(AccountStorage.uid == account.uid)
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
            s.add(account)
        s.commit()

    def getAccount(self, uid: UserId) -> AccountStorage:
        assert isinstance(uid, UserId)
        accounts = self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == uid).all()
        if len(accounts) == 0:
            self._log.debug(":getAccountExpiry(): Account not found")
            raise SeEntryNotFound("Account not found.")
        assert isinstance(accounts[0], AccountStorage)
        return accounts[0]

    def deleteAccount(self, uid: UserId) -> None:
        assert isinstance(uid, UserId)
        self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == uid).delete()
        self._dbc.getSession().commit()

    def getAccountExpiry(self, uid: UserId) -> datetime:
        assert isinstance(uid, UserId)
        items = self._dbc.getSession().query(AccountStorage).filter(AccountStorage.uid == uid).all()
        if len(items) == 0:
            self._log.debug(":getAccountExpiry(): Account not found")
            raise SeEntryNotFound("Account not found.")

        assert isinstance(items[0].getValidUntil(), datetime)
        return items[0].getValidUntil()

    def addCscaCertificate(self, csca: x509.CscaCertificate, issuerId: Optional[CertificateId] = None) -> CertificateId:
        """
        Inserts new CSCA into database
        :param csca: CSCA certificate to insert into database.
        :param issuerId: The CSCA issuerId in case the CSCA is linked (Optional).
        :return: The csca CertificateId
        """
        self._log.debug("Inserting new CSCA into database C={} serial={}"
            .format(formatAlpha2(csca.issuerCountry), csca.serial_number))

        assert isinstance(csca, x509.CscaCertificate)
        assert issuerId is None or isinstance(issuerId, CertificateId)

        cs = CSCAStorage(csca, issuerId)
        if self._dbc.getSession().query(CSCAStorage).filter(CSCAStorage.id == cs.id).count() > 0:
            raise SeEntryAlreadyExists("CSCA already exists")

        self._dbc.getSession().add(cs)
        self._dbc.getSession().commit()
        return cs.id

    def getCSCAbySubject(self, subject: Name) -> Optional[x509.CscaCertificate]:
        """ Get CSCA by it's issuer and serial number. """
        assert isinstance(subject, Name)
        items = self._dbc.getSession() \
            .query(CSCAStorage) \
            .filter(CSCAStorage.subject == subject.human_friendly) \
            .all()

        if len(items) == 0:
            return None
        return items[0].getCertificate()

    def getCSCAbySubjectKey(self, subjectKey: bytes) -> Optional[x509.CscaCertificate]:
        """ Get CSCA by it's subject key. """
        assert isinstance(subjectKey, bytes)
        items = self._dbc.getSession() \
            .query(CSCAStorage) \
            .filter(CSCAStorage.subjectKey == subjectKey) \
            .all()

        if len(items) == 0:
            return None
        return items[0].getCertificate()

    def addDscCertificate(self, dsc: x509.DocumentSignerCertificate, issuerId: CertificateId) -> CertificateId:
        """
        Inserts new DSC certificate into database
        :param dsc: DSC certificate to insert into database.
        :param issuerId: The DSC issuerId.
        :return: The dsc CertificateId
        """
        self._log.debug("Inserting new DSC into database C={} serial={}"
            .format(formatAlpha2(dsc.issuerCountry), dsc.serial_number))

        assert isinstance(dsc, x509.DocumentSignerCertificate)
        assert isinstance(issuerId, CertificateId)

        ds = DscStorage(dsc, issuerId)
        if self._dbc.getSession().query(DscStorage).filter(DscStorage.id == ds.id).count() > 0:
            raise SeEntryAlreadyExists("DSC already exists")

        self._dbc.getSession().add(ds)
        self._dbc.getSession().commit()
        return ds.id

    def getDSCbySerialNumber(self, issuer: Name, serial: int) -> Optional[x509.DocumentSignerCertificate]:
        """ Get DSC by it's issuer and serial number. """
        assert isinstance(issuer, Name)
        assert isinstance(serial, int)
        items = self._dbc.getSession() \
            .query(DscStorage) \
            .filter(DscStorage.issuer == issuer.human_friendly, \
                DscStorage.serial == str(serial) \
            ).all()

        if len(items) == 0:
            return None
        return items[0].getCertificate()

    def getDSCbySubjectKey(self, subjectKey: bytes) -> Optional[x509.DocumentSignerCertificate]:
        """ Get DSC by it's subject key. """
        assert isinstance(subjectKey, bytes)
        items = self._dbc.getSession() \
            .query(DscStorage) \
            .filter(DscStorage.subjectKey == subjectKey) \
            .all()

        if len(items) == 0:
            return None
        return items[0].getCertificate()


class MemoryDBError(StorageAPIError):
    pass

class MemoryDB(StorageAPI):
    '''
    MemoryDB implements StorageAPI as non-peristent database.
    The data is stored in memory (RAM) and gets deleted as instance of MemoryDB is destroyed.
    The purpose of MemoryDB is testing of port proto without needing to set up (or reset) proper database.
    Internally data is stored as dictionary in 4 categories:
        proto_challenges -> Dictionary[CID, Tuple[Challenge, datetime]]
        accounts         -> Dictionary[UserId, AccountStorage]
        cscas            -> Set[CscaCertificate]
        dscs             -> Set[DocumentSignerCertificate]
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
        challenge and time of creation.

        :param cid: Challenge id
        :return: Tuple[Challenge, datetime]
        :raises:
            MemoryDBError: If challenge is not found
        """
        assert isinstance(cid, CID)
        try:
            return self._d['proto_challenges'][cid]
        except Exception as e:
            raise SeEntryNotFound("Challenge not found") from e

    def addChallenge(self, challenge: Challenge, timedate: datetime) -> None:
        assert isinstance(challenge, Challenge)
        assert isinstance(timedate, datetime)
        if challenge.id in self._d['proto_challenges']:
            raise MemoryDBError("Challenge already exists")
        self._d['proto_challenges'][challenge.id] = (challenge, timedate)

    def deleteChallenge(self, cid: CID) -> None:
        assert isinstance(cid, CID)
        if cid in self._d['proto_challenges']:
            self._d['proto_challenges'].pop(cid)

    def deleteExpiredChallenges(self, time: datetime) -> None:
        assert isinstance(time, datetime)
        d = { cid:(c, createTime)
            for cid, (c, createTime) in self._d['proto_challenges'].items()
            if createTime >= time }
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

    def addCscaCertificate(self, csca: x509.CscaCertificate, issuerId: Optional[CertificateId] = None) -> CertificateId:
        """
        Adds new CSCA into database
        :param csca: CSCA certificate to insert into database.
        :param issuerId: The CSCA issuerId in case the CSCA is linked (Optional).
        :return: The csca CertificateId
        """
        self._log.debug("Inserting new CSCA into database C={} serial={}"
            .format(formatAlpha2(csca.issuerCountry), csca.serial_number))

        assert isinstance(csca, x509.CscaCertificate)
        assert issuerId is None or isinstance(issuerId, CertificateId)

        cs = CSCAStorage(csca, issuerId)
        for c in self._d['cscas']:
            if c.id == cs.id:
                raise SeEntryAlreadyExists("CSCA already exists")
        self._d['cscas'].add(cs)
        return cs.id

    def getCSCAbySubject(self, subject: Name)-> Optional[x509.CscaCertificate]:
        """Get CSCA"""
        assert isinstance(subject, Name)
        for cs in self._d['cscas']:
            if cs.subject == subject.human_friendly:
                return cs.getCertificate()
        return None

    def getCSCAbySubjectKey(self, subjectKey: bytes) -> Optional[x509.CscaCertificate]:
        """Get CSCA"""
        assert isinstance(subjectKey, bytes)
        for csca in self._d['cscas']:
            if csca.subjectKey == subjectKey:
                return csca.getCertificate()
        return None

    def addDscCertificate(self, dsc: x509.DocumentSignerCertificate, issuerId: CertificateId) -> CertificateId:
        """
        Adds new DSC certificate into database
        :param csca: DSC certificate to insert into database.
        :param issuerId: The DSC issuerId in case the CSCA is linked (Optional).
        :return: The dsc CertificateId
        """
        self._log.debug("Inserting new CSCA into database C={} serial={}"
            .format(formatAlpha2(dsc.issuerCountry), dsc.serial_number))

        assert isinstance(dsc, x509.CscaCertificate)
        assert issuerId is None or isinstance(issuerId, CertificateId)

        ds = DscStorage(dsc, issuerId)
        for c in self._d['dscs']:
            if c.id == ds.id:
                raise SeEntryAlreadyExists("DSC already exists")
        self._d['dscs'].add(ds)
        return ds.id

    def getDSCbySerialNumber(self, issuer: Name, serial: int) -> Optional[x509.DocumentSignerCertificate]:
        """Get DSC"""
        assert isinstance(issuer, Name)
        assert isinstance(serial, int)
        for dsc in self._d['dscs']:
            if dsc.issuer == issuer and dsc.serial_number == serial:
                return dsc
        return None

    def getDSCbySubjectKey(self, subjectKey: bytes) -> Optional[x509.DocumentSignerCertificate]:
        """Get DSC"""
        assert isinstance(subjectKey, bytes)
        for dsc in self._d['dscs']:
            if dsc.subjectKey == subjectKey:
                return dsc
        return None
