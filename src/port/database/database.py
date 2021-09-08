from __future__ import annotations
import logging

from abc import ABC, abstractmethod
from asn1crypto import x509
from collections import defaultdict
from datetime import datetime

from .account import AccountStorage
from .challenge import ChallengeStorage
from .connection import PortDatabaseConnection
from .sod import SodTrack
from .x509 import (
    CertificateRevocationInfo,
    CertificateStorage,
    PkiDistributionUrl,
    CrlUpdateInfo,
    DscStorage,
    CscaStorage
)

from port.proto.utils import bytes_to_int, sha512_256

from pymrtd.pki.crl import CertificateRevocationList
from pymrtd.pki.x509 import Certificate, CscaCertificate, DocumentSignerCertificate

from sqlalchemy import and_, literal, or_
from sqlalchemy.orm.scoping import scoped_session
from sqlalchemy.orm.query import Query
from sqlalchemy.sql.functions import func

from typing import Final, List, NoReturn, Optional, Tuple, TypeVar, Union
from port.proto.types import CertificateId, Challenge, CID, CountryCode, CrlId, SodId, UserId

class StorageAPIError(Exception):
    pass

class SeEntryNotFound(StorageAPIError):
    pass

class SeEntryAlreadyExists(StorageAPIError):
    pass

seAccountNotFound: Final       = SeEntryNotFound("Account not found")
seChallengeExists: Final       = SeEntryAlreadyExists("Challenge already exists")
seChallengeNotFound: Final     = SeEntryNotFound("Challenge not found")
seCrlUpdateInfoNotFound: Final = SeEntryNotFound("CRL Update Info not found")
seCscaExists: Final            = SeEntryAlreadyExists("CSCA certificate already exists")
seDscExists: Final             = SeEntryAlreadyExists("DSC certificate already exists")
seEfSodExists: Final           = SeEntryAlreadyExists("EF.SOD file already exists")

#pylint: disable=too-many-public-methods

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
        :raises seChallengeNotFound: If challenge is not found
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
    def updateAccount(self, account: AccountStorage) -> None:
        """
        Adds new accout to storage or updates existing.
        :param account: Account storage to add.
        """

    @abstractmethod
    def deleteAccount(self, uid: UserId) -> None:
        """
        Deletes the account under `uid` from DB.
        :param `uid: The user ID of the account.
        """

    @abstractmethod
    def accountExists(self, uid: UserId) -> bool:
        """
        Checks if the account with `uid` exists in DB.
        :param `uid`: The user ID of the account.
        :return: True if account exists, otherwise False.
        """

    @abstractmethod
    def findAccount(self, uid: UserId) -> Optional[AccountStorage]:
        """
        Returns account under `uid` from DB if exists in the DB.
        :param `uid`: The account user ID.
        :return: AccountStorage if account exitsts, otherwise None.
        """

    @abstractmethod
    def getAccount(self, uid: UserId) -> AccountStorage:
        """
        Returns account under `uid` from DB.
        :param `uid`: The account user ID.
        :return: AccountStorage
        :raises seAccountNotFound: If account is not found.
        """

    @abstractmethod
    def getAccountExpiry(self, uid: UserId) -> datetime:
        """
        Returns account attestation expiration.
        :param `uid`: The account user ID.
        :raises seAccountNotFound: If account is not found in the DB.
        """

    @abstractmethod
    def addSodTrack(self, sod: SodTrack) -> None:
        """
        Insert EF.SOD track into database.
        :param sod: EF.SOD track to add.
        """

    @abstractmethod
    def deleteSodTrack(self, sodId: SodId) -> None:
        """
        Deletes EF.SOD track from database.
        :param sodId: Id of the EF.SOD track to remove from database
        """

    @abstractmethod
    def findSodTrack(self, sodId: SodId) -> Optional[SodTrack]:
        """
        Returns EF.SOD track from database.
        :param sodId: Id of the EF.SOD track to retrieve.
        :return: SodTrack object if `sodId` exists, otherwise None.
        """

    @abstractmethod
    def findMatchingSodTracks(self, sod: SodTrack) -> Optional[List[SodTrack]]:
        """
        Returns list of EF.SOD track from database that matches part of content of `sod`.
        The query is pulled over either the matching SodId, or hashAlgo and any of the dg hashes match.
        :param sod: The EF.SOD track to match content of.
        :return: list of SodTrack or None if no matching SodTrack is found.
        """

    @abstractmethod
    def sodTrackMatches(self, sod: SodTrack) -> bool:
        """
        Checks if in the database exists any such EF.SOD track that has
        either the same SodId, or hashAlgo and any of the dg hashes match.
        Note, the point of such extensive check is to possible detect any "sybil" passport
        that had EF.SOD reissued but some of EF.DG files remained the same as in the old passport.

        For example:
            Passport was lost, a country reissues new passport which contains
            the same EF.DG2 (owner image) as the old passport.
            In such case, this function should return True.

        :param sod: The EF.SOD track check for.
        :return: True if EF.SOD track exists, otherwise False.
        """

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
        """

    @abstractmethod
    def deleteCsca(self, cscaId: CertificateId) -> None:
        """
        Deletes CSC Certificate from DB.
        :param `cscaId`: ID of `CscaStorage` to delete from storage.
        """

    @abstractmethod
    def findCsca(self, certId: CertificateId)-> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the id.
        :param certId: The certificate id to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """

    @abstractmethod
    def findCscaBySerial(self, issuer: x509.Name, serial: TypeVar("T",int, bytes)) -> Optional[CscaStorage]:
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
        :param issuerId: The CertificateId of CSCA which issued this DSC certificate.
        :return: The dsc CertificateId
        """

    @abstractmethod
    def addDscStorage(self, dsc: DscStorage) -> None:
        """
        Inserts new DSC certificate storage into database
        :param dsc: DscStorage to insert into database.
        """

    @abstractmethod
    def deleteDsc(self, dscId: CertificateId) -> None:
        """
        Deletes DSC Certificate from DB.
        :param `dscId`: ID of `DscStorage` to delete from storage.
        """

    @abstractmethod
    def findDsc(self, certId: CertificateId) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the certificate id.
        :param certId: The DSC certificate id.
        :return: DscStorage
        """

    @abstractmethod
    def findDscBySerial(self, issuer: x509.Name, serial: TypeVar("T", int, bytes)) -> Optional[DscStorage]:
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
    def updateCrl(self, crl: CertificateRevocationList) -> None:
        """
        Updates CRL for country.
        Before the new certificate revocation info entries are added, any existing entry is removed first.
        :param crl: The certificate revocation list.
        :raises: DatabaseAPIError on DB connection errors.
        """

    @abstractmethod
    def getCrlInfo(self, crlId: CrlId) -> CrlUpdateInfo:
        """
        Returns list of CRL update infos for the country.
        :param crlId: ID of the CRL update info.
        :return: CrlUpdateInfo
        """

    @abstractmethod
    def findCrlInfo(self, country: CountryCode) -> Optional[List[CrlUpdateInfo]]:
        """
        Returns list of CRL update infos for the country.
        :param country: iso alpha-2 country code to retrieve the list of CRL update infos.
        :return: Optional[List[CrlUpdateInfo]]
        """

    @abstractmethod
    def findCrlInfoByIssuer(self, issuer: x509.Name) -> Optional[CrlUpdateInfo]:
        """
        Returns CRL update infos for the issuer.
        :param issuer: CRL issuer DN.
        :return: Optional[CrlUpdateInfo]
        """

    @abstractmethod
    def findCrl(self, country: CountryCode) -> Optional[List[CertificateRevocationInfo]]:
        """
        Returns list of infos about revoked certificates for country.
        :param country: The iso alpha-2 country code to get the list of certificate revocation infos for.
        :return: List of countries revoked certificate infos or None
        """

    @abstractmethod
    def revokeCertificate(self, cri: CertificateRevocationInfo) -> None:
        """
        Inserts or updates certificate revocation information in the DB.
        :param cri: The certificate revocation information.
        """

    @abstractmethod
    def unrevokeCertificate(self, cri: CertificateRevocationInfo) -> None:
        """
        Deletes certificate revocation information in the DB.
        :param cri: The certificate revocation information.
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
    DatabaseAPI implements StorageAPI as persistent storage through PortDatabaseConnection and SQL Alchemy.
    It's defined as abstraction layer over class Connection (which uses PostgreSQL)
    to expose Connection interface to StorageAPI without mixing two interfaces.
    '''

    def __init__(self, dialect:str, host:str, db: str, username: str, password: str, dbLog: bool = False):
        '''
        Creates new ORM database connection.
        :param dialect: The database dialect e.g.:  mariadb, mysql, oracle, postgresql, sqlite.
        :param host: The database urlhost. Can be empty string in case of sqlite.
        :param db: The database path.
        :param username: The database username.
        :param password: The database password.
        :param dbLog (Optional): If set to True the underling DB implementation will debug log all DB actions and SQL statements.
        :raises PortDbConnectionError: On DB connection errors.
        '''
        self._log = logging.getLogger('proto.db.api')
        self._dbc = PortDatabaseConnection(dialect, host, db, username, password, debugLogging = dbLog)

    @property
    def __db(self) -> scoped_session:
        return self._dbc.session

    def _exists(self, q: Query) -> bool:
        #https://docs.sqlalchemy.org/en/14/orm/query.html?highlight=count#sqlalchemy.orm.Query.exists
        return self.__db \
            .query(literal(True)) \
            .filter(q.exists()) \
            .scalar()

    def __handle_exception(self, e) -> NoReturn:
        self.__db.rollback()
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
        :raises seChallengeNotFound: If challenge is not found.
        :raises DatabaseAPIError: On DB connection errors.
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
        :raises DatabaseAPIError: On DB connection errors.
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
        :raises SeEntryAlreadyExists: If challenge already exists for user.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(challenge, Challenge)
        assert isinstance(expires, datetime)
        try:
            cs = ChallengeStorage(uid, challenge, expires)

            if self._exists(self.__db.query(ChallengeStorage.id) \
                .filter(or_(ChallengeStorage.id == challenge.id, ChallengeStorage.uid == uid))):
                raise seChallengeExists

            self.__db.add(cs)
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def deleteChallenge(self, cid: CID) -> None:
        """
        :raises DatabaseAPIError: On DB connection errors.
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
        :raises DatabaseAPIError: On DB connection errors.
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

    def updateAccount(self, account: AccountStorage) -> None:
        """
        Adds new accout to storage or updates existing.
        :param account: Account storage to add.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(account, AccountStorage)
        self._log.debug("Inserting or updating account, uid=%s", account.uid)
        try:
            self.__db.merge(account)
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def deleteAccount(self, uid: UserId) -> None:
        """
        Deletes the account under `uid` from DB.
        :param `uid: The user ID of the account.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(uid, UserId)
        self._log.debug("Deleting account from DB, uid=%s", uid)
        try:
            self.__db \
                .query(AccountStorage) \
                .filter(AccountStorage.uid == uid) \
                .delete()
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def accountExists(self, uid: UserId) -> bool:
        """
        Checks if the account with `uid` exists in DB.
        :param `uid`: The user ID of the account.
        :return: True if account exists, otherwise False.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(uid, UserId)
        try:
            return self._exists(self.__db \
                .query(AccountStorage.uid) \
                .filter(AccountStorage.uid == uid))
        except Exception as e:
            self.__handle_exception(e)

    def findAccount(self, uid: UserId) -> Optional[AccountStorage]:
        """
        Returns account under `uid` from DB if exists in the DB.
        :param `uid`: The account user ID.
        :return: AccountStorage if account exitsts, otherwise None.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(uid, UserId)
        try:
            return self.__db \
                .query(AccountStorage) \
                .filter(AccountStorage.uid == uid) \
                .first()
        except Exception as e:
            self.__handle_exception(e)

    def getAccount(self, uid: UserId) -> AccountStorage:
        """
        Returns account under `uid` from DB.
        :param `uid`: The account user ID.
        :return: AccountStorage
        :raises seAccountNotFound: If account is not found.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(uid, UserId)
        a = self.findAccount(uid)
        if a is None:
            raise seAccountNotFound
        return a

    def getAccountExpiry(self, uid: UserId) -> datetime:
        """
        Returns account attestation expiration.
        :param `uid`: The account user ID.
        :raises seAccountNotFound: If account is not found in the DB.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(uid, UserId)
        try:
            accnt = self.__db \
                .query(AccountStorage) \
                .filter(AccountStorage.uid == uid) \
                .first()
            if accnt is None:
                raise seAccountNotFound
            return accnt.expires
        except Exception as e:
            self.__handle_exception(e)

    def addSodTrack(self, sod: SodTrack) -> None:
        """
        Insert EF.SOD track into database.
        :param sod: EF.SOD track to add.
        :raises seEfSodExists: if there is EF.SOD track that has the same sodId or hashAlgo and any of the dgHashes match.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(sod, SodTrack)
        self._log.debug("Inserting new EF.SOD track into DB, sodId=%s", sod.id)
        try:
            if self.sodTrackMatches(sod):
                raise seEfSodExists
            self.__db.add(sod)
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def deleteSodTrack(self, sodId: SodId) -> None:
        """
        Deletes EF.SOD track from database.
        :param sodId: Id of the EF.SOD track to remove from database
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(sodId, SodId)
        self._log.debug("Deleting EF.SOD track from DB, sodId=%s", sodId)
        try:
            self.__db \
                .query(SodTrack) \
                .filter(SodTrack.id == sodId) \
                .delete()
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def findSodTrack(self, sodId: SodId) -> Optional[SodTrack]:
        """
        Returns EF.SOD track from database.
        :param sodId: Id of the EF.SOD track to retrieve.
        :return: SodTrack object if `sodId` exists, otherwise None.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(sodId, SodId)
        try:
            return self.__db \
                .query(SodTrack) \
                .filter(SodTrack.id == sodId) \
                .first()
        except Exception as e:
            self.__handle_exception(e)

    def findMatchingSodTracks(self, sod: SodTrack) -> Optional[List[SodTrack]]:
        """
        Returns list of EF.SOD track from database that matches part of content of `sod`.
        The query is pulled over either the matching SodId, or hashAlgo and any of the dg hashes match.
        :param sod: The EF.SOD track to match content of.
        :return: list of SodTrack or None if no matching SodTrack is found.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(sod, SodTrack)
        try:
            # Check if sodId exist in db or (hashAlgo is same and one of dgHashes exists in DB)
            filterByHashes = None
            if sod.hashAlgo is not None:
                filterByHashes = and_(SodTrack.hashAlgo == sod.hashAlgo, \
                    or_(sod.dg1Hash is not None and SodTrack.dg1Hash == sod.dg1Hash, \
                        sod.dg2Hash is not None and SodTrack.dg2Hash == sod.dg2Hash, \
                        sod.dg3Hash is not None and SodTrack.dg3Hash == sod.dg3Hash, \
                        sod.dg4Hash is not None and SodTrack.dg4Hash == sod.dg4Hash, \
                        sod.dg5Hash is not None and SodTrack.dg5Hash == sod.dg5Hash, \
                        sod.dg6Hash is not None and SodTrack.dg6Hash == sod.dg6Hash, \
                        sod.dg7Hash is not None and SodTrack.dg7Hash == sod.dg7Hash, \
                        sod.dg8Hash is not None and SodTrack.dg8Hash == sod.dg8Hash, \
                        sod.dg9Hash is not None and SodTrack.dg9Hash == sod.dg9Hash, \
                        sod.dg10Hash is not None and SodTrack.dg10Hash == sod.dg10Hash, \
                        sod.dg11Hash is not None and SodTrack.dg11Hash == sod.dg11Hash, \
                        sod.dg12Hash is not None and SodTrack.dg12Hash == sod.dg12Hash, \
                        sod.dg13Hash is not None and SodTrack.dg13Hash == sod.dg13Hash, \
                        sod.dg14Hash is not None and SodTrack.dg14Hash == sod.dg14Hash, \
                        sod.dg15Hash is not None and SodTrack.dg15Hash == sod.dg15Hash, \
                        sod.dg16Hash is not None and SodTrack.dg16Hash == sod.dg16Hash  \
                )).self_group()
            l = self.__db \
                .query(SodTrack) \
                .filter(or_(SodTrack.id == sod.id, filterByHashes is not None and filterByHashes)) \
                .all()
            return l if len(l) > 0 else None
        except Exception as e:
            self.__handle_exception(e)

    def sodTrackMatches(self, sod: SodTrack) -> bool:
        """
        Checks if in the database exists any such EF.SOD track that has
        either the same SodId, or hashAlgo and any of the dg hashes match.
        When hashAlgo is None the check by dg hashes is not performed.
        Note, the point of such extensive check is to possible detect any "sybil" passport
        that had EF.SOD reissued but some of EF.DG files remained the same as in the old passport.

        For example:
            Passport was lost, a country reissues new passport which contains
            the same EF.DG2 (owner image) as the old passport.
            In such case, this function should return True.

        :param sod: The EF.SOD track check for.
        :return: True if EF.SOD track exists, otherwise False.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(sod, SodTrack)
        try:
            # Check if sodId exist in db or (hashAlgo is same and one of dgHashes exists in DB)
            filterByHashes = None
            if sod.hashAlgo is not None:
                filterByHashes = and_(SodTrack.hashAlgo == sod.hashAlgo, \
                    or_(sod.dg1Hash is not None and SodTrack.dg1Hash == sod.dg1Hash, \
                        sod.dg2Hash is not None and SodTrack.dg2Hash == sod.dg2Hash, \
                        sod.dg3Hash is not None and SodTrack.dg3Hash == sod.dg3Hash, \
                        sod.dg4Hash is not None and SodTrack.dg4Hash == sod.dg4Hash, \
                        sod.dg5Hash is not None and SodTrack.dg5Hash == sod.dg5Hash, \
                        sod.dg6Hash is not None and SodTrack.dg6Hash == sod.dg6Hash, \
                        sod.dg7Hash is not None and SodTrack.dg7Hash == sod.dg7Hash, \
                        sod.dg8Hash is not None and SodTrack.dg8Hash == sod.dg8Hash, \
                        sod.dg9Hash is not None and SodTrack.dg9Hash == sod.dg9Hash, \
                        sod.dg10Hash is not None and SodTrack.dg10Hash == sod.dg10Hash, \
                        sod.dg11Hash is not None and SodTrack.dg11Hash == sod.dg11Hash, \
                        sod.dg12Hash is not None and SodTrack.dg12Hash == sod.dg12Hash, \
                        sod.dg13Hash is not None and SodTrack.dg13Hash == sod.dg13Hash, \
                        sod.dg14Hash is not None and SodTrack.dg14Hash == sod.dg14Hash, \
                        sod.dg15Hash is not None and SodTrack.dg15Hash == sod.dg15Hash, \
                        sod.dg16Hash is not None and SodTrack.dg16Hash == sod.dg16Hash  \
                )).self_group()
            q = self.__db \
                .query(SodTrack) \
                .filter(or_(SodTrack.id == sod.id, filterByHashes is not None and filterByHashes))
            return self._exists(q)
        except Exception as e:
            self.__handle_exception(e)

    def addCsca(self, csca: CscaCertificate, issuerId: Optional[CertificateId] = None) -> CertificateId:
        """
        Inserts new CSCA into database
        :param csca: CSCA certificate to insert into database.
        :param issuerId: The CSCA issuerId in case the CSCA is linked (Optional).
        :return: The csca CertificateId
        :raises SeEntryAlreadyExists: If the same CSCA storage already exists.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(csca, CscaCertificate)
        assert issuerId is None or isinstance(issuerId, CertificateId)
        cs = CscaStorage(csca, issuerId)
        self.addCscaStorage(cs)
        return cs.id

    def deleteCsca(self, cscaId: CertificateId) -> None:
        """
        Deletes CSC Certificate from DB.
        :param `cscaId`: ID of `CscaStorage` to delete from storage.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(cscaId, CertificateId)
        self._log.debug("Deleting CSCA certificate id=%s", cscaId)
        try:
            self.__db \
                .query(CscaStorage) \
                .filter(CscaStorage.id == cscaId) \
                .delete()
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def addCscaStorage(self, csca: CscaStorage) -> None: #pylint: disable=arguments-differ
        """
        Inserts new CSCA certificate storage into database
        :param csca: CscaStorage to insert into database.
        :raises SeEntryAlreadyExists: If the same CSCA storage already exists.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(csca, CscaStorage)
        self._log.debug("Inserting new CSCA into DB, C=%s serial=%s", csca.country, csca.serial.hex())
        try:
            if self._exists(self.__db.query(CscaStorage.id).filter(CscaStorage.id == csca.id)):
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
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(certId, CertificateId)
        try:
            return self.__db \
                .query(CscaStorage) \
                .filter(CscaStorage.id == certId) \
                .first()
        except Exception as e:
            self.__handle_exception(e)

    def findCscaBySerial(self, issuer: x509.Name, serial: TypeVar("T",int, bytes)) -> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the certificate serial number.
        :param issuer: CSCA issuer name.
        :param serial: CSCA serial number to search for.
        :return: CscaStorage, or None if no CSCA certificate was found.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(issuer, x509.Name)
        assert isinstance(serial, int) or isinstance(serial, bytes)
        try:
            if isinstance(serial, int):
                serial = CertificateStorage.makeSerial(serial)
            return self.__db \
                .query(CscaStorage) \
                .filter(CscaStorage.serial == serial, \
                    func.lower(CscaStorage.issuer) == issuer.human_friendly.lower()) \
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
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(subject, x509.Name)
        try:
            cscas: Optional[List[CscaStorage]] = None
            q = self.__db \
                .query(CscaStorage) \
                .filter(
                    func.lower(CscaStorage.subject) == subject.human_friendly.lower())

            # If we have subject key, try to filter by subject name and subject key
            if subjectKey is not None:
                cscas = q.filter(CscaStorage.subjectKey == subjectKey) \
                         .all()
            else:
                cscas = q.all()

            return cscas if len(cscas) != 0 else None
        except Exception as e:
            self.__handle_exception(e)

    def findCscaCertificatesBySubject(self, subject: x509.Name) -> Optional[List[CscaStorage]]:
        """
        Returns list of CSCA certificate storage objects that match the subject param.
        :param subject: Certificate subject name to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(subject, x509.Name)
        try:
            cscas = self.__db \
                .query(CscaStorage) \
                .filter(
                    func.lower(CscaStorage.subject) == subject.human_friendly.lower()) \
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
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(subjectKey, bytes)
        assert isinstance(country, CountryCode)
        try:
            cscas = self.__db \
                .query(CscaStorage) \
                .filter(CscaStorage.country == country,\
                        CscaStorage.subjectKey == subjectKey) \
                .all()
            return cscas if len(cscas) != 0 else None
        except Exception as e:
            self.__handle_exception(e)

    def addDsc(self, dsc: DocumentSignerCertificate, issuerId: CertificateId) -> CertificateId:
        """
        Inserts new DSC certificate into database
        :param dsc: DSC certificate to insert into database.
        :param issuerId: The CertificateId of CSCA which issued this DSC certificate.
        :return: The dsc CertificateId
        :raises seDscExists: If the same DSC certificate storage already exists.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(dsc, DocumentSignerCertificate)
        assert isinstance(issuerId, CertificateId)
        ds = DscStorage(dsc, issuerId)
        self.addDscStorage(ds)
        return ds.id

    def addDscStorage(self, dsc: DscStorage) -> None:
        """
        Inserts new DSC certificate storage into database
        :param dsc: DscStorage to insert into database.
        :raises seDscExists: If the same DSC certificate storage already exists.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(dsc, DscStorage)
        self._log.debug("Inserting new DSC certificate into DB, C=%s serial=%s", dsc.country, dsc.serial.hex())
        try:
            if self._exists(self.__db.query(DscStorage.id).filter(DscStorage.id == dsc.id)):
                raise seDscExists
            self.__db.add(dsc)
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def deleteDsc(self, dscId: CertificateId) -> None:
        """
        Deletes DSC Certificate from DB.
        :param `dscId`: ID of `DscStorage` to delete from storage.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(dscId, CertificateId)
        self._log.debug("Deleting DSC certificate id=%s", dscId)
        try:
            self.__db \
                .query(DscStorage) \
                .filter(DscStorage.id == dscId) \
                .delete()
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def findDsc(self, certId: CertificateId) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the certificate id.
        :param certId: The DSC certificate id.
        :return: DscStorage
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(certId, CertificateId)
        try:
            return self.__db \
                .query(DscStorage) \
                .filter(DscStorage.id == certId) \
                .first()
        except Exception as e:
            self.__handle_exception(e)

    def findDscBySerial(self, issuer: x509.Name, serial: TypeVar("T", int, bytes)) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the issuer name and serial number.
        :param issuer: The DSC certificate issuer.
        :param serial: The DSC certificate serial number.
        :return: DscStorage
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(issuer, x509.Name)
        assert isinstance(serial, int) or isinstance(serial, bytes)
        try:
            if isinstance(serial, int):
                serial = CertificateStorage.makeSerial(serial)
            return self.__db \
                .query(DscStorage) \
                .filter(DscStorage.serial == serial, \
                    func.lower(DscStorage.issuer) == issuer.human_friendly.lower()) \
                .first()
        except Exception as e:
            self.__handle_exception(e)

    def findDscBySubjectKey(self, subjectKey: bytes) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the subjectKey.
        :param subjectKey: The DSC certificate subject key.
        :return: DscStorage
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(subjectKey, bytes)
        try:
            return self.__db \
                .query(DscStorage) \
                .filter(DscStorage.subjectKey == subjectKey) \
                .first()
        except Exception as e:
            self.__handle_exception(e)

    def updateCrl(self, crl: CertificateRevocationList) -> None:
        """
        Updates CRL for country.
        Before the new certificate revocation info entries are added, any existing entry is removed first.
        :param crl: The certificate revocation list.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(crl, CertificateRevocationList)
        self._log.debug("Updating CRL: '%s' crlNumber=%s", crl.issuer.human_friendly, crl.crlNumber)
        try:
            crlInfo = CrlUpdateInfo.fromCrl(crl)
            self.__db.merge(crlInfo)

            # Delete any existing cri entry for the country and crlId
            self.__db \
                .query(CertificateRevocationInfo) \
                .filter(CertificateRevocationInfo.country == crlInfo.country,\
                        CertificateRevocationInfo.crlId == crlInfo.id) \
                .delete()

            if crl.revokedCertificates is not None:
                for rc in crl.revokedCertificates:
                    cri = CertificateRevocationInfo\
                            .fromRevokedCertificate(crlInfo.country, rc)
                    cri.crlId = crlInfo.id

                    # Find possible revoked certificate id in the DB
                    cs = self.findDscBySerial(crl.issuer, cri.serial)
                    if cs is None:
                        cs = self.findCscaBySerial(crl.issuer, cri.serial)

                    certId = cs.id if cs is not None else None
                    cri.certId = certId
                    self.__db.merge(cri)

            self.__db.commit()
        except AssertionError:
            raise
        except Exception as e:
            self.__handle_exception(e)

    def getCrlInfo(self, crlId: CrlId) -> CrlUpdateInfo:
        """
        Returns list of CRL update infos for the country.
        :param crlId: ID of the CRL update info.
        :return: CrlUpdateInfo
        :raises seCrlUpdateInfoNotFound: If CRL Update inf ois not found.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(crlId, CrlId)
        try:
            ci = self.__db \
                .query(CrlUpdateInfo) \
                .filter(CrlUpdateInfo.id == crlId) \
                .first()
            if ci is None:
                raise seCrlUpdateInfoNotFound
            return ci
        except Exception as e:
            self.__handle_exception(e)

    def findCrlInfo(self, country: CountryCode) -> Optional[List[CrlUpdateInfo]]:
        """
        Returns list of CRL update infos for the country.
        :param country: iso alpha-2 country code to retrieve the list of CRL update infos.
        :return: Optional[List[CrlUpdateInfo]]
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(country, CountryCode)
        try:
            crl = self.__db \
                .query(CrlUpdateInfo) \
                .filter(CrlUpdateInfo.country == country) \
                .all()
            return crl if len(crl) != 0 else None
        except Exception as e:
            self.__handle_exception(e)

    def findCrlInfoByIssuer(self, issuer: x509.Name) -> Optional[CrlUpdateInfo]:
        """
        Returns CRL update infos for the issuer.
        :param issuer: CRL issuer DN.
        :return: Optional[CrlUpdateInfo]
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(issuer, x509.Name)
        country = CountryCode(issuer.native['country_name'])
        try:
            return self.__db \
                .query(CrlUpdateInfo) \
                .filter(CrlUpdateInfo.country == country,
                    func.lower(CrlUpdateInfo.issuer) == issuer.human_friendly.lower()) \
                .first()
        except Exception as e:
            self.__handle_exception(e)

    def findCrl(self, country: CountryCode) -> Optional[List[CertificateRevocationInfo]]:
        """
        Returns list of infos about revoked certificates for country.
        :param country: The iso alpha-2 country code to get the list of certificate revocation infos for.
        :return: List of countries revoked certificate infos or None
        :raises DatabaseAPIError: On DB connection errors.
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

    def revokeCertificate(self, cri: CertificateRevocationInfo) -> None:
        """
        Inserts or updates certificate revocation information in the DB.
        :param cri: The certificate revocation information.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(cri, CertificateRevocationInfo)
        self._log.debug("Revoking certificate C=%s serial=%s certId=%s crlId=%s", cri.country, cri.serial.hex(), cri.certId, cri.crlId)
        try:
            self.__db.merge(cri)
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def unrevokeCertificate(self, cri: CertificateRevocationInfo) -> None:
        """
        Deletes certificate revocation information in the DB.
        :param cri: The certificate revocation information.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(cri, CertificateRevocationInfo)
        self._log.debug("Unrevoking certificate criId=%s C=%s serial=%s certId=%s crlId=%s",
            cri.id, cri.country, cri.serial.hex(), cri.certId, cri.crlId)
        try:
            self.__db \
                .query(CertificateRevocationInfo) \
                .filter(or_(CertificateRevocationInfo.id == cri.id,\
                       and_(CertificateRevocationInfo.country == cri.country,\
                            CertificateRevocationInfo.serial == cri.serial,
                            CertificateRevocationInfo.crlId == cri.crlId))) \
                .delete()
            self.__db.commit()
        except Exception as e:
            self.__handle_exception(e)

    def isCertificateRevoked(self, crt: Union[Certificate, CertificateStorage]) -> bool:
        """
        Verifies in the DB if certificate is revoked.
        :param crt: The certificate or CertificateStorage to verify.
        :return: Returns True if certificate is revoked, otherwise False.
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(crt, Certificate) or isinstance(crt, CertificateStorage)
        try:
            if isinstance(crt, Certificate):
                country = CountryCode(crt.issuerCountry)
                certId  = CertificateId.fromCertificate(crt)
                serial  = CertificateStorage.makeSerial(crt.serial_number)
            else: # CertificateStorage
                country = crt.country
                certId  = crt.id
                serial  = crt.serial

            q = self.__db \
                .query(CertificateRevocationInfo) \
                .filter_by(country = country) \
                .filter(or_(CertificateRevocationInfo.certId == certId,
                            CertificateRevocationInfo.serial == serial))
            return self._exists(q)
        except Exception as e:
            self.__handle_exception(e)

    def addPkiDistributionUrl(self, pkidUrl: PkiDistributionUrl) -> None:
        """
        Adds eMRTD PKI distribution point URL address if it doesn't exist yet.
        :param pkidUrl: PkiDistributionUrl
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(pkidUrl, PkiDistributionUrl)
        self._log.debug("Adding PKI distribution URL. C=%s id=%s type=%s", pkidUrl.country, pkidUrl.id, pkidUrl.type.name)
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
        :raises DatabaseAPIError: On DB connection errors.
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
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(pkidId, int)
        self._log.debug("Deleting PKI distribution URL from DB. id=%s", pkidId)
        try:
            self.__db \
                .query(PkiDistributionUrl) \
                .filter(PkiDistributionUrl.id == pkidId) \
                .delete()
            self.__db.commit()
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
        proto_challenge -> Dictionary[CID, Tuple[UserId, Challenge, datetime - expires]]
        account         -> Dictionary[UserId, AccountStorage]
        csca            -> Set[List[CscaStorage]]
        dsc             -> Set[DscStorage]
    '''

    def __init__(self):
        self._log = logging.getLogger(MemoryDB.__name__)
        self._d = {
            'proto_challenge' : {},
            'account' : {},
            'sod'     : {},                # <sodId, SodTrack>
            'csca'    : defaultdict(list), # <country, List[CscaStorage]>
            'dsc'     : defaultdict(list), # <country, List[DscStorage]>
            'crlui'   : defaultdict(dict), # <country, <CrlId, CrlUpdateInfo>>
            'crt'     : defaultdict(dict), # <country, <CertificateRevocationInfo.id, CertificateRevocationInfo>>
            'pkidurl' : {}                 # <PkiDistributionUrl.id, LPkiDistributionUrl>
        }

    def getChallenge(self, cid: CID) -> Tuple[Challenge, datetime]:
        """
        Function fetches challenge from db and returns
        challenge and expiration time.

        :param cid: Challenge id
        :return: Tuple[Challenge, datetime]
        :raises seChallengeNotFound: If challenge is not found
        """
        assert isinstance(cid, CID)
        try:
            _, c, et = self._d['proto_challenge'][cid]
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
        for _, (suid, c, et) in self._d['proto_challenge'].items():
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
        if challenge.id in self._d['proto_challenge']:
            raise seChallengeExists

        for _, (suid, _, _) in self._d['proto_challenge'].items():
            if suid == uid:
                raise seChallengeExists
        self._d['proto_challenge'][challenge.id] = (uid, challenge, expires)

    def deleteChallenge(self, cid: CID) -> None:
        assert isinstance(cid, CID)
        if cid in self._d['proto_challenge']:
            self._d['proto_challenge'].pop(cid)

    def deleteExpiredChallenges(self, time: datetime) -> None:
        assert isinstance(time, datetime)
        d = { cid:(uid, c, cet)
            for cid, (uid, c, cet) in self._d['proto_challenge'].items()
            if cet >= time }
        self._d['proto_challenge'] = d

    def updateAccount(self, account: AccountStorage) -> None:
        """
        Adds new accout to storage or updates existing.
        :param account: Account storage to add.
        """
        assert isinstance(account, AccountStorage)
        self._log.debug("Inserting or updating account, uid=%s", account.uid)
        self._d['account'][account.uid] = account


    def deleteAccount(self, uid: UserId) -> None:
        """
        Deletes the account under `uid` from DB.
        :param `uid: The user ID of the account.
        """
        assert isinstance(uid, UserId)
        self._log.debug("Deleting account from DB, uid=%s", uid)
        if uid in self._d['account']:
            del self._d['account'][uid]

    def accountExists(self, uid: UserId) -> bool:
        """
        Checks if the account with `uid` exists in DB.
        :param `uid`: The user ID of the account.
        :return: True if account exists, otherwise False.
        """
        assert isinstance(uid, UserId)
        return uid in self._d['account']

    def findAccount(self, uid: UserId) -> Optional[AccountStorage]:
        """
        Returns account under `uid` from DB if exists in the DB.
        :param `uid`: The account user ID.
        :return: AccountStorage if account exitsts, otherwise None.
        """
        assert isinstance(uid, UserId)
        if uid not in self._d['account']:
            return None
        return self._d['account'][uid]

    def getAccount(self, uid: UserId) -> AccountStorage:
        """
        Returns account under `uid` from DB.
        :param `uid`: The account user ID.
        :return: AccountStorage
        :raises seAccountNotFound: If account is not found.
        """
        assert isinstance(uid, UserId)
        a = self.findAccount(uid)
        if a is None:
            raise seAccountNotFound
        return a

    def getAccountExpiry(self, uid: UserId) -> datetime:
        """
        Returns account attestation expiration.
        :param `uid`: The account user ID.
        :raises seAccountNotFound: If account is not found in the DB.
        """
        assert isinstance(uid, UserId)
        if uid not in self._d['account']:
            raise seAccountNotFound
        a = self.getAccount(uid)
        return a.expires

    def addSodTrack(self, sod: SodTrack) -> None:
        """
        Insert EF.SOD track into database.
        :param sod: EF.SOD track to add.
        """
        assert isinstance(sod, SodTrack)
        self._log.debug("Inserting new EF.SOD track into DB, sodId=%s", sod.id)
        if self.sodTrackMatches(sod):
            raise seEfSodExists
        self._d['sod'][sod.id] = sod

    def deleteSodTrack(self, sodId: SodId) -> None:
        """
        Deletes EF.SOD track from database.
        :param sodId: Id of the EF.SOD track to remove from database
        """
        assert isinstance(sodId, SodId)
        self._log.debug("Deleting EF.SOD track from DB, sodId=%s", sodId)
        if sodId in self._d['sod']:
            del self._d['sod'][sodId]


    def findSodTrack(self, sodId: SodId) -> Optional[SodTrack]:
        """
        Returns EF.SOD track from database.
        :param sodId: Id of the EF.SOD track to retrieve.
        :return: SodTrack object if `sodId` exists, otherwise None.
        """
        assert isinstance(sodId, SodId)
        if sodId in self._d['sod']:
            return self._d['sod'][sodId]
        return None

    @staticmethod
    def _anyOfDgHash(l: SodTrack, r: SodTrack):
        return (l.dg1Hash is not None and r.dg1Hash == l.dg1Hash) or \
            (l.dg2Hash is not None and r.dg2Hash == l.dg2Hash) or \
            (l.dg3Hash is not None and r.dg3Hash == l.dg3Hash) or \
            (l.dg4Hash is not None and r.dg4Hash == l.dg4Hash) or \
            (l.dg5Hash is not None and r.dg5Hash == l.dg5Hash) or \
            (l.dg6Hash is not None and r.dg6Hash == l.dg6Hash) or \
            (l.dg7Hash is not None and r.dg7Hash == l.dg7Hash) or \
            (l.dg8Hash is not None and r.dg8Hash == l.dg8Hash) or \
            (l.dg9Hash is not None and r.dg9Hash == l.dg9Hash) or \
            (l.dg10Hash is not None and r.dg10Hash == l.dg10Hash) or \
            (l.dg11Hash is not None and r.dg11Hash == l.dg11Hash) or \
            (l.dg12Hash is not None and r.dg12Hash == l.dg12Hash) or \
            (l.dg13Hash is not None and r.dg13Hash == l.dg13Hash) or \
            (l.dg14Hash is not None and r.dg14Hash == l.dg14Hash) or \
            (l.dg15Hash is not None and r.dg15Hash == l.dg15Hash) or \
            (l.dg16Hash is not None and r.dg16Hash == l.dg16Hash)

    def findMatchingSodTracks(self, sod: SodTrack) -> Optional[List[SodTrack]]:
        """
        Returns list of EF.SOD track from database that matches part of content of `sod`.
        The query is pulled over either the matching SodId, or hashAlgo and any of the dg hashes match.
        :param sod: The EF.SOD track to match content of.
        :return: list of SodTrack or None if no matching SodTrack is found.
        """
        l: List[SodTrack] = []
        if sod.id in self._d['sod']:
            l.append(self._d['sod'][sod.id])
        for s in self._d['sod'].values():
            if s.id != sod.id and s.hashAlgo == sod.hashAlgo \
                and MemoryDB._anyOfDgHash(sod, s):
                l.append(s)
        return l if len(l) > 0 else None

    def sodTrackMatches(self, sod: SodTrack) -> bool:
        """
        Checks if in the database exists any such EF.SOD track that has
        either the same SodId, or hashAlgo and any of the dg hashes match.
        Note, the point of such extensive check is to possible detect any "sybil" passport
        that had EF.SOD reissued but some of EF.DG files remained the same as in the old passport.

        For example:
            Passport was lost, a country reissues new passport which contains
            the same EF.DG2 (owner image) as the old passport.
            In such case, this function should return True.

        :param sod: The EF.SOD track check for.
        :return: True if EF.SOD track exists, otherwise False.
        """
        assert isinstance(sod, SodTrack)
        if sod.id in self._d['sod']:
            return True
        for s in self._d['sod'].values():
            if s.hashAlgo == sod.hashAlgo \
                and MemoryDB._anyOfDgHash(sod, s):
                return True
        return False

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
        self._log.debug("Inserting new CSCA into DB, C=%s serial=%s", csca.country, csca.serial.hex())
        for c in self._d['csca'][csca.country]:
            if c.id == csca.id:
                raise seCscaExists
        self._d['csca'][csca.country].append(csca)

    def deleteCsca(self, cscaId: CertificateId) -> None:
        """
        Deletes CSC Certificate from DB.
        :param `cscaId`: ID of `CscaStorage` to delete from storage.
        """
        assert isinstance(cscaId, CertificateId)
        self._log.debug("Deleting CSCA certificate id=%s", cscaId)
        for cscas in self._d['csca'].values():
            for csca in cscas:
                if csca.id == cscaId:
                    cscas.remove(csca)
                    return

    def findCsca(self, certId: CertificateId)-> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the id.
        :param certId: The certificate id to search for.
        :return: list of CscaStorage, or None if no CSCA certificate was found.
        """
        assert isinstance(certId, CertificateId)
        for _, cscas in self._d['csca'].items():
            for csca in cscas:
                if csca.id == certId:
                    return csca
        return None

    def findCscaBySerial(self, issuer: x509.Name, serial: TypeVar("T",int, bytes)) -> Optional[CscaStorage]:
        """
        Returns CSCA certificate storage objects that match the certificate serial number.
        :param issuer: CSCA issuer name.
        :param serial: CSCA serial number to search for.
        :return:
        """
        assert isinstance(issuer, x509.Name)
        assert isinstance(serial, int) or isinstance(serial, bytes)
        country = CountryCode(issuer.native['country_name'])
        if isinstance(serial, int):
            serial = CertificateStorage.makeSerial(serial)
        for csca in self._d['csca'][country]:
            if csca.issuer.lower() == issuer.human_friendly.lower() \
                and csca.serial == serial:
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
        cscas = []
        country = CountryCode(subject.native['country_name'])
        for csca in self._d['csca'][country]:
            if csca.subject.lower() == subject.human_friendly.lower():
                if subjectKey is None or csca.subjectKey == subjectKey:
                    cscas.append(csca)
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
        for csca in self._d['csca'][country]:
            if csca.subject.lower() == subject.human_friendly.lower():
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
        for csca in self._d['csca'][country]:
            if csca.subjectKey == subjectKey:
                cscas.append(csca)
        return cscas if len(cscas) != 0 else None

    def addDsc(self, dsc: DocumentSignerCertificate, issuerId: CertificateId) -> CertificateId:
        """
        Adds new DSC certificate into database
        :param csca: DSC certificate to insert into database.
        :param issuerId: The CertificateId of CSCA which issued this DSC certificate.
        :raises SeEntryAlreadyExists: If DSC certificate already exists
        :return: The dsc CertificateId
        """
        assert isinstance(dsc, DocumentSignerCertificate)
        assert isinstance(issuerId, CertificateId)

        ds = DscStorage(dsc, issuerId)
        self.addDscStorage(ds)
        return ds.id

    def addDscStorage(self, dsc: DscStorage) -> None:
        """
        Inserts new DSC certificate storage into database
        :param dsc: DscStorage to insert into database.
        :raises SeEntryAlreadyExists: If DSC certificate already exists
        """
        self._log.debug("Inserting new DSC into DB, C=%s serial=%s",
        dsc.country, dsc.serial.hex())
        for c in self._d['dsc'][dsc.country]:
            if c.id == dsc.id:
                raise seDscExists
        self._d['dsc'][dsc.country].append(dsc)

    def deleteDsc(self, dscId: CertificateId) -> None:
        """
        Deletes DSC Certificate from DB.
        :param `dscId`: ID of `DscStorage` to delete from storage.
        """
        assert isinstance(dscId, CertificateId)
        self._log.debug("Deleting DSC certificate id=%s", dscId)
        for dscs in self._d['dsc'].values():
            for dsc in dscs:
                if dsc.id == dscId:
                    dscs.remove(dsc)
                    return

    def findDsc(self, certId: CertificateId) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the certificate id.
        :param certId: The DSC certificate id.
        :return: DscStorage
        """
        assert isinstance(certId, CertificateId)
        for _, dscs in self._d['dsc'].items():
            for dsc in dscs:
                if dsc.id == certId:
                    return dsc
        return None

    def findDscBySerial(self, issuer: x509.Name, serial: TypeVar("T", int, bytes)) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the issuer name and serial number.
        :param issuer: The DSC certificate issuer.
        :param serial: The DSC certificate serial number.
        :return: DscStorage

        """
        assert isinstance(issuer, x509.Name)
        assert isinstance(serial, int) or isinstance(serial, bytes)
        if isinstance(serial, int):
            serial = CertificateStorage.makeSerial(serial)
        for dsc in self._d['dsc'][CountryCode(issuer.native['country_name'])]:
            if dsc.issuer.lower() == issuer.human_friendly.lower() \
                and dsc.serial == serial:
                return dsc
        return None

    def findDscBySubjectKey(self, subjectKey: bytes) -> Optional[DscStorage]:
        """
        Returns DSC certificate storage that matches the subjectKey.
        :param subjectKey: The DSC certificate subject key.
        :return: DscStorage
        """
        assert isinstance(subjectKey, bytes)
        for _, dscs in self._d['dsc'].items():
            for dsc in dscs:
                if dsc.subjectKey == subjectKey:
                    return dsc
        return None

    def updateCrl(self, crl: CertificateRevocationList) -> None:
        """
        Updates CRL for country.
        Before the new certificate revocation info entries are added, any existing entry is removed first.
        :param crl: The certificate revocation list.
        :raises: DatabaseAPIError on DB connection errors.
        """
        assert isinstance(crl, CertificateRevocationList)
        self._log.debug("Updating CRL: '%s' crlNumber=%s", crl.issuer.human_friendly, crl.crlNumber)

        crlInfo = CrlUpdateInfo.fromCrl(crl)
        self._d['crlui'][crlInfo.country][crlInfo.id] = crlInfo

        # Remove any existing entries for the previous CRL
        cri_to_remove = []
        if crlInfo.country in self._d['crt']:
            for cri in self._d['crt'][crlInfo.country].values():
                if cri.crlId == crlInfo.id:
                    cri_to_remove.append(cri.id)
        for cid in cri_to_remove:
            del self._d['crt'][crlInfo.country][cid]

        if crl.revokedCertificates is not None:
            for rc in crl.revokedCertificates:
                cri = CertificateRevocationInfo\
                        .fromRevokedCertificate(crlInfo.country, rc)
                cri.crlId = crlInfo.id

                # Find possible revoked certificate id in the DB
                cs = self.findDscBySerial(crl.issuer, cri.serial)
                if cs is None:
                    cs = self.findCscaBySerial(crl.issuer, cri.serial)

                certId = cs.id if cs is not None else None
                cri.certId = certId
                self.revokeCertificate(cri)

    def getCrlInfo(self, crlId: CrlId) -> CrlUpdateInfo:
        """
        Returns list of CRL update infos for the country.
        :param crlId: ID of the CRL update info.
        :return: CrlUpdateInfo
        :raises SeEntryNotFound: If CRL Update inf ois not found.
        """
        for cuis in self._d['crlui'].values():
            if crlId in cuis:
                return cuis[crlId]
        raise seCrlUpdateInfoNotFound

    def findCrlInfo(self, country: CountryCode) -> Optional[List[CrlUpdateInfo]]:
        """
        Returns list of CRL update infos for the country.
        :param country: iso alpha-2 country code to retrieve the list of CRL update infos.
        :return: Optional[List[CrlUpdateInfo]]
        """
        assert isinstance(country, CountryCode)
        if country in self._d['crlui']:
            return self._d['crlui'][country].values()
        return None

    def findCrlInfoByIssuer(self, issuer: x509.Name) -> Optional[CrlUpdateInfo]:
        """
        Returns CRL update infos for the issuer.
        :param issuer: CRL issuer DN.
        :return: Optional[CrlUpdateInfo]
        :raises DatabaseAPIError: On DB connection errors.
        """
        assert isinstance(issuer, x509.Name)
        country = CountryCode(issuer.native['country_name'])
        if country in self._d['crlui']:
            for cui in self._d['crlui'][country].values():
                if cui.issuer.lower() == issuer.human_friendly.lower():
                    return cui
        return None

    def findCrl(self, country: CountryCode) -> Optional[List[CertificateRevocationInfo]]:
        """
        Returns list of infos about revoked certificates for country.
        :param country: The iso alpha-2 country code to get the list of certificate revocation infos for.
        """
        assert isinstance(country, CountryCode)
        if country in self._d['crt']:
            return [crl for crls in self._d['crt'][country].values() for crl in crls]
        return None

    def revokeCertificate(self, cri: CertificateRevocationInfo) -> None:
        """
        Inserts or updates certificate revocation information in the DB.
        :param cri: The certificate revocation information.
        """
        assert isinstance(cri, CertificateRevocationInfo)
        self._log.debug("Revoking certificate C=%s serial=%s certId=%s crlId=%s", cri.country, cri.serial.hex(), cri.certId, cri.crlId)
        cri.id = bytes_to_int(sha512_256(cri.country.encode('utf-8') + cri.serial)[0:8])
        self._d['crt'][cri.country][cri.id] = cri

    def unrevokeCertificate(self, cri: CertificateRevocationInfo) -> None:
        """
        Deletes certificate revocation information in the DB.
        :param cri: The certificate revocation information.
        """
        assert isinstance(cri, CertificateRevocationInfo)
        self._log.debug("Unrevoking certificate criId=%s C=%s serial=%s certId=%s crlId=%s",
            cri.id, cri.country, cri.serial.hex(), cri.certId, cri.crlId)
        if cri.country in self._d['crt']:
            if cri.id is not None and cri.id in self._d['crt'][cri.country]:
                del self._d['crt'][cri.country][cri.id]
            else:
                cri_to_remove = []
                c: CertificateRevocationInfo
                for c in self._d['crt'][cri.country].values():
                    if c.serial == cri.serial and c.crlId == cri.certId:
                        cri_to_remove.append(c.id)
                for cid in cri_to_remove:
                    del self._d['crt'][cri.country][cid]

    def isCertificateRevoked(self, crt: TypeVar("T",Certificate, CertificateStorage)) -> bool:
        """
        Verifies in the DB if certificate is revoked.
        :param crt: The certificate to verify.
        :return: Returns True if certificate is revoked, otherwise False.
        """
        assert isinstance(crt, Certificate) or isinstance(crt, CertificateStorage)
        if isinstance(crt, Certificate):
            certId  = CertificateId.fromCertificate(crt)
            serial  = CertificateStorage.makeSerial(crt.serial_number)
            country = CountryCode(crt.issuerCountry)
        else: # CertificateStorage
            country = crt.country
            certId  = crt.id
            serial  = crt.serial

        if country in self._d['crt']:
            for cri in self._d['crt'][country].values():
                if cri.certId == certId or serial == cri.serial:
                    return True
        return False

    def addPkiDistributionUrl(self, pkidUrl: PkiDistributionUrl) -> None:
        """
        Adds eMRTD PKI distribution point URL address if it doesn't exist yet.
        :param pkidUrl: PkiDistributionUrl
        """
        assert isinstance(pkidUrl, PkiDistributionUrl)
        self._log.debug("Adding PKI distribution URL. C=%s id=%s type=%s", pkidUrl.country, pkidUrl.id, pkidUrl.type.name)
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
