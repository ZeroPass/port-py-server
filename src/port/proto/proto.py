import port.log as log
from port.proto.types import CountryCode

from . import utils
from .challenge import CID, Challenge
from .db import StorageAPI
from .session import Session, SessionKey
from .user import UserId

from asn1crypto.x509 import Name
from datetime import datetime, timedelta

from pymrtd import ef
from pymrtd.pki.keys import AAPublicKey, SignatureAlgorithm
from pymrtd.pki.x509 import CertificateVerificationError, CscaCertificate, DocumentSignerCertificate

from port.database.storage.accountStorage import AccountStorage
from port.database.storage.x509Storage import CertificateStorage, CscaStorage

from threading import Timer
from typing import Final, List, Optional, Tuple, Union

class ProtoError(Exception):
    """ General protocol exception """
    code = 400

class PeSigVerifyFailed(ProtoError):
    """ Challenge signature verification error """
    code = 401

class PeMacVerifyFailed(ProtoError):
    """ Session mac verification error """
    code = 401

class PeNotFound(ProtoError):
    """ Non existing elements error (e.g.: account doesn't exist, CSCA can't be faound etc...) """
    code = 404

class PeConflict(ProtoError):
    """ User account error """
    code = 409

class PePreconditionFailed(ProtoError):
    """
    One or more condition in verification of eMRTD PKI trustchain failed.
    Or when verifying SOD contains specific DG e.g.: DG1
    """
    code = 412

class PeInvalidOrMissingParam(ProtoError):
    """ Invalid or missing required protocol parameter """
    code = 422

class PePreconditionRequired(ProtoError):
    """
    Required preconditions that are marked as optional.
    e.g.: at registration dg14 might be required or at login dg1 could be required
    """
    code = 428

class PeChallengeExpired(ProtoError):
    """ Challenge has expired """
    code = 498

class PeCredentialsExpired(ProtoError):
    """ Challenge has expired """
    code = 498

peAccountAlreadyRegistered: Final         = PeConflict("Account already registered")
peAccountExpired: Final                   = PeCredentialsExpired("Account has expired")
peChallengeExpired: Final                 = PeChallengeExpired("Challenge has expired")
peChallengeVerificationFailed: Final      = PeSigVerifyFailed("Challenge signature verification failed")
peCscaExists: Final                       = PeConflict("CSCA certificate already exists")
peCscaExpired: Final                      = ProtoError("CSCA certificate has expired")
peCscaNotFound: Final                     = PeNotFound("CSCA certificate not found")
peCscaSelfIssued: Final                   = PeNotFound("No CSCA link was found for self-issued CSCA")
peDg1Required: Final                      = PePreconditionRequired("EF.DG1 required")
peDg14Required: Final                     = PePreconditionRequired("EF.DG14 required")
peDscExists: Final                        = PeConflict("DSC certificate already exists")
peDscExpired: Final                       = ProtoError("DSC certificate has expired")
peDscNotFound: Final                      = PeNotFound("DSC certificate not found")
peInvalidCsca: Final                      = PeInvalidOrMissingParam("Invalid CSCA certificate")
peInvalidDsc: Final                       = PeInvalidOrMissingParam("Invalid DSC certificate")
peMissingAAInfoInDg14: Final              = PePreconditionRequired("Missing ActiveAuthenticationInfo in DG14 file")
peMissingParamAASigAlgo: Final            = PeInvalidOrMissingParam("Missing param aaSigAlgo")
peTrustchainCheckFailedExpiredCert: Final = PePreconditionFailed("Expired certificate in the trustchain")
peTrustchainCheckFailedNoCsca: Final      = PePreconditionFailed("Missing issuer CSCA certificate in the trustchain")
peTrustchainCheckFailedRevokedCert: Final = PePreconditionFailed("Revoked certificate in the trustchain")
peTrustchainVerificationFailed: Final     = PePreconditionFailed("Trustchain verification failed")
peUnknownPathSodToDsc: Final              = PePreconditionFailed("Unknown connection path from SOD to DSC certificate")

def peInvalidDgFile(dgNumber: ef.dg.DataGroupNumber) -> PePreconditionFailed:
    return PePreconditionFailed("Invalid EF.{} file".format(dgNumber.native))


class PortProto:

    def __init__(self, storage: StorageAPI, cttl: int, maintenanceInterval: int = 36):
        """
        Initializes new PortProto.
        :param storage: database storage to use
        :param cttl: Challenge expiration time in seconds (time-to-leave)
        :param maintenanceInterval: Protocol maintenance interval in seconds.
                                    i.e. expired challenges are purged once per this interval.
                                    Default interval is 3600 sec (1 hour)
        """
        self.cttl = cttl
        self._db  = storage
        self._log = log.getLogger("port.proto")
        self.maintenanceInterval = maintenanceInterval
        self._mjtimer: Timer     = None

    def start(self):
        self.doMaintenance()

    def stop(self):
        if self._mjtimer is not None and self._mjtimer.is_alive():
            self._log.debug("Stopping maintenance thread...")
            self._mjtimer.cancel()
            self._mjtimer.join(30)
            if self._mjtimer.is_alive():
                self._log.error("Couldn't stop maintenance thread")
            else:
                self._log.debug("Stopping maintenance thread...SUCCESS")

    def doMaintenance(self):
        self._log.debug('Start maintenance job')
        if self._mjtimer is not None:
            self._mjtimer.cancel()

        try:
            self.__purgeExpiredChallenges()
        except Exception as e:
            self._log.error("An exception was encountered while doing maintenance job")
            self._log.exception(e)

        self._mjtimer = Timer(self.maintenanceInterval, self.doMaintenance)
        self._mjtimer.setName('maintenance_job')
        self._mjtimer.daemon = True # Causes the thread to be canceled by SIGINT
        self._mjtimer.start()
        self._log.debug('Finished maintenance job, next schedule at: {}'
            .format(utils.time_now() + timedelta(seconds=self.maintenanceInterval)))

    def createNewChallenge(self, uid: UserId) -> Tuple[Challenge, datetime]:
        """
        Returns new proto challenge for user ID.
        If non-expired challenge is found in the db for the user, that challenge is returned instead.
        :param uid: The user ID to generate the challenge for.
        :return: Challenge and expiration time
        """
        self._log.debug("Generating challenge for uid={}".format(uid))
        now = utils.time_now()
        cet = self._db.findChallengeByUID(uid)
        if cet is not None: # return found challenge if still valid
            if self._has_challenge_expired(cet[1], now):
                self._log.debug("Deleting existing expired challenge from DB")
                self._db.deleteChallenge(cet[0].id)
            else:
                self._log.debug("Found existing challenge")
                return cet
        # Let's generate new challenge, as non was found or already expired.
        c  = Challenge.generate(now, uid)
        et = self._get_challenge_expiration(now)
        self._db.addChallenge(uid, c, et)
        self._log.debug("New challenge created cid={}".format(c.id))
        return (c, et)

    def cancelChallenge(self, cid: CID) -> Union[None, dict]:
        self._db.deleteChallenge(cid)
        self._log.debug("Challenge canceled cid={}".format(cid))

    def register(self, uid: UserId, sod: ef.SOD, dg15: ef.DG15, cid: CID, csigs: List[bytes], dg14: ef.DG14 = None) -> Tuple[UserId, SessionKey, datetime]:
        """
        Register new user account.

        :param dg15: eMRTD DataGroup file 15
        :param sod: eMRTD Data Security Object
        :param cid: Challenge id
        :param csigs: List of signatures made over challenge chunks
        :param dg14: (Optional) eMRTD DataGroup file 14
        :return: Tuple of user id, session key and session expiration time
        """
        # 1. Verify account doesn't exist yet
        if self._db.accountExists(uid):
            et = self._db.getAccountExpiry(uid)
            if not utils.has_expired(et, utils.time_now()):
                raise peAccountAlreadyRegistered
            self._log.debug("Account has expired, registering new credentials")

        # 2. Verify emrtd PKI trust chain
        self.__verify_emrtd_trustchain(sod, dg14, dg15)

        # 3. Verify challenge authentication
        aaSigAlgo = None
        aaPubKey = dg15.aaPublicKey
        if aaPubKey.isEcKey():
            if dg14 is None:
                raise peDg14Required
            elif dg14.aaSignatureAlgo is None:
                raise peMissingAAInfoInDg14
            aaSigAlgo = dg14.aaSignatureAlgo

        self.__verify_challenge(cid, aaPubKey, csigs, aaSigAlgo)
        self._db.deleteChallenge(cid) # Verifying has succeeded, delete challenge from db

        # 4. Generate session key and session
        sk = SessionKey.generate()
        s  = Session(sk)

        # 5. Insert account into db
        et = self._get_default_account_expiration()
        a = AccountStorage(uid, sod, aaPubKey, aaSigAlgo, None, s, et)
        self._db.addOrUpdateAccount(a)

        self._log.debug("New account created: uid={}".format(uid.hex()))
        if len(sod.dsCertificates) > 0:
            self._log.debug("Issuing country of account's eMRTD: {}"
                .format(utils.code_to_country_name(sod.dsCertificates[0].issuerCountry)))
        self._log.verbose("valid_until={}".format(a.validUntil))
        self._log.verbose("login_count={}".format(a.loginCount))
        self._log.verbose("dg1=None")
        self._log.verbose("pubkey={}".format(a.aaPublicKey.hex()))
        self._log.verbose("sigAlgo={}".format("None" if aaSigAlgo is None else a.aaSigAlgo.hex()))
        self._log.verbose("session={}".format(s.bytes().hex()))

        # 6. Return user id, session key and session expiry date
        return (uid, sk, et)

    def login(self, uid: UserId, cid: CID, csigs: List[bytes], dg1: ef.DG1 = None) -> Tuple[SessionKey, datetime]:
        """
        Login user and return session key.

        :param uid: User id
        :param cid: Challenge id
        :param csigs: List of signatures made over challenge chunks
        :param dg1: (Optional) eMRTD DataGroup file 1
        :return: Tuple of session key and session expiration time
        """
        # Get account
        a = self._db.getAccount(uid)

        # 1. Require DG1 if login count is gt 1
        self._log.debug("Logging-in account with uid={} login_count={}".format(uid.hex(), a.loginCount))
        if a.loginCount >= 1 and a.dg1 is None and dg1 is None:
            self._log.error("Login cannot continue due to max no. of anonymous logins and no DG1 file was provided!")
            raise peDg1Required

        # 2. If we got DG1 verify SOD contains its hash,
        #    and assign it to the account
        if dg1 is not None:
            self._log.debug("Verifying received DG1(surname={} name={}) file is valid ...".format(dg1.mrz.surname, dg1.mrz.name))
            sod = a.getSOD()
            self.__verify_sod_contains_hash_of(sod, dg1)
            a.setDG1(dg1)

        # 3. Verify account credentials haven't expired
        if utils.has_expired(a.validUntil, utils.time_now()):
            raise peAccountExpired

        # 4. Verify challenge
        self.__verify_challenge(cid, a.getAAPublicKey(), csigs, a.getAASigAlgo())
        self._db.deleteChallenge(cid) # Verifying has succeeded, delete challenge from db

        # 5. Generate session key and session
        sk = SessionKey.generate()
        s  = Session(sk)
        a.setSession(s)

        # 6. Update account
        a.loginCount += 1
        self._db.addOrUpdateAccount(a)
        if dg1 is not None:
            self._log.info("File DG1(surname={} name={}) issued by {} is now tied to eMRTD pubkey={}"
                     .format(dg1.mrz.surname, dg1.mrz.name, utils.code_to_country_name(dg1.mrz.country), a.aaPublicKey.hex()))

        # 7. Return session key and session expiry date
        self._log.debug("User has been successfully logged-in. uid={} session_expires: {}".format(uid.hex(), a.validUntil))
        self._log.verbose("session={}".format(s.bytes().hex()))
        return (sk, a.validUntil)

    def sayHello(self, uid, mac):
        """
        Return greeting message based on whether user being anonymous or not.

        :param uid: User id
        :param mac: session mac over function name and uid
        :return: Greeting message
        """
        # Get account
        a = self._db.getAccount(uid)

        # 1. verify session mac
        data = "sayHello".encode('ascii') + uid
        self.__verify_session_mac(a, data, mac)

        # 2. return greetings
        msg = "Hi, anonymous!"
        dg1 = a.getDG1()
        if dg1 is not None:
            msg = "Hi, {} {}!".format(dg1.mrz.surname, dg1.mrz.name)
        return msg

    def __verify_challenge(self, cid: CID, aaPubKey: AAPublicKey, csigs: List[bytes], aaSigAlgo: SignatureAlgorithm = None ) -> None:
        """
        Check if signature is correct and the time frame is OK
        :raises:
            PeChallengeExpired: If challenge stored in db by cid has already expired
            PeMissingParam: If aaPubKey is ec public key and no sigAlgo is provided
            PeSigVerifyFailed: If verifying signatures over chunks of challenge fails
        """

        try:
            self._log.debug("Verifying challenge cid={}".format(cid))
            if aaPubKey.isEcKey() and aaSigAlgo is None:
                raise peMissingParamAASigAlgo

            # Verify if challenge has expired expiration time
            c, cct = self._db.getChallenge(cid)
            if self._has_challenge_expired(cct, utils.time_now()):
                self._db.deleteChallenge(cid)
                raise peChallengeExpired

            # Verify challenge signatures
            ccs = [c[0:8], c[8:16], c[16:24], c[24:32]]
            for idx, sig in enumerate(csigs):
                if not aaPubKey.verifySignature(ccs[idx], sig, aaSigAlgo):
                    raise peChallengeVerificationFailed
            self._log.success("Challenge signed with eMRTD was successfully verified!")
        except:
            self._log.error("Challenge verification failed!")
            raise

    def __verify_emrtd_trustchain(self, sod: ef.SOD, dg14: Union[ef.DG14, None], dg15: ef.DG15) -> None:
        """"
        Verify eMRTD trust chain from eMRTD SOD to issuing CSCA
        :raises: An exception is risen if any part of trust chain verification fails
        """
        assert isinstance(sod, ef.SOD)
        assert isinstance(dg14, (ef.DG14, type(None)))
        assert isinstance(dg15, ef.DG15)

        try:
            self._log.info("Verifying eMRTD trust chain ...")
            if dg14 is not None:
                self.__verify_sod_contains_hash_of(sod, dg14)

            self.__verify_sod_contains_hash_of(sod, dg15)
            self.__validate_certificate_path(sod)
            self._log.success("eMRTD trust chain was successfully verified!")
        except CertificateVerificationError as e:
            self._log.error("Failed to verify eMRTD certificate trust chain: {}".format(e))
            raise peTrustchainVerificationFailed from e
        except ProtoError as e:
            self._log.error("Failed to verify eMRTD certificate trust chain: {}".format(e))
            raise
        except Exception as e:
            self._log.error("Failed to verify eMRTD certificate trust chain! e={}".format(e))
            self._log.exception(e)
            raise

    def __get_dsc_by_issuer_and_serial_number(self, issuer: Name, serialNumber: int, sod: ef.SOD) -> Tuple[Optional[DocumentSignerCertificate], bool]:
        """
        Get DSC from SOD or from database if not found ind SOD.
        :param issuer:
        :param serialNumber:
        :param sod:
        :return: Pair of DSC/None and boolean whether DSC should be validated to CSCA certificate.
                 Note: DSC should be validated to CSCA only if DSC is found in SOD file.
                       DSC found in DB should be considered already validated.
        """
        # Try to find DSC in database
        dsc = self._db.findDscBySerial(issuer, serialNumber)
        if dsc is not None:
            return (dsc.getCertificate(), False)

        # DSC not found in database, try to find it in SOD file
        for dsc in sod.dsCertificates:
            if dsc.serial_number == serialNumber and dsc.issuer == issuer:
                return (dsc, True) # DSC should be validated to issuing CSCA
        return (None, False)

    def __get_dsc_by_subject_key(self, subjectKey: bytes, sod: ef.SOD) -> Tuple[Optional[DocumentSignerCertificate], bool]:
        """
        Get DSC from SOD or from database if not found ind SOD.
        :param subjectKey:
        :param sod:
        :return: Pair of DSC/None and boolean whether DSC should be validated to CSCA certificate.
                 Note: DSC should be validated to CSCA only if DSC is found in SOD file.
                       DSC found in DB should be considered as already validated.
        """
        # Try to find DSC in database
        dsc = self._db.findDscBySubjectKey(subjectKey)
        if dsc is not None:
            return (dsc.getCertificate(), False)

        # DSC not found in database, try to find it in SOD file
        for dsc in sod.dsCertificates:
            if dsc.subjectKey == subjectKey:
                return (dsc, True) # DSC should be validated to issuing CSCA
        return (None, False)

    def __validate_dsc_to_csca(self, dsc: DocumentSignerCertificate):
        """ Find DSC's issuing CSCA and validate DSC with it. """
        # 1. Get CSCA which issued DSC
        self._log.verbose("Trying to find the DSC issuing CSCA in DB. DSC issuer=[{}] auth_key={}"
            .format(dsc.issuer.human_friendly, dsc.authorityKey.hex() if dsc.authorityKey is not None else None))

        cscas: Optional[List[CscaStorage]] = self._db.findCscaCertificates(dsc.issuer, dsc.authorityKey)
        if cscas is None:
            raise peCscaNotFound

        csca: Optional[CscaCertificate] = None
        for c in cscas:
            if c.notValidAfter >= dsc.notValidAfter:
                csca = c.getCertificate()
                break

        if csca is None:
            raise peCscaNotFound

        self._log.verbose("Found CSCA country={} serial={} fp={} key_id={}".format(
            utils.code_to_country_name(csca.issuerCountry),
            csca.serial_number,
            csca.fingerprint[0:8],
            csca.subjectKey.hex() if csca.subjectKey is not None else 'N/A'
        ))

        # 2. Verify CSCA expiration time
        self._log.verbose("Verifying CSCA expiration time. {}".format(utils.format_cert_et(csca)))
        if not csca.isValidOn(utils.time_now()):
            self._log.error("CSCA has expired!")
            raise peCscaExpired

        # 3. verify CSCA really issued DSC
        self._log.verbose("Verifying CSCA issued DSC ...")
        dsc.verify(issuingCert=csca)

    def _get_challenge_expiration(self, createTime: datetime) -> datetime:
        """
        Calculates challenge expiration time from the time when challenge was created.
        :param createTime: The challenge create time.
        """
        createTime = createTime.replace(tzinfo=None)
        return createTime + timedelta(seconds=self.cttl)

    def _has_challenge_expired(self, expireTime: datetime, datetime: datetime) -> bool:
        """
        Verifies if challenge create time is already in the range of challenge expiration interval.
        :param expireTime: The challenge expiration time.
        :param datetime: The date and time to compare expiration against. (Should be current datetime)
        """
        expireTime = expireTime.replace(tzinfo=None)
        datetime   = datetime.replace(tzinfo=None)
        return utils.has_expired(expireTime, datetime)

    def __validate_certificate_path(self, sod: ef.SOD):
        """Verification of issuer certificate from SOD file"""
        self._log.debug("Validating path CSCA => DSC => SOD ...")
        assert isinstance(sod, ef.SOD)
        # Get DSCs certificates that signed SOD file. DSC is also validated to CSCA trust chain if necessary.
        dscs = []
        for _, signer in enumerate(sod.signers):
            if signer.name == "issuer_and_serial_number":
                #sni = signer['sid'].chosen
                signer = signer.chosen
                issuer = signer["issuer"]
                serial = signer["serial_number"].native
                self._log.verbose("Getting DSC which issued SOD by serial no.: {} and issuer: [{}]".format(serial, issuer.human_friendly))
                dsc, validateDSC = self.__get_dsc_by_issuer_and_serial_number(issuer, serial, sod)
            elif signer.name == "subject_key_identifier":
                keyid = signer.native
                self._log.verbose("Getting DSC which issued SOD by subject_key={}".format(keyid.hex()))
                dsc, validateDSC = self.__get_dsc_by_subject_key(keyid, sod)
            else:
                raise peUnknownPathSodToDsc

            if dsc is None:
                raise peDscNotFound

            self._log.verbose("Got DSC fp={} issuer_country={}, validating path to CSCA required: {}"
                .format(dsc.fingerprint[0:8], utils.code_to_country_name(dsc.issuerCountry), validateDSC))

            self._log.verbose("Verifying DSC expiration time. {}".format(utils.format_cert_et(dsc)))
            if not dsc.isValidOn(utils.time_now()):
                raise peDscExpired
            elif validateDSC:
                self.__validate_dsc_to_csca(dsc) # validate CSCA has issued DSC
            dscs.append(dsc)

        # Verify DSCs signed SOD file
        self._log.verbose("Verifying DSC issued SOD ...")
        sod.verify(issuer_dsc_certs=dscs)

    def __verify_sod_contains_hash_of(self, sod: ef.SOD, dg: ef.DataGroup):
        assert isinstance(sod, ef.SOD)
        assert isinstance(dg, ef.DataGroup)

        self._log.debug("Verifying SOD contains matching hash of {} file ...".format(dg.number.native))
        if self._log.getEffectiveLevel() <= log.VERBOSE:
            sod_dghv = sod.ldsSecurityObject.dgHashes.find(dg.number)
            self._log.verbose("SOD contains hash of {} file: {}".format(dg.number.native, (sod_dghv is not None)))
            if sod_dghv is not None:
                hash_algo = sod.ldsSecurityObject.dgHashAlgo['algorithm'].native
                self._log.verbose("{} hash value of {} file in SOD: {}".format(hash_algo, dg.number.native, sod_dghv.hash.hex()))
                h = sod.ldsSecurityObject.getDgHasher()
                h.update(dg.dump())
                self._log.verbose("Actual {} hash value of {} file: {}".format(hash_algo, dg.number.native, h.finalize().hex()))

        # Validation of dg hash value in SOD
        if not sod.ldsSecurityObject.contains(dg):
            raise peInvalidDgFile(dg.number)
        self._log.debug("{} file is valid!".format(dg.number.native))

    def _get_default_account_expiration(self):
        """ Returns until the session is valid. """
        # Note: in ideal situation passport expiration date would be read from DG1 file and returned here.
        #       For now we return fix 10min period but should be calculated from the expiration time of DSC who signed the account's SOD.
        return utils.time_now() + timedelta(minutes=10)

    def __verify_session_mac(self, a: AccountStorage, data: bytes, mac: bytes):
        """
        Check if mac is valid
        :raises:
            PeMacVerifyFailed: If mac is invalid
        """
        self._log.debug("Verifying session MAC ...")

        s = a.getSession()
        self._log.verbose("nonce: {}".format(s.nonce))
        self._log.verbose("data: {}".format(data.hex()))
        self._log.verbose("mac: {}".format(mac.hex()))

        success = s.verifyMAC(data, mac)
        self._log.debug("MAC successfully verified!")

        # Update account's session nonce
        a.setSession(s)
        self._db.addOrUpdateAccount(a)

        if not success:
            raise PeMacVerifyFailed("Invalid session MAC")

    def __purgeExpiredChallenges(self):
        self._log.debug('Purging expired challenges')
        now = utils.time_now()
        self._db.deleteExpiredChallenges(now)
