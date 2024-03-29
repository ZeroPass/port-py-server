from __future__ import annotations

from asn1crypto.cms import IssuerAndSerialNumber
from datetime import datetime, timedelta
from port import database, log as log
from port.database.sod import SodTrack

from pymrtd import ef
from pymrtd.ef.sod import DataGroupHash
from pymrtd.pki.cms import SignerInfo
from pymrtd.pki.crl import CertificateRevocationList
from pymrtd.pki.keys import AAPublicKey, SignatureAlgorithm
from pymrtd.pki.x509 import Certificate, CertificateVerificationError, CscaCertificate, DocumentSignerCertificate

from typing import List, Optional, Tuple, Union

from . import utils
from .error import * # pylint: disable=unused-wildcard-import, wildcard-import
from .lds_filterlist import ldsMatchWhitelist, LdsHashFilterList, FilterListHash
from .types import Challenge, CID, CountryCode, SodId, hook, UserId

class PortProto:

    def __init__(self, storage: database.StorageAPI, cttl: int):
        """
        Initializes new PortProto.
        :param storage: database storage to use
        :param cttl: Challenge expiration time in seconds (time-to-live)
        """
        self.cttl  = cttl
        self._db   = storage
        self._log  = log.getLogger("port.proto")
        self.blsod = set() # EF.SOD blacklist

    def blacklistSod(self, sodId: SodId):
        self.blsod.add(sodId)

    def whitelistSod(self, sodId: SodId):
        if sodId in self.blsod:
            self.blsod.remove(sodId)

    @hook
    def getChallenge(self, uid: UserId, seed: Optional[bytes] = None) -> Tuple[Challenge, datetime]:
        """
        Returns new proto challenge for registered user user ID.
        If non-expired challenge is found in the db for the user, that challenge is returned instead.
        :param uid: The existing user ID to generate the challenge for.
        :return: Challenge and expiration time
        :raises `peAccountNotAttested`: If previous account PA attestation is not valid anymore,
                                        e.g.: accnt.sodId=None, accnt EF.SOD certificate trustchain is not valid anymore.
        :raises `peAttestationExpired`: If account attestation has expired.
        :raises `seAccountNotFound`: If no account exists under provided `uid`.
        :raises `StorageAPIError`: On storage related errors.
        """
        self._log.debug("Generating challenge for uid=%s", uid)

        # TODO: Uncomment below code to limit function to register accounts
        # # 1. Get account
        # a = self._db.getAccount(uid)

        # # 2. Verify account has valid PA attestation and has not expired.
        timeNow = utils.time_now()
        # self._check_account_is_valid_on(a, timeNow)
        # # if a.expires is not None \
        # #     and utils.has_expired(a.expires, timeNow):
        # #     raise peAttestationExpired
        # self._check_attestation(a)

        # 3. a) Find any existing challenge, if it does and is not expired return it
        cet = self._db.findChallengeByUID(uid)
        if cet is not None: # return found challenge if still valid
            if self._has_challenge_expired(cet[1], timeNow):
                self._log.debug("Deleting existing expired challenge from DB")
                self._db.deleteChallenge(cet[0].id)
            else:
                self._log.debug("Found existing challenge")
                return cet

        # 3. b) No challenge exists or has expired, let's generate a new one.
        c  = Challenge.generate(timeNow, uid + (seed or b''))
        et = self._get_challenge_expiration(timeNow)
        self._db.addChallenge(uid, c, et)
        self._log.debug("New challenge created cid=%s", c.id)
        return (c, et)

    @hook
    def cancelChallenge(self, cid: CID) -> Union[None, dict]:
        self._db.deleteChallenge(cid)
        self._log.debug("Challenge canceled, cid=%s", cid)

    def purgeExpiredChallenges(self, time:datetime = utils.time_now()) -> bool:
        """
        Function cleans all expired proto challenges from the database.
        :param `time`: All challenges that are less than this time are deemed to be expired.
                       Default is what returns `utils.time_now()`.
        :return: True if deleting cleaning succeeds, otherwise False.
        """
        try:
            self._log.debug('Purging expired challenges')
            self._db.deleteExpiredChallenges(time)
            return True
        except Exception as e:
            self._log.error("An exception was encountered while purging expired challenges!")
            self._log.exception(e)
            return False

    @hook
    def register(self, uid: UserId, sod: ef.SOD, dg15: Optional[ef.DG15] = None , dg14: Optional[ef.DG14] = None, allowSodOverride: bool = False) \
        -> dict:
        """
        Register new user account with eMRTD attestation (Passive Authentication).

        Any existing account can be re-registered if `allowSodOverride`=True, or account has expired or has invalid attestation.
        By invalid attestation it means that the attested certificate trustchain is invalid or account doesn't have EF.SOD track assigned or can't be found in the DB.

        Note that account can be re-registered only with EF.SOD which issuing country matches the account's attestation country.
        The expiration time of existing account will be copied on re-registration in case it has not expired yet.
        Also dg1 and dg2 will be copied to the new registration if their hashes matches hash stored in `sod`.

        :param `uid`: User ID to register new account for.
        :param `sod`: eMRTD Data Security Object
        :param `dg15`: (Optional) eMRTD DataGroup file 15. File is required if `sod` contains hash of EF.DG15.
        :param `dg14`: (Optional) eMRTD DataGroup file 14. File is required if `dg15` contains EC public key.
        :param `allowSodOverride`: If True, override any existing attestation for account under `uid`.
                                   Previously EF.SOD will stay in DB for the 'sybil' protection and no account will be able to re-register it.

        :return: Empty dictionary

        :raises `peAccountAlreadyRegistered`: When account with `uid` already exist and has not expired yet.
        :raises `peCountryCodeMismatch`: If an existing account tries to override attestation with EF.SOD issued by different country than
                                       previous attestation country country.
        :raises `peDscNotFound`: When no `sod` signing DSC certificate is found.
        :raises `peEfDg14MissingAAInfo`: If `dg14` is missing AAInfo data.
        :raises `peEfDg14Required`: If `dg15` contains ECC public key and `dg14` is None.
        :raises `peEfDg15Required`: If `sod` contains hash of EF.DG15.
        :raises `peEfSodMatch`: If the same or matching EF.SOD already exists in the DB.
        :raises `peEfSodNotGenuine`: If `sod` verification with DSC certificate fails i.e. signature verification fails.
                                   E.g.: when EF.SOD was intentionally altered or is corrupted.
        :raises `peInvalidDgFile`: If `sod` doesn't contain the same hashes of `dg15` and `dg14` (if present)
        :raises `peInvalidEfSod`: If no valid signer is found for `sod`, `sod` is not signed or contains invalid signer infos.
        :raises `peTrustchainCheckFailedExpiredCert`: If any of the certificates in the EF.SOD trustchain has expired.
        :raises `peTrustchainCheckFailedNoCsca`: If root issuing CSCA certificate is not found.
        :raises `peTrustchainCheckFailedRevokedCert`: If any of the certificates in the EF.SOD trustchain is revoked.
        :raises `ProtoError`: any exception which is risen from addDscCertificate method when new DSC is added or
                            risen from _verify_cert_trustchain method.
        :raises `StorageApiError`: In any case when there is an error in connection to the DB storage
                                 or problem with storing object in storage.
        """
        self._log.debug("register: uid=%s, %s %s %s allowSodOverride=%s",
            uid, sod, dg15 if dg15 is not None else "", dg14 if dg14 is not None else "", allowSodOverride)

        # 1. Verify we have all required DG files and are authenticated in EF.SOD
        #    Note: We do this first, since it should be cheap check.
        aaSigAlgo = None
        aaPubKey = None
        if dg15 is not None:
            self._verify_sod_contains_hash_of(sod, dg15)
            aaPubKey = dg15.aaPublicKey
            if aaPubKey.isEcKey():
                if dg14 is None:
                    raise peEfDg14Required
                aaSigAlgo = dg14.aaSignatureAlgo
                if aaSigAlgo is None:
                    raise peEfDg14MissingAAInfo
        elif sod.ldsSecurityObject.dgHashes.contains(ef.DataGroupNumber(15)): # EF.DG15 is required if present in EF.SOD
            raise peEfDg15Required

        if dg14 is not None: # check EF.SOD contains Ef.DG14 if provided
            self._verify_sod_contains_hash_of(sod, dg14)

        # 2. Verify if account already exists, and if it does
        #    check that it has expired already or allowSodOverride == True.
        accnt = self._db.findAccount(uid)
        if accnt is not None:
            self._log.debug("Found existing account uid=%s in the DB", uid)
            if not allowSodOverride:
                if self._is_account_pa_attested(accnt): # Allow account re-attestation if PA attestation is invalid.
                    raise peAccountAlreadyRegistered
                self._log.debug("Account attestation has expired or is invalid, registering new attestation ...")
            else:
                self._log.debug("allowSodOverride=True, registering new attestation")

        # Following 2 emrtd checks are done first for the precautionary reasons
        # to prevent potential spoofing attacks if there are any undiscovered bugs.

        # 3. Verify EF.SOD is genuine aka passive authn
        #    Before any other operation with sod,
        #    verify that an actual country issued the mrtd.
        dsc: database.DscStorage = self._verify_sod_is_genuine(sod)
        self._log.success("%s appears to be genuine! issuer dscId=%s", sod, dsc.id)

        # 4. Verify the country code matches if account exists already.
        #    Note, this locks account to the country.
        if accnt is not None and accnt.country != dsc.country:
            raise peCountryCodeMismatch

        # 5. Check EF.SOD is not blacklisted or there doesn't already exit any similar EF.SOD duplicate in the DB
        st = database.SodTrack.fromSOD(sod, dscId=dsc.id)
        self._log.debug("%s => sodId=%s", sod, st.id)
        if st.id in self.blsod:
            raise peEfSodNotAllowed

        self._log.debug("Searching for any EF.SOD track in DB which matches sodId=%s", st.id)
        sods = self._find_sod_match(dsc.country, st)
        if sods is not None:
            self._log.debug("Found %s matching track(s) in the DB.", len(sods))
            for mst in sods:
                if accnt is not None and mst.id == accnt.sodId:
                    # Allow registering of matching EF.SOD only if `mst`
                    # belongs to `accnt`.
                    self._log.info(" Removing matched EF.SOD track sodId=%s from DB due to match with account's sodId.", mst.id)
                    self._db.deleteSodTrack(mst.id)
                    continue
                self._log.error("Found a valid matching EF.SOD track with sodId=%s for sodId=%s", mst.id, st.id)
                raise peEfSodMatch

        # 6. Save EF.SOD track
        self._db.addSodTrack(st)

        # 7. Insert account into db

        # Set previous registered EF.DG1 & EF.DG2 files
        # if hashes match with the hashes stored in the
        # new EF.SOD ldsSecurityObject
        dg1 = None
        dg2 = None
        if accnt:
            if accnt.sodId == st.id:
                # assume that all files are the same in the new EF.SOD
                dg1 = accnt.dg1
                dg2 = accnt.dg2
            else:
                # Try to find matching hashes of existing EF.DG files
                if accnt.dg1 and st.contains(ef.DG1.load(accnt.dg1)):
                    dg1 = accnt.dg1
                if accnt.dg2:
                    h = st.getDgHasher()
                    h.update(accnt.dg2)
                    if h.finalize() == st.dg2Hash:
                        dg2 = accnt.dg2

        et = self._get_account_expiration(uid, accnt, st, dsc)
        accnt = database.AccountStorage(
            uid=uid,
            country=dsc.country,
            sodId=st.id,
            expires=et,
            aaPublicKey=aaPubKey,
            aaSigAlgo=aaSigAlgo,
            aaCount=0,
            aaLastAuthn=None,
            dg1=dg1,
            dg2=dg2
        )
        self._db.updateAccount(accnt)

        self._log.debug("New account created: uid=%s", uid)
        if len(sod.dscCertificates) > 0:
            self._log.debug("Account's eMRTD issuing country: %s",
                utils.code_to_country_name(dsc.country))
        self._log.debug("sodId=%s"  , accnt.sodId)
        self._log.debug("expires=%s", accnt.expires)
        self._log.debug("aaCount=%s", accnt.aaCount)
        self._log.debug("dg1=%s"    , accnt.dg1.hex() if accnt.dg1 else None)
        self._log.debug("dg2=%s"    , accnt.dg2.hex() if accnt.dg2 else None)
        self._log.debug("pubkey=%s" , accnt.aaPublicKey.hex() if accnt.aaPublicKey else None)
        self._log.debug("sigAlgo=%s", accnt.aaSigAlgo.hex() if accnt.aaSigAlgo else None)
        return {}

    @hook
    def getAttestationInfo(self, uid: UserId) -> Tuple[database.AccountStorage, database.SodTrack, datetime, bool]:
        """
        Returns attestation info for account under `uid`.
        :param `uid`: `UserId` of account.
        :return: A tuple consisting of
                `database.AccountStorage` object,
                 account's `database.SodTrack`object,
                 `datetime` when the account attestation expires and
                 `bool` If True account has valid passive attestation.
        :raises `seAccountNotFound`: If no account exists under provided `uid`.
        :raises `StorageAPIError`: On storage related errors.
        """
        self._log.debug("getAttestationInfo: uid=%s", uid)
        a = self._db.getAccount(uid)
        if a.sodId is not None:
            st = self._db.findSodTrack(a.sodId)
        pa_attested = self._is_account_pa_attested(a, st)

        expires = a.expires
        if expires is None:
            expires = utils.time_now()
            if st is not None:
                dsc = self._db.findDsc(st.dscId)
                if dsc is not None:
                    expires = dsc.notValidAfter
        return (a, st, expires, pa_attested)

    @hook
    def getAssertion(self, uid: UserId, cid: CID, csigs: List[bytes]) -> dict:
        """
        Get eMRTD active authentication assertion for existing account with `uid`.

        :param `uid`: User id
        :param `cid`: Challenge id
        :param `csigs`: List of signatures made over challenge chunks
        :return: Empty dictionary
        :raises `peChallengeExpired`: If challenge stored in db by cid has already expired
        :raises `peChallengeVerificationFailed`: If verification of challenge signature fails.
        :raises `peMissingParamAASigAlgo`: If aaPubKey is ec public key and no sigAlgo is provided
        :raises `peAccountNotAttested`: If previous account attestation is not valid anymore,
                                        e.g.: accnt.sodId=None, accnt EF.SOD certificate trustchain is not valid anymore.
        :raises `peAttestationExpired`: If account attestation has expired.
        :raises `seAccountNotFound`: If no account exists under provided `uid`.
        :raises `seChallengeNotFound`: If challenge is not found.
        :raises `StorageAPIError`: On storage related errors.
        """
        self._log.debug("getAssertion: uid=%s cid=%s", uid, cid)

        # 1. Get account
        a = self._db.getAccount(uid)

        # 2. Verify account hasn't expired (expired attestation)
        timeNow = utils.time_now()
        self._check_account_is_valid_on(a, timeNow)

        # 3. Verify challenge
        self._verify_challenge(uid, cid, a.getAAPublicKey(), csigs, a.getAASigAlgo())

        # 4. Verify account still has still valid attestation
        self._log.debug("Verifying account attestation is still valid for sodId=%s", a.sodId)
        self._check_attestation(a)

        self._db.deleteChallenge(cid) # Verifying has succeeded, delete challenge from db

        # 6. Update account
        a.aaCount    += 1
        a.aaLastAuthn = timeNow
        self._db.updateAccount(a)
        self._log.debug("Authentication for gerAssert succeeded. uid=%s aaCount=%s", uid, a.aaCount)

        return {}

    @hook
    def addCscaCertificate(self, csca: CscaCertificate, allowSelfIssued: bool = False) -> database.CscaStorage:
        """
        Adds new CSCA certificate into database.
        Before CSCA is added to the DB, the certificate is verified that it conforms to the ICAO 9303 standard.
        i.e.: Is CA certificate constraints cert path to 0 and it hasn't expired yet.
        If self issued CSCA is not allowed, the protocol verifies if it has valid CSCA link certificate (LCSCA) for it,
        and if not the function fails. Certificate goes also through trust chain verification e.g. check if certificate wasn't revoked
        or the certificate signature can be verified successfully (in LCSCA case).

        :param csca: The CSCA certificate to add.
        :param allowSelfIssued: By default false, if set to True the self issued certificate will be added to the DB.
                                Warning: self-issued CSCA should only be allowed from privileged and verified sources
                                         e.g. fully verified CSCA master list, server admin).
                                         Self-issued CSCA should be PROHIBITED, for example, through public api.
        :return database.CscaStorage:
        :raises peCscaExists: When `csca` is already stored in the database.
        :raises peCscaNotFound: When no issuing CSCA is found for LCSCA certificate `csca`.
        :raises peCscaSelfIssued: If `allowSelfIssued` is False and no matching LCSCA certificate is found for `csca`.
        :raises peCscaTooNewOrExpired: If CSCA is too new (nvb > now) or has expired.
        :raises peInvalidCsca: When CSCA doesn't conform to the ICAO 9303 standard.
        """
        if not utils.is_valid_alpha2(csca.issuerCountry):
            self._log.error("Trying to add CSCA certificate with no or invalid country code!")
            raise peInvalidCsca
        try:
            self._log.debug("addCscaCertificate: C=%s serial=%s allowSelfIssued=%s",
                CountryCode(csca.issuerCountry), database.CscaStorage.makeSerial(csca.serial_number).hex(), str(allowSelfIssued))

            # 1.) Check if CSCA is valid at current time.
            # Although this check is also performed by the _verify_cert_trustchain
            # we perform this check anyway here, to filter out and not to waste much
            # of resources on any expired certificate.
            timeNow = utils.time_now()
            if not csca.isValidOn(timeNow):
                self._log.error("Trying to add CSCA certificate which is too new or has expired! C=%s serial=%s %s",
                    csca.issuerCountry, database.CscaStorage.makeSerial(csca.serial_number).hex(), utils.format_cert_et(csca, timeNow))
                raise peCscaTooNewOrExpired

            # 2.) Verify we have conformant CSCA certificate
            # Note:
            #   CSCA certificates:lt_csca_275b.cer, lt_csca_2748.cer, lt_csca_2761.cer
            #   have invalid encoding of subject key identifier and key_identifier & subjectKey methods throw an exception.
            #   i.e.: KeyIdentifier is defined in RFC 5280 as OCTET STRING within OCTET STRING
            #         but the problematic certs encode key id as single OCTET STRING.
            csca.checkConformance()

            # 3.) Find the issuer if csca is LCSCA or corresponding LCSCA.
            issuerCert: Optional[database.CscaStorage] = None # None for allowed self-issued
            selfIssued = csca.self_signed == 'maybe'
            if selfIssued:
                if not allowSelfIssued:
                    # Find matching LCSCA or fail
                    self._log.debug("Looking for matching LCSCA...")
                    cscas: List[database.CscaStorage] = self._db.findCscaCertificates(csca.subject, csca.subjectKey)
                    for c in (cscas or []):
                        crt: CscaCertificate = c.getCertificate()
                        if csca.fingerprint == crt.fingerprint:
                            raise peCscaExists
                        if crt.isValidOn(timeNow) and \
                           (crt.subjectKey == csca.subjectKey or \
                            crt.public_key.dump() == csca.public_key.dump()):
                            self._log.debug("Found LCSCA ")
                            issuerCert = c # The cert id should not be used for issuerId
                            break

                    if issuerCert is None:
                        self._log.error("No LCSCA found for self-issued CSCA certificate. C=%s serial=%s allowSelfIssued=%s",
                            CountryCode(csca.issuerCountry), csca.serial_number, str(allowSelfIssued))
                        raise peCscaSelfIssued
            else: #LCSCA
                cscas: List[database.CscaStorage] = self._db.findCscaCertificates(csca.issuer, csca.authorityKey)
                for c in (cscas or []):
                    if c.isSelfIssued and c.isValidOn(timeNow):
                        issuerCert = c
                        break
                if issuerCert is None:
                    raise peCscaNotFound

            # 4.) Verify cert signature
            csca.verify(issuerCert=(csca if selfIssued else issuerCert.getCertificate()), checkConformance = False)

            # 5.) Verify certificate trustchain validity and store CSCA in DB
            cs = database.CscaStorage(csca, None if selfIssued else issuerCert.id)
            self._verify_cert_trustchain(cs)
            self._db.addCscaStorage(cs)

            # 6.) Save any CRL distribution url stored in csca
            self._save_crl_url_from_cert(cs.country, csca)
            self._log.info("The new CSCA certificate was inserted into the DB. id=%s C=%s serial=%s", cs.id, cs.country, cs.serial.hex())
            return cs
        except ProtoError:
            raise
        except CertificateVerificationError as e: # Conformance check failed or signature verification failed
            self._log.error("Certificate conformance check or signature verification has failed while trying to add new CSCA certificate! C=%s serial=%s",
                csca.issuerCountry, database.CscaStorage.makeSerial(csca.serial_number).hex())
            self._log.error("  e=%s", e)
            raise peInvalidCsca from None
        except ValueError as e: # possible ans1crypto encountered parse error
            self._log.error("A parse error was encountered while trying to add new CSCA certificate! C=%s serial=%s",
                 csca.issuerCountry, database.CscaStorage.makeSerial(csca.serial_number).hex())
            self._log.exception(e)
            raise peInvalidCsca from None
        except Exception as e:
            self._log.error("An exception was encountered while trying to add new CSCA certificate! C=%s serial=%s",
                csca.issuerCountry, database.CscaStorage.makeSerial(csca.serial_number).hex())
            self._log.exception(e)
            raise

    @hook
    def addDscCertificate(self, dsc: DocumentSignerCertificate) -> database.DscStorage:
        """
        Adds new DSC certificate into database.
        Before DSC is added to the DB, the certificate is checked:
            - that is valid at the present time
            - that conforms to the ICAO 9303 standard.
            - if dsc contains document type list, check it can produce passport document.
            - that the issuing CSCA certificate exists in the DB and it has issued dsc (signature check)
            - has valid trustchain i.e. non of the certificate in the chain (CSCA => ... => dsc)
              has expired or has been revoked.
            - that the same DSC doesn't exist yet.

        :param dsc: The DSC certificate to add.
        :return database.DscStorage:
        :raises peDscTooNewOrExpired: When `dsc` is too new (nvb > now) or has expired.
        :raises peInvalidDsc: When `dsc` doesn't conform to the ICAO 9303 standard or
                              or verification of the signature with the issuing CSCA certificate fails.
        :raises peDscCantIssuePassport: If DSC can't issue passport document.
        :raises peCscaNotFound: When the issuing CSCA certificate can't be found in the DB.
        """
        if not utils.is_valid_alpha2(dsc.issuerCountry):
            self._log.error("Trying to add DSC certificate with no or invalid country code!")
            raise peInvalidDsc
        try:
            self._log.debug("addDscCertificate: C=%s serial=%s",
                CountryCode(dsc.issuerCountry), database.DscStorage.makeSerial(dsc.serial_number).hex())

            # 1.) Check if DSC is valid at current time.
            # Although this check is also performed by the _verify_cert_trustchain
            # we perform this check anyway here, to filter out and not to waste much
            # of resources on any expired certificate.
            timeNow = utils.time_now()
            if not dsc.isValidOn(timeNow):
                self._log.error("Trying to add DSC certificate which is too new or expired! C=%s serial=%s %s",
                    dsc.issuerCountry, database.DscStorage.makeSerial(dsc.serial_number).hex(), utils.format_cert_et(dsc, timeNow))
                raise peDscTooNewOrExpired

            # 2.) Verify we have conformant DSC certificate
            dsc.checkConformance()

            # 3.) Check that DSC can sign and issue passport document
            if dsc.documentTypes is not None:
                if not dsc.documentTypes.contains(ef.mrz.DocumentType.Passport.value):
                    raise peDscCantIssuePassport

            # 4.) Find the CSCA certificate that issued DSC.
            issuerCert = self._find_first_csca_for_dsc(dsc)
            if issuerCert is None:
                raise peCscaNotFound

            # 5.) Verify issuing CSCA has really issued dsc
            dsc.verify(issuerCert=issuerCert.getCertificate(), checkConformance = False)

            # 6.) Verify certificate trustchain validity and store DSC in DB
            cs = database.DscStorage(dsc, issuerCert.id)
            self._verify_cert_trustchain(cs)
            self._db.addDscStorage(cs)

            # 7.) Save any CRL distribution url stored in DSC
            self._save_crl_url_from_cert(cs.country, dsc)
            self._log.info("The new DSC certificate was inserted into the DB. id=%s C=%s serial=%s", cs.id, cs.country, cs.serial.hex())
            return cs
        except ProtoError:
            raise
        except CertificateVerificationError as e: # Conformance check failed or signature verification failed
            self._log.error("Certificate conformance check or signature verification has failed while trying to add new DSC certificate! C=%s serial=%s",
                dsc.issuerCountry, database.DscStorage.makeSerial(dsc.serial_number).hex())
            self._log.error("  e=%s", e)
            raise peInvalidDsc from None
        except ValueError as e: # possible ans1crypto encountered parse error
            self._log.error("A parse error was encountered while trying to add new DSC certificate! C=%s serial=%s",
                dsc.issuerCountry, database.DscStorage.makeSerial(dsc.serial_number).hex())
            self._log.exception(e)
            raise peInvalidDsc from None
        except Exception as e:
            self._log.error("An exception was encountered while trying to add new DSC certificate! C=%s serial=%s",
                dsc.issuerCountry, database.DscStorage.makeSerial(dsc.serial_number).hex())
            self._log.exception(e)
            raise

    @hook
    def updateCRL(self, crl: CertificateRevocationList):
        """
        Adds new or update existing country CRL in DB.
        Before CRL is added to the DB, it is checked:
            - that is valid at present time i.e. crl.thisUpdate <= timeNow
            - that existing or newer CRL already doesn't exists
            - that conforms to the ICAO 9303 standard.
            - that valid issuing CSCA certificate exists in the DB (signature check)

        :param crl: The CRL object.
        :raises peCrlTooNew: If CRL is too new (i.e.: crl.thisUpdate > timeNow).
        :raises peInvalidCrl: When CRL doesn't conform to the ICAO 9303 standard or
                              verification of the signature with the issuing CSCA certificate fails.
        :raises peCrlOld: When newer version of CRL for the country already exists.
        :raises peCscaNotFound: If the issuing CSCA certificate can't be found in the DB.
        :raises peTrustchainCheckFailedExpiredCert: If CSCA has expired.
        :raises peTrustchainCheckFailedRevokedCert: If CSCA is revoked.
        """
        if not utils.is_valid_alpha2(crl.issuerCountry):
            self._log.error("Trying to update CRL with no or invalid country code!")
            raise peInvalidCrl
        try:
            self._log.debug("updateCRL: issuer='%s' crlNumber=%s ", crl.issuer.human_friendly, crl.crlNumber)

            # 1.) Check if CRL is valid at present time.
            timeNow = utils.time_now()
            if crl.thisUpdate > timeNow:
                self._log.error("Trying to update future CRL! issuer='%s' crlNumber=%s thisUpdate=%s now=%s",
                    crl.issuer.human_friendly, crl.crlNumber, crl.thisUpdate, timeNow)
                raise peCrlTooNew

            # 2.) Check there is not already existing or newer CRL in the DB
            crlInfo = self._db.findCrlInfoByIssuer(crl.issuer)
            if crlInfo is not None:
                doUpdate = crl.thisUpdate > crlInfo.thisUpdate
                if crl.crlNumber is not None and crlInfo.number is not None:
                    doUpdate = doUpdate and (crl.crlNumber > crlInfo.number)
                if not doUpdate:
                    self._log.error("Skipping country CRL update, provided CRL is same or older than current!")
                    self._log.error("  issuer='%s' new.crlNumber=%s new.thisUpdate=%s current.crlNumber=%s current.thisUpdate=%s",
                        crl.issuer.human_friendly, crl.crlNumber, crl.thisUpdate, crlInfo.number, crlInfo.thisUpdate)
                    raise peCrlOld

            # 3.) Verify we have conformant CRL
            crl.checkConformance()

            # 4.) Find the CSCA certificate that issued CRL.
            issuerCert: Optional[database.CscaStorage] = None
            cscas: List[database.CscaStorage] = self._db.findCscaCertificates(crl.issuer, crl.authorityKey)
            for c in (cscas or []):
                if c.isValidOn(timeNow): # Skip any LCSCA that have expired
                    issuerCert = c
                    break
            if issuerCert is None:
                raise peCscaNotFound

            # 5.) Verify issuing CSCA has really issued CRL
            crl.verify(issuerCert=issuerCert.getCertificate(), checkConformance = False)

            # 6.) Verify issuing CSCA has valid trustchain
            self._verify_cert_trustchain(issuerCert)

            # 7.) Store tore CRL update info and revoked certificate info into DB
            self._db.updateCrl(crl)

            self._log.info("The country CRL was updated, issuer='%s' crlNumber=%s", crl.issuer.human_friendly, crl.crlNumber)
        except ProtoError:
            raise
        except CertificateVerificationError as e: # Conformance check failed or signature verification failed
            self._log.error("The conformance check or signature verification has failed while trying to update CRL! issuer='%s' crlNumber=%s ",
                crl.issuer.human_friendly, crl.crlNumber)
            self._log.error("  e=%s", e)
            raise peInvalidCrl from None
        except ValueError as e: # possible ans1crypto encountered parse error
            self._log.error("A parse error was encountered while trying while trying to update CRL! issuer='%s' crlNumber=%s ",
                crl.issuer.human_friendly, crl.crlNumber)
            self._log.exception(e)
            raise peInvalidCrl from None
        except Exception as e:
            self._log.error("An exception was encountered while trying to update CRL! issuer='%s' crlNumber=%s ",
                crl.issuer.human_friendly, crl.crlNumber)
            self._log.exception(e)
            raise

    @staticmethod
    def _filter_lds_hashes(st: SodTrack, whitelist: LdsHashFilterList) -> dict[ef.DataGroupNumber, bytes]:
        """"
        Function returns not-whitelisted LDS hashes mapped to data group number
        """
        dgHashes = {}
        for i in range(ef.DataGroupNumber.min, ef.DataGroupNumber.max + 1):
            dg = ef.DataGroupNumber(i)
            h = FilterListHash(st.hashAlgo, st.dgHash(dg))
            if h.hash is not None and not whitelist.contains(dg, h):
                dgHashes[dg] = h.hash
        return dgHashes

    def _find_sod_match(self, country: CountryCode, st: SodTrack) -> Optional[List[SodTrack]]:
        """
        Function returns list of SodTracks in database which matches the `st` SodID or
        there is LDS hash which matches the hash in `st`'s LDS hash list.
        """
        def log_lds_hashes(get_hash):
            if self._log.level <= log.DEBUG:
                self._log.debug("  hashAlgo=%s", st.hashAlgo)
                for i in range(ef.DataGroupNumber.min, ef.DataGroupNumber.max + 1):
                    dg = ef.DataGroupNumber(i)
                    h = get_hash(dg)
                    if h:
                        self._log.debug("  %s=%s", dg.native, h.hex())

        self._log.debug("EF.SOD LDS hashes: ")
        log_lds_hashes(st.dgHash)
        dgHashes = self._filter_lds_hashes(st, ldsMatchWhitelist[country])
        self._log.debug("LDS hashes to match in database: ")
        log_lds_hashes(lambda dgn: dgHashes[dgn] if dgn in dgHashes else None)
        return self._db.findSodTrackMatch(st.id, st.hashAlgo, dgHashes)

    def _find_first_csca_for_dsc(self, dsc: DocumentSignerCertificate) -> Optional[database.CscaStorage]:
        """
        Returns first issuing CSCA certificate of DSC certificate which is not LCSCA.
        :param dsc: DSC certificate to retrieve the issuing CSCA certificate for
        :return Optional[database.CscaStorage]:
        """
        cscas: List[database.CscaStorage] = self._db.findCscaCertificates(dsc.issuer, dsc.authorityKey)
        for c in (cscas or []):
            # This check ensures to not take any LCSCA certificate as the issuer cert
            # since they can have shorter expiration time
            if c.notValidAfter >= dsc.notValidAfter:
                return c
        return None

    def _verify_cert_trustchain(self, crt: database.CertificateStorage) -> None:
        """
        Verifies certificate trustchain and if fails ProtoError exception is risen.
        The check is done from certificate in question to the root issuer certificate:
            1.) Check if certificate is valid on current date.
            2.) Check that certificate isn't revoked.
            3.) If certificate has issuer, check issuer certificate is stored in DB and has valid trustchain.
        :param crt: The certificate to verify the trustchain for.
        :raises PePreconditionFailed: When there is invalid or revoked certificate in the trustchain.
                 Invalid certificate is either not valid at present time, is missing issuer certificate or issuer certificate is invalid.
        :raises StorageAPIError: If there is an DB storage error when trying to retrieve issuer CSCA certificate of `crt`.
        """
        assert isinstance(crt, database.CertificateStorage)
        self._log.debug("Verifying certificate trustchain id=%s C=%s serial=%s issuer_id=%s",
            crt.id, crt.country, crt.serial.hex(), crt.issuerId)

        if not crt.isValidOn(utils.time_now()):
            self._log.error("Failed to verify certificate trustchain: Expired certificate in the chain, id=%s C=%s serial=%s %s",
                    crt.id, crt.country, crt.serial.hex(), utils.format_cert_et(crt, utils.time_now()))
            raise peTrustchainCheckFailedExpiredCert

        if self._db.isCertificateRevoked(crt):
            self._log.error("Failed to verify certificate trustchain: Revoked certificate in the chain, id=%s C=%s serial=%s",
                crt.id, crt.country, crt.serial.hex())
            raise peTrustchainCheckFailedRevokedCert

        if not crt.isSelfIssued():
            issuer = self._db.findCsca(crt.issuerId)
            if issuer is None:
                self._log.error("Failed to verify certificate trustchain: issuer CSCA not found! id=%s C=%s serial=%s issuer_id=%s",
                    crt.id, crt.country, crt.serial.hex(), crt.issuerId)
                raise peTrustchainCheckFailedNoCsca
            self._verify_cert_trustchain(issuer)

    def _verify_sod_is_genuine(self, sod: ef.SOD) -> database.DscStorage:
        """
        Verifies EF.SOD file was issued by at least 1 valid country DSC certificate
        aka passive authentication as specified in ICAO9303 part 11 5.1 Passive Authentication.
        https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf

        Valid DSC in this context means DSC certificate which has valid trustchain.
        If DSC certificate doesn't exists yet in DB and is found in `sod` object
        it will be inserted into DB.

        In essence, the function goes over the list of signers and tries to find the first signer for
        which the signature verification over `sod` object succeeds and has valid trust chain.
        The verification per signer is as follows:
        1.) Try to find the DSC certificate in DB.
        2.) If found, do the DSC trustchain verification
            else insert DSC into DB though `addDscCertificate` method
        3.) Verify DSC issuer EF.SOD.
        4.) If there was no error in the above steps return from function

        :param `sod`: EF.SOD file to verify.
        :return: `database.DscStorage` of the first valid DSC certificate which signed EF.SOD.

        :raises `peInvalidEfSod`: If no valid signer is found, EF.SOD is not signed, contains invalid signer infos.
        :raises `peTrustchainCheckFailedExpiredCert`: If any of the certificates in the EF.SOD trustchain has expired.
        :raises `peTrustchainCheckFailedNoCsca`: If root issuing CSCA certificate is not found.
        :raises `peTrustchainCheckFailedRevokedCert`: If any of the certificates in the EF.SOD trustchain is revoked.
        :raises `peEfSodNotGenuine`: If Ef.SOD verification with DSC certificate fails i.e. signature verification fails.
                                   E.g.: when EF.SOD was intentionally altered or is corrupted.
        :raises `peDscNotFound`: When no signing DSC certificate is found.
        :raises `ProtoError`: any exception which is risen from `addDscCertificate` method when new DSC is added or
                              risen from _verify_cert_trustchain method.
        """
        self._log.verbose("_verify_sod_is_genuine: %s", sod)
        lastException = None
        si: SignerInfo
        for si in sod.signers:
            try:
                if si.signedAttributes is None:
                    self._log.debug("Skipping verifying %s file with SI='%s'. No signed attributes.", sod, si)
                    raise peInvalidEfSod

                self._log.debug("Trying to verify %s file with SI='%s'", sod, si)
                sid = si.id
                if isinstance(sid, IssuerAndSerialNumber):
                    dsc = self._db.findDscBySerial(sid['issuer'], sid['serial_number'].native)
                elif isinstance(sid, bytes):
                    dsc = self._db.findDscBySubjectKey(sid)
                else:
                    self._log.debug("Invalid SI version=%s", si.version.native)
                    raise peInvalidEfSod

                # Add DSC to DB if doesn't exist yet,
                # and verify DSC certificate trustchain
                if dsc is None:
                    self._log.debug("The DSC certificate was not found in DB for SI='%s', getting certificate from %s file.", si, sod)
                    dsc = sod.getDscCertificate(si)
                    if dsc is None:
                        self._log.debug("Skipping verifying %s file with SI='%s'. No DSC certificate found.", sod, si)
                        raise peDscNotFound
                    dsc = self.addDscCertificate(dsc) # Note, the dsc validity and trustchain should be checked in this function.
                else:
                    self._verify_cert_trustchain(dsc)

                # Verify Ef.SOD with found DSC certificate
                self._log.debug("Verifying %s with dscId=%s", sod, dsc.id)
                sod.verify(si, dsc.getCertificate())
                return dsc # The EF.SOD was successfully verified
            except Exception as e:
                self._log.warning("An exception was encountered while trying to verify %s file with SI='%s'", sod, si)
                self._log.warning("  error=%s", e)
                lastException = e

        if isinstance(lastException, ef.SODError):
            self._log.error("Failed to verify authenticity of file %s: %s", sod, lastException)
            raise peEfSodNotGenuine from lastException
        if isinstance(lastException, ProtoError):
            self._log.error("Failed to verify certificate trust chain for file %s: %s", sod, lastException)
            raise lastException

        if lastException is not None:
            self._log.error("Failed to verify authenticity of file %s! e=%s", sod, lastException)
            self._log.exception(lastException)
            raise lastException

        self._log.error("Failed to verify authenticity of file %s. No signers found!", sod)
        raise peInvalidEfSod

    def _is_sod_track_valid(self, st: database.SodTrack) -> bool:
        """
        Checks if EF.SOD track is still, verifies `st` has valid certificate trustchain.
        i.e. CSCA -> DSC -> EF.SOD track
        :param `st`: The EF.SOD track to check.
        :return: True if `st` has valid certificate trustchain, otherwise False.
        :raises StorageAPIError: On DB errors.
        :raises Exception*: Any other exception that is risen in the verification process, and is not `PePreconditionFailed`.
                            i.e not trustchain verification error.
        """
        assert isinstance(st, database.SodTrack)
        try:
            if st.dscId is None:
                return False
            dsc = self._db.findDsc(st.dscId)
            if dsc is None:
                return False
            self._verify_cert_trustchain(dsc)
            return True
        except PePreconditionFailed as e:
            self._log.debug("Looks like database.SodTrack doesn't have valid certificate trustchain.")
            self._log.debug("  tc_error=%s", e)
            return False
        except AssertionError:
            raise
        except database.StorageAPIError as e:
            self._log.error("A DB error was encountered while trying to checking if database.SodTrack is valid.")
            self._log.error("  e=%s", e)
            raise
        except Exception as e:
            self._log.error("An exception was encountered while trying to checking if database.SodTrack is valid.")
            self._log.error("  e=%s", e)
            raise

    def _is_account_pa_attested(self, accnt: database.AccountStorage, st: Optional[database.SodTrack] = None) -> bool:
        """
        Checks if account is attested with valid eMRTD biometric passport.
        In short, verifies that account attestation has not expired and
        has assigned valid EF.SOD track with valid certificates trustchain.
        i.e. CSCA -> DSC -> EF.SOD track -> account
        :param `accnt`: The account to verify.
        :param `st` (Optional): The database.SodTrack of `accnt` to verify the certificate trustchain of.
        :return: True if `accnt` has valid eMRTD attestation, otherwise False.
        :raises StorageAPIError: On DB errors.
        :raises Exception*: Any other exception that is risen in the verification process, and is not `PePreconditionFailed`.
                            i.e not trustchain verification error.
        """
        assert isinstance(accnt, database.AccountStorage)
        assert isinstance(st, (database.SodTrack, type(None)))
        try:
            if accnt.sodId is None \
                or (st is not None and accnt.sodId != st.id):
                return False
            if accnt.expires is not None \
                and utils.has_expired(accnt.expires, utils.time_now()):
                return False

            if st is None:
                st = self._db.findSodTrack(accnt.sodId)
            if st is None:
                return False
            return self._is_sod_track_valid(st)
        except database.StorageAPIError as e:
            self._log.error("A DB error was encountered while trying to checking if account is attested.")
            self._log.error("  e=%s", e)
            raise

    def _check_account_is_valid_on(self, account: database.AccountStorage, time:datetime) -> None:
        '''
            Check if account registration is valid on `time` and raise `peAttestationExpired` if not.
            :account AccountStorage: Account to verify expiry.
            :time datetime: The date and time to check if account is valid at.
            :raises `peAttestationExpired`: If account attestation has expired on specified `time`.
        '''
        if account.expires is not None \
            and utils.has_expired(account.expires, time):
            raise peAttestationExpired

    def _check_attestation(self, account: database.AccountStorage) -> None:
        '''
            Verifies that account attestation is still valid and raises `peAccountNotAttested` id not.
            :param account: Account storage to verify the attestation for.
            :raises `peAccountNotAttested`: If previous account attestation is not valid anymore,
                                        e.g.: accnt.sodId=None, accnt EF.SOD certificate trustchain is not valid anymore.
        '''
        self._log.debug("Verifying account attestation with uid=%s is still valid for sodId=%s", account.uid, account.sodId)
        if account.sodId is None \
            or ((sod := self._db.findSodTrack(account.sodId)) and sod is None) \
            or not self._is_account_pa_attested(account, sod):
            self._log.error("Account PA attestation not valid, uid=%s", account.uid)
            raise peAccountNotAttested

    def _verify_challenge(self, uid: UserId, cid: CID, aaPubKey: AAPublicKey, csigs: List[bytes], aaSigAlgo: SignatureAlgorithm = None ) -> None:
        """
        Check if signature is correct and the time frame is OK
        :raises `peChallengeExpired`: If challenge stored in db by cid has already expired
        :raises `peChallengeVerificationFailed`: If verification of challenge signature fails.
        :raises `peMissingParamAASigAlgo`: If aaPubKey is ec public key and no sigAlgo is provided
        :raises `seChallengeNotFound`: If challenge is not found.
        :raises `StorageAPIError`: On any storage related errors.
        """
        try:
            self._log.debug("Verifying challenge cid=%s", cid)
            if aaPubKey.isEcKey() and aaSigAlgo is None:
                raise peMissingParamAASigAlgo

            # Verify if challenge has expired expiration time
            c, cct = self._db.getChallenge(cid, uid)
            if self._has_challenge_expired(cct, utils.time_now()):
                self._db.deleteChallenge(cid)
                raise peChallengeExpired

            # Verify challenge signatures
            ccs = [c[0:8], c[8:16], c[16:24], c[24:32]]
            if csigs is None or len(csigs) != len(ccs):
                self._log.error("The size of csigs list doesn't match the size of ccs list")
                raise peChallengeVerificationFailed
            for idx, sig in enumerate(csigs):
                if not aaPubKey.verifySignature(ccs[idx], sig, aaSigAlgo):
                    self._log.error("Signature verification failed for challenge chunk at idx=%s", idx)
                    raise peChallengeVerificationFailed
            self._log.success("Challenge signed with eMRTD was successfully verified!")
        except PeInvalidOrMissingParam:
            raise
        except PeChallengeExpired:
            raise
        except PeSigVerifyFailed:
            raise
        except Exception as e:
            self._log.error("Challenge verification failed!")
            self._log.error("  e=%s", e)
            raise

    def _save_crl_url_from_cert(self, country: CountryCode, cert: Certificate):
        assert isinstance(country, CountryCode)
        assert isinstance(cert, Certificate)
        for crlDistribution in cert.crl_distribution_points:
            for crlUrl in crlDistribution['distribution_point'].native:
                self._db.addPkiDistributionUrl(
                    database.PkiDistributionUrl(country, database.PkiDistributionUrl.Type.CRL, crlUrl))

    def _get_challenge_expiration(self, createTime: datetime) -> datetime:
        """
        Calculates challenge expiration time from the time when challenge was created.
        :param createTime: The challenge create time.
        """
        createTime = createTime.replace(tzinfo=None)
        return createTime + timedelta(seconds=self.cttl)

    def _has_challenge_expired(self, expireTime: datetime, date: datetime) -> bool: # pylint: disable=no-self-use
        """
        Verifies if challenge create time is already in the range of challenge expiration interval.
        :param expireTime: The challenge expiration time.
        :param datetime: The date and time to compare expiration against. (Should be current datetime)
        """
        expireTime = expireTime.replace(tzinfo=None)
        date       = date.replace(tzinfo=None)
        return utils.has_expired(expireTime, date)

    def _verify_sod_contains_hash_of(self, sod: ef.SOD, dg: ef.DataGroup) -> None:
        """
        Verifies that EF.SOD contains hash of `dg` file.
        :param sod: The EF.SOD.
        :param dg: The EF.DG file to verify.
        :raises peInvalidDgFile: If `sod` doesn't contain hash for `dg` or
                                 the hash of `dg` is different than hash stored in `sod`.
        """
        assert isinstance(sod, ef.SOD)
        assert isinstance(dg, ef.DataGroup)
        self._log.debug("Verifying %s contains matching hash of file %s", sod, dg)

        if self._log.getEffectiveLevel() <= log.VERBOSE: # verbose log
            sod_dghv = sod.ldsSecurityObject.dgHashes.find(dg.number)
            self._log.verbose("EF.SOD contains hash of %s file: %s", dg.number.native, (sod_dghv is not None))
            if sod_dghv is not None:
                hash_algo = sod.ldsSecurityObject.dgHashAlgo['algorithm'].native
                self._log.verbose("%s hash value of file %s in EF.SOD: %s", hash_algo, dg.number.native, sod_dghv.hash.hex())
                h = sod.ldsSecurityObject.getDgHasher()
                h.update(dg.dump())
                self._log.verbose("Actual %s hash value of file %s: %s", hash_algo, dg.number.native, h.finalize().hex())

        # Validation of dg hash value in EF.SOD
        if not sod.ldsSecurityObject.contains(dg):
            self._log.error("EF.SOD doesn't contain hash of file %s", dg)
            raise peInvalidDgFile(dg.number)
        self._log.debug("File %s is valid!", dg)

    def _get_account_expiration(self, uid: UserId, account: Optional[database.AccountStorage], sod: database.SodTrack, dsc: database.DscStorage) -> Optional[datetime]: #pylint: disable=no-self-use,unused-argument,useless-return
        """
        Returns datetime till account attestation can be valid. Should be less or equal to `dsc.notValidAfter`.
        `None` is returned by default aka attestation valid until attestation has valid passive auth trustchain
        :param `uid`: The account user ID.
        :param `sod`: The account attested EF.SOD track.
        :param `dsc`: The account attested DSC certificate storage.
        """
        assert isinstance(uid, UserId)
        assert isinstance(account, (database.AccountStorage, type(None)))
        assert isinstance(sod, database.SodTrack)
        assert isinstance(dsc, database.DscStorage)
        assert sod.dscId == dsc.id
        if account is not None and account.expires is not None and \
            not utils.has_expired(account.expires, utils.time_now()):
            return account.expires
        return None
