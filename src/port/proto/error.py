from pymrtd import ef
from typing import Final

class ProtoError(Exception):
    """ General protocol exception """
    code = 400

class PeUnauthorized(ProtoError):
    code = 401

class PeSigVerifyFailed(PeUnauthorized):
    """ Challenge signature verification error """

class PeForbbidden(ProtoError):
    """ Forbbiden actions, elements e.g. blacklisted elements """
    code = 403

class PeNotFound(ProtoError):
    """ Non existing elements error (e.g.: account doesn't exist, CSCA can't be found etc...) """
    code = 404

class PeConflict(ProtoError):
    """ User account error """
    code = 409

class PePreconditionFailed(ProtoError):
    """
    One or more condition in verification of eMRTD PKI trustchain failed.
    Or when verifying EF.SOD contains specific DG e.g.: DG1
    """
    code = 412

class PeInvalidOrMissingParam(ProtoError):
    """ Invalid or missing required protocol parameter. """
    code = 422

class PePreconditionRequired(ProtoError):
    """
    Required preconditions.
    e.g.: EF.DG15 file has ECC public key and EF.DG14 is missing AAInfo
    """
    code = 428

class PeChallengeExpired(ProtoError):
    """ Challenge has expired """
    code = 498

class PeAttestationExpired(ProtoError):
    """ Challenge has expired """
    code = 498

peAccountAlreadyRegistered: Final         = PeConflict("Account already registered")
peAccountNotAttested: Final               = PeUnauthorized("Account is not attested")
peAttestationExpired: Final               = PeAttestationExpired("Account attestation has expired")
peChallengeExpired: Final                 = PeChallengeExpired("Challenge has expired")
peChallengeVerificationFailed: Final      = PeSigVerifyFailed("Challenge signature verification failed")
peCountryCodeMismatch: Final              = PeConflict("Country code mismatch")
peCscaExists: Final                       = PeConflict("CSCA certificate already exists")
peCscaNotFound: Final                     = PeNotFound("CSCA certificate not found")
peCscaSelfIssued: Final                   = PeNotFound("No CSCA link was found for self-issued CSCA")
peCscaTooNewOrExpired: Final              = PeInvalidOrMissingParam("CSCA certificate is too new or has expired")
peCrlOld: Final                           = PeInvalidOrMissingParam("Old CRL")
peCrlTooNew: Final                        = PeInvalidOrMissingParam("Can't add future CRL")
peDscCantIssuePassport: Final             = PeInvalidOrMissingParam("DSC certificate can't issue biometric passport")
peDscExists: Final                        = PeConflict("DSC certificate already exists")
peDscNotFound: Final                      = PeNotFound("DSC certificate not found")
peDscTooNewOrExpired: Final               = PeInvalidOrMissingParam("DSC certificate is too new or has expired")
peEfDg14MissingAAInfo: Final              = PePreconditionRequired("EF.DG14 file is missing ActiveAuthenticationInfo")
peEfDg14Required: Final                   = PeInvalidOrMissingParam("EF.DG14 file required")
peEfDg15Required: Final                   = PeInvalidOrMissingParam("EF.DG15 file required")
peEfSodNotAllowed: Final                  = PeForbbidden("EF.SOD file not allowed to be used in attestation")
peEfSodMatch: Final                       = PeConflict("Matching EF.SOD file already registered")
peEfSodNotGenuine: Final                  = PeUnauthorized("EF.SOD file not genuine")
peInvalidCsca: Final                      = PeInvalidOrMissingParam("Invalid CSCA certificate")
peInvalidCrl: Final                       = PeInvalidOrMissingParam("Invalid CRL file")
peInvalidDsc: Final                       = PeInvalidOrMissingParam("Invalid DSC certificate")
peInvalidEfSod: Final                     = PeInvalidOrMissingParam("Invalid EF.SOD file")
peMissingParamAASigAlgo: Final            = PeInvalidOrMissingParam("Missing param aaSigAlgo")
peTrustchainCheckFailedExpiredCert: Final = PePreconditionFailed("Expired certificate in the trustchain")
peTrustchainCheckFailedNoCsca: Final      = PePreconditionFailed("Missing issuer CSCA certificate in the trustchain")
peTrustchainCheckFailedRevokedCert: Final = PePreconditionFailed("Revoked certificate in the trustchain")

def peInvalidDgFile(dgNumber: ef.dg.DataGroupNumber) -> PeInvalidOrMissingParam:
    return PeInvalidOrMissingParam(f'Invalid {dgNumber.native} file')
