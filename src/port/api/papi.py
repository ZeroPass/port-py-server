from base64 import b64decode, b64encode
from collections import defaultdict
from enum import IntFlag

from port.proto import UserId
from pymrtd.ef.dg import DataGroupNumber
from pymrtd.pki import x509

from port.proto.proto import PeInvalidOrMissingParam

from .base import JsonRpcApi, portapi
from .utils import SUCCESS, try_deserialize

class AttestationFlag(IntFlag):
    NotAttested   = 0
    PassiveAuthn  = 1 # Account has valid passive authentication. i.e.: valid path EF.SOD track => DSC => CSCA
    ActiveAuthn   = 2 # Account has genuine passport chip attestation. i.e.: data for performing passive authn was not cloned.

class PortPrivateApi(JsonRpcApi):
    """
    Port private JSON-RPC API.
    """
    __name__ = 'papi'

# RPC API methods
    # API: port.get_account
    @portapi
    def get_account(self, uid: str) -> dict:
        """
        Returns account data and attestation information for account under `uid`.
        :param `uid`: Base64 encoded UserId.
        :return `dict`:
                `attestation`: The attestation level which denotes what type of account attestation(s) was performed. See `AttestationFlag`.
                               Note:

                                    - If flags `PassiveAuthn` and `ActiveAuthn` are set, the account should be treated as fully attested and trusted.

                                    - If only flag `PassiveAuthn` is set, the account should be treated as not fully attested and semi-trusted (the passport data might be cloned).

                                    - If flag `PassiveAuthn` is not set, `NotAttested` will always be assigned.

                `country`:  The country which issued account's attestation passport.
                `expires`:  The date when the account attestation expires.
                `aa_count`: Optional, if `ActiveAuthentication` flag is set, this field has assigned the number of active authns performed by the account.

                `ef`:       Optional, dictionary of data group hashes and files. The value of "hash" dictionary consist of pair `hash_algo : hash_value` as dictionary.
                            If EF.DG1 file is present than the value of returned "file"  dictionary is MRZ in JSON format.
                            IF EF.DG2 is present than the value of returned "file" dictionary is binary EF.DG2 encoded in Base64 format.
                              e.g.:
                                {
                                  "ef" : {
                                    "dg1" : {
                                      "hash" : { "sha256", "ABC00975....11FF0099"},
                                      "file" : { <MRZ dictionary>}
                                    },
                                    "dg2" : {
                                      "hash" : { "sha256", "ABC00975....11FF0099"}
                                    },
                                    "dg14" : {
                                      "hash" : { "sha256", "ABC00975....11FF0099"}
                                    }
                                  }
                                }
        """
        uid = try_deserialize(lambda: UserId.fromBase64(uid))
        accnt, sod, expires, attested = self._proto.getAttestationInfo(uid)

        attestation = AttestationFlag.NotAttested
        if attested:
            attestation |= AttestationFlag.PassiveAuthn
            if accnt.aaCount > 0:
                attestation |= AttestationFlag.ActiveAuthn

        aai = defaultdict(lambda: defaultdict(dict))
        aai |= {
            "attestation" : attestation.value,
            "country"     : accnt.country,
            "expires"     : expires
        }

        # Add fields aa_count and DG1 & DG2 files
        if AttestationFlag.PassiveAuthn in attestation:
            aai |= { "aa_count" : accnt.aaCount }
        if accnt.dg1 is not None:
            aai['ef']['dg1']['file'] = accnt.getDG1().mrz.toJson()
        if accnt.dg2 is not None:
            aai['ef']['dg2']['file'] = b64encode(accnt.dg2)

        # Add dg hashes
        for i in range(1, 17):
            dghash = sod.dgHash(DataGroupNumber(i))
            if dghash is not None:
                aai['ef'][f'dg{i}']['hash'] = { sod.hashAlgo : dghash.hex() }

        return aai

    # API: port.upload_certificate
    @portapi
    def upload_certificate(self, cert: str, allow_self_issued_csca: bool = False):
        """
        Uploads new CSCA or DSC certificate into DB.
        :param `cert`: Base64 encoded CSCA or DSC certificate.
        :param `allow_self_issued_csca`: If True self-signed CSCA certificates will be also accepted.
        :return `str`: "success"
        """
        cert  = try_deserialize(lambda: x509.Certificate.load(b64decode(cert)))
        ku = cert.key_usage_value.native
        if cert.ca:
            cert.__class__ = x509.CscaCertificate
            self._proto.addCscaCertificate(cert, allowSelfIssued=allow_self_issued_csca)
        elif 'digital_signature' in ku and 'key_cert_sign' not in ku:
            cert.__class__ = x509.DocumentSignerCertificate
            self._proto.addDscCertificate(cert)
        else:
            raise PeInvalidOrMissingParam("Unknown certificate type")
        return SUCCESS
