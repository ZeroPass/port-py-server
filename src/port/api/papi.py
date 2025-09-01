from base64 import b64decode, b64encode
from collections import defaultdict
from enum import IntFlag

from port.proto import PeInvalidOrMissingParam, UserId
from pymrtd.ef.dg import DataGroupNumber
from pymrtd.pki import x509
from pymrtd.pki.crl import CertificateRevocationList

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

                `aa`: (Optional) if `PassiveAuthentication` and `ActiveAuthentication` flag is set, this field has assigned a dictionary with fields:

                     - `count`: the number of successfull active authns performed by the account.

                     - `last_authn`: the date of the last successful active authn.
                     e.g.:

                       {
                         "aa": {
                           "count":2,
                           "last_authn":"2021-09-13T10:58:44.294755"
                         }
                       }

                `ef`: (Optional) If `PassiveAuthentication` is set, a dictionary of data group hashes and files.
                       The value of "hash" dictionary consist of pair `hash_algo : hash_value` as dictionary.
                       If EF.DG1 file is present than the value of returned "file"  dictionary is MRZ in JSON format.
                       If EF.DG2 is present than the value of returned "file" dictionary is the DG2 text content.
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

                Example of returned data:
                   {
                      "attestation":3, // Passive | Active
                      "country":"SI",
                      "expires":"2021-09-16T10:58:44.294755",
                      "aa": {
                        "count":2,
                        "last_authn":"2021-09-13T10:58:44.294755"
                      },
                      "ef":{
                        "dg1":{
                          "hash":{"sha256":"0a0aa521cc643c0269e2c71205e3fe50c43ff9e6980f5bc745898c1a0795cea0"}
                        },
                        "dg2":{
                          "hash":{"sha256":"1b1b7bcf824157e20b7060956bed9e9a34d9699926000c7f2019120a0f6295b1"}
                        },
                        "dg3":{
                          "hash":{"sha256":"2c2c7bd08f74b698fcb2948e27f98fc1ee04eac21ef1187a284a4f726090bac2"}
                        },
                        "dg14":{
                          "hash":{"sha256":"3d3dee0a12eff3464d2a25f20808ed60c1773d45f815c5c371afd366639bd8d3"}
                        },
                        "dg15":{
                          "hash":{"sha256":"4e3e4dab9996890e32b20ed93b91a654618ca18aa330cd9828f2c1b20f2aede4"}
                        }
                      }
                    }
        """
        uid = try_deserialize(lambda: UserId.fromBase64(uid), self._log)
        accnt, sod, expires, pa_attested = self._proto.getAttestationInfo(uid)

        attestation = AttestationFlag.NotAttested
        if pa_attested:
            attestation |= AttestationFlag.PassiveAuthn
            if accnt.aaCount > 0:
                attestation |= AttestationFlag.ActiveAuthn

        aai = defaultdict(lambda: defaultdict(dict))
        aai |= {
            "attestation" : attestation.value,
            "country"     : accnt.country,
            "expires"     : expires
        }

        if AttestationFlag.PassiveAuthn in attestation:
            # Add fields aa_count
            if AttestationFlag.ActiveAuthn in attestation:
                aai['aa'] = {
                  "count" : accnt.aaCount,
                  "last_authn" : accnt.aaLastAuthn
                }

            # Add DG1 & DG2 files
            if accnt.dg1 is not None:
                aai['ef']['dg1']['file'] = accnt.getDG1().mrz.toJson()
            if accnt.dg2 is not None:
                aai['ef']['dg2']['file'] = accnt.dg2.hex()

            # Add dg hashes
            for i in range(1, 17):
                dghash = sod.dgHash(DataGroupNumber(i))
                if dghash is not None:
                    aai['ef'][f'dg{i}']['hash'] = {
                        'algorithm': sod.hashAlgo,
                        'value' : dghash.hex()
                    }
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
        cert  = try_deserialize(lambda: x509.Certificate.load(b64decode(cert)), self._log)
        ku = cert.key_usage_value.native
        if cert.ca:
            cert = x509.CscaCertificate.load(cert.dump())
            self._proto.addCscaCertificate(cert, allowSelfIssued=allow_self_issued_csca)
        elif 'digital_signature' in ku and 'key_cert_sign' not in ku:
            cert = x509.DocumentSignerCertificate.load(cert.dump())
            self._proto.addDscCertificate(cert)
        else:
            raise PeInvalidOrMissingParam("Unknown certificate type")
        return SUCCESS

    # API: port.upload_crl
    @portapi
    def upload_crl(self, crl: str):
        """
        Adds new or updates existing country CRL in DB.
        :param `crl`: Base64 encoded CRL.
        :return `str`: "success"
        """
        crl  = try_deserialize(lambda: CertificateRevocationList.load(b64decode(crl)), self._log)
        self._proto.updateCRL(crl)
        return SUCCESS
