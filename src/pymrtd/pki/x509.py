from asn1crypto import x509
from cert_utils import verify_cert_sig

class CertificateVerificationError(Exception):
    pass

class Certificate(x509.Certificate):
    def verify(self, issuing_cert: x509.Certificate):
        """
        Verifies certificate has all required fields and that issuing certificate did issue this certificate.
        On failure CertificateVerificationError exception is risen.
        """

        self._verifiy_cert_fields()
        self._verifiy_tbs_cert_fields()

        if not verify_cert_sig(self, issuing_cert):
            raise CertificateVerificationError("Signature verification failed")

    def _require(cond, message: str):
        if not cond:
            raise CertificateVerificationError(message)

    def _require_cert_field(self, field: str):
        Certificate._require(field in self, 
            "Missing required certificate field '{}'".format(field)
         )

    def _verifiy_cert_fields(self):
        self._require_cert_field('tbs_certificate')
        self._require_cert_field('signature_algorithm')
        self._require_cert_field('signature_value')

    def _require_tbs_cert_field(self, field: str):
        Certificate._require(field in self['tbs_certificate'], 
            "Missing required tbs certificate field '{}'".format(field)
         )

    def _verifiy_tbs_cert_fields(self):
        self._require_tbs_cert_field('extensions')
        self._require_tbs_cert_field('issuer')
        self._require_tbs_cert_field('serial_number')
        self._require_tbs_cert_field('signature')
        self._require_tbs_cert_field('subject')
        self._require_tbs_cert_field('subject_public_key_info')
        self._require_tbs_cert_field('validity')
        self._require_tbs_cert_field('version')

    def _require_extension_field(self, field: str):
        exts = self['tbs_certificate']['extensions']
        for e in exts:
            if field in e['extn_id'].native:
                return
        Certificate._require(False, 
            "Missing required extension field '{}'".format(field)
         )




class CscaCertificate(Certificate):
    def verify(self):
        self.verify(self)

    def verify(self, issuing_cert: x509.Certificate):
        super().verify(issuing_cert)

        super()._require_extension_field('basic_constraints')
        Certificate._require(self.ca, "Country signing certificate must be CA")
        #Certificate._require( self.max_path_length is None or 0 <= self.max_path_length <= 1, #Note: Portuguese cross-link CSCA has value 2
        #                "Invalid CSCA path length constraint: {}".format(self.max_path_length)
        #)

        super()._require_extension_field('key_identifier')

        super()._require_extension_field('key_usage')
        key_usage = self.key_usage_value.native
        Certificate._require(
            'key_cert_sign' in key_usage or 'digital_signature' in key_usage, # Note:  'digital_signature' usually should not be present (icao 9303-p12 page 17)
            "Missing field 'keyCertSign' in KeyUsage"
        )
        Certificate._require('crl_sign' in key_usage, "Missing field 'cRLSign' in KeyUsage")