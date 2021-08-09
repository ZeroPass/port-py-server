
from typing import cast
import asn1crypto.core as asn1

from . import cms #pylint: disable=relative-beyond-top-level
from .x509 import CscaCertificate, MasterListSignerCertificate #pylint: disable=relative-beyond-top-level
from .oids import id_icao_cscaMasterList #pylint: disable=relative-beyond-top-level


class CertList(asn1.SetOf):
    _child_spec = CscaCertificate

class CscaList(asn1.Sequence):
    _fields = [
        ('version', asn1.Integer),
        ('certList', CertList)
    ]

    @property
    def version(self) -> int:
        return super().__getitem__('version').native

    def __len__(self):
        return len(self._get_list())

    def __getitem__(self, key):
        return self._get_list().__getitem__(key)

    def __iter__(self):
        return self._get_list().__iter__()

    def _get_list(self) -> CertList:
        return super().__getitem__('certList')



class MlSignedData(cms.MrtdSignedData):
    _certificate_spec = MasterListSignerCertificate
    cms.cms_register_encap_content_info_type(
        'icaoCscaMasterList',
        id_icao_cscaMasterList,
        CscaList
    )


class MlContentInfo(cms.MrtdContentInfo):
    _signed_data_spec = MlSignedData


class CscaMasterListError(Exception):
    pass


class CscaMasterList(MlContentInfo):

    @classmethod
    def load(cls, encoded_bytes, strict=False) -> "CscaMasterList":
        ci = cast(cls, super().load(encoded_bytes, strict=strict))
        ctype = ci['content_type'].native
        if ctype != 'signed_data': # ICAO 9303-12-p25
            raise CscaMasterListError("Invalid master list content type: {}, should be 'signed_data'".format(ctype))

        #pylint: disable=protected-access

        cver = ci.signedData.version.native
        if cver != 'v3': # ICAO 9303-12-p25
            raise CscaMasterListError("Invalid SignedData version: {}, should be 'v3'".format(cver))

        if ci.signedData.contentType.dotted != id_icao_cscaMasterList:
            raise CscaMasterListError("Invalid encapContentInfo type: {}, should be '{}'".format(ci.signedData.contentType.dotted, id_icao_cscaMasterList))

        if ci.signedData.content.version != 0: # ICAO 9303-12-p27
            raise CscaMasterListError("Unsupported encapContentInfo version: {}, should be 0".format(ci.signedData.version))

        if len(ci.signedData.certificates) < 1:
            raise CscaMasterListError("No master list signer certificate found")

        assert isinstance(ci.signedData.certificates[0], MasterListSignerCertificate)
        assert isinstance(ci.signedData.content, CscaList)
        return ci

    @property
    def signedData(self) -> MlSignedData:
        return self['content']

    @property
    def signerCertificates(self) -> Optional[List[Certificate]]:
        ''' Returns list of Master List Signer certificates if present, otherwise None. '''
        return self.signedData.certificates

    @property
    def cscaList(self) -> CscaList:
        ''' Returns list of CSCAs '''
        return self.signedData.content

    def verify(self, si: cms.SignerInfo, issuerCert: Certificate) -> None:
        '''
        Verifies every SignerInfo object and the digital signature over content.
        On verification failure a CscaMasterListError exception is risen.
        '''
        try:
            self.signedData.verify(si, issuerCert)
        except cms.MrtdSignedDataError as e:
            raise CscaMasterListError(e) from e
