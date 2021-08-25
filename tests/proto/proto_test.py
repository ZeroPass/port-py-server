#pylint: disable=line-too-long,protected-access,too-many-locals,too-many-statements
import copy
import json
import os
import py
import pytest
import random

from datetime import timedelta
from port.proto.proto import (
    peAccountAlreadyRegistered,
    peAccountNotAttested,
    peAttestationExpired,
    PeAttestationExpired,
    peChallengeExpired,
    PeChallengeExpired,
    peChallengeVerificationFailed,
    PeConflict,
    peCountryCodeMismatch,
    peCscaExists,
    peCscaNotFound,
    peCscaSelfIssued,
    peCscaTooNewOrExpired,
    peCrlOld,
    peCrlTooNew,
    peEfDg14Required,
    peDscCantIssuePassport,
    peDscExists,
    peDscNotFound,
    peDscTooNewOrExpired,
    peEfSodNotGenuine,
    peInvalidCsca,
    peInvalidCrl,
    peInvalidDsc,
    peInvalidEfSod,
    PeInvalidOrMissingParam,
    peEfSodMatch,
    peEfDg14MissingAAInfo,
    peMissingParamAASigAlgo,
    PeNotFound,
    PePreconditionFailed,
    PePreconditionRequired,
    PeSigVerifyFailed,
    peTrustchainCheckFailedExpiredCert,
    peTrustchainCheckFailedNoCsca,
    peTrustchainCheckFailedRevokedCert,
    PeUnauthorized,
    PortProto,
    ProtoError
)
from port.proto import CertificateId, Challenge, CountryCode, MemoryDB, SodId, UserId, utils
from port.database import CertificateRevocationInfo, DscStorage
from pymrtd import ef
from pymrtd.pki.x509 import CscaCertificate, DocumentSignerCertificate
from pymrtd.ef.dg import DataGroupNumber
from unittest import mock
from typing import List, Optional

_dir = os.path.dirname(os.path.realpath(__file__))
TV_DIR    = py.path.local(_dir) /'..'/'tv'
CERTS_DIR = TV_DIR / 'certs'
LDS_DIR   = TV_DIR / 'lds'

def alter_sod(sod: ef.SOD):
     # copy and set don't work so replace the raw hash of DG1
    s = ef.SOD.load(sod.dump() \
        .replace(sod.ldsSecurityObject.dgHashes.find(ef.dg.DataGroupNumber(1)).hash,\
             bytes.fromhex('BADEF50D00000000FF6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CD')))
    return s

def alter_dg15(dg15: ef.DG15):
    # alter last byte
    raw = bytearray(dg15.dump())
    raw[-1] = raw[-1] ^ 0xFF
    s = ef.DG15.load(bytes(raw))
    return s

def alter_csigs(idx: int, csigs: List[bytes]):
    acsigs = copy.deepcopy(csigs)
    sig    = bytearray(acsigs[idx])
    sig[random.randint(0, len(sig) - 1)] ^= 0xFF
    acsigs[idx] = bytes(sig)
    return acsigs

def check_ds_eq_dsc(ds: DscStorage, dsc: DocumentSignerCertificate, cscaId: CertificateId):
    assert ds is not None
    assert ds.id             == CertificateId.fromCertificate(dsc)
    assert ds.country        == CountryCode(dsc.issuerCountry)
    assert ds.serialNumber   == dsc.serial_number
    assert ds.notValidBefore == dsc.notValidBefore
    assert ds.notValidAfter  == dsc.notValidAfter
    assert ds.issuerId       == cscaId
    assert ds.issuer         == dsc.issuer.human_friendly
    assert ds.authorityKey   == dsc.authorityKey
    assert ds.subject        == dsc.subject.human_friendly
    assert ds.subjectKey     == dsc.subjectKey
    assert ds.certificate    == dsc.dump()
    assert ds.getCertificate().dump() == dsc.dump()
    assert ds.isValidOn(dsc.notValidBefore + timedelta(seconds=1) )
    assert ds.isValidOn(utils.time_now())
    assert ds.isValidOn(dsc.notValidAfter - timedelta(seconds=1))
    assert ds.isSelfIssued() == False

def test_proto_errors():
    # Test PE exception classes
    pe = ProtoError()
    assert pe.code == 400

    peua = PeUnauthorized()
    assert peua.code == 401
    assert issubclass(PeUnauthorized, ProtoError)

    pesvf = PeSigVerifyFailed()
    assert pesvf.code == 401
    assert issubclass(PeSigVerifyFailed, PeUnauthorized)

    penf = PeNotFound()
    assert penf.code == 404
    assert issubclass(PeNotFound, ProtoError)

    pec = PeConflict()
    assert pec.code == 409
    assert issubclass(PeConflict, ProtoError)

    pepf = PePreconditionFailed()
    assert pepf.code == 412
    assert issubclass(PePreconditionFailed, ProtoError)

    peiomp = PeInvalidOrMissingParam()
    assert peiomp.code == 422
    assert issubclass(PeInvalidOrMissingParam, ProtoError)

    pepr = PePreconditionRequired()
    assert pepr.code == 428
    assert issubclass(PePreconditionRequired, ProtoError)

    pece = PeChallengeExpired()
    assert pece.code == 498
    assert issubclass(PeChallengeExpired, ProtoError)

    peae = PeAttestationExpired()
    assert peae.code == 498
    assert issubclass(PeAttestationExpired, ProtoError)

    # Test predefined exception objects
    assert isinstance(peAccountAlreadyRegistered, PeConflict)
    assert str(peAccountAlreadyRegistered) == "Account already registered"

    assert isinstance(peAttestationExpired, PeAttestationExpired)
    assert str(peAttestationExpired) == "Account attestation has expired"

    assert isinstance(peAccountNotAttested, PeUnauthorized)
    assert str(peAccountNotAttested) == "Account is not attested"

    assert isinstance(peChallengeExpired, PeChallengeExpired)
    assert str(peChallengeExpired) == "Challenge has expired"

    assert isinstance(peChallengeVerificationFailed, PeSigVerifyFailed)
    assert str(peChallengeVerificationFailed) == "Challenge signature verification failed"

    assert isinstance(peCountryCodeMismatch, PeConflict)
    assert str(peCountryCodeMismatch) == "Country code mismatch"

    assert isinstance(peCscaExists, PeConflict)
    assert str(peCscaExists) == "CSCA certificate already exists"

    assert isinstance(peCscaNotFound, ProtoError)
    assert str(peCscaNotFound) == "CSCA certificate not found"

    assert isinstance(peCscaSelfIssued, PeNotFound)
    assert str(peCscaSelfIssued) == "No CSCA link was found for self-issued CSCA"

    assert isinstance(peCscaTooNewOrExpired, ProtoError)
    assert str(peCscaTooNewOrExpired) == "CSCA certificate is too new or has expired"

    assert isinstance(peCrlOld, PeInvalidOrMissingParam)
    assert str(peCrlOld) == "Old CRL"

    assert isinstance(peCrlTooNew, PeInvalidOrMissingParam)
    assert str(peCrlTooNew) == "Can't add future CRL"

    assert isinstance(peEfDg14Required, PeInvalidOrMissingParam)
    assert str(peEfDg14Required) == "EF.DG14 file required"

    assert isinstance(peDscCantIssuePassport, PeInvalidOrMissingParam)
    assert str(peDscCantIssuePassport) == "DSC certificate can't issue biometric passport"

    assert isinstance(peDscExists, PeConflict)
    assert str(peDscExists) == "DSC certificate already exists"

    assert isinstance(peDscNotFound, PeNotFound)
    assert str(peDscNotFound) == "DSC certificate not found"

    assert isinstance(peDscTooNewOrExpired, ProtoError)
    assert str(peDscTooNewOrExpired) == "DSC certificate is too new or has expired"

    assert isinstance(peEfSodNotGenuine, PeUnauthorized)
    assert str(peEfSodNotGenuine) == "EF.SOD file not genuine"

    assert isinstance(peInvalidCsca, PeInvalidOrMissingParam)
    assert str(peInvalidCsca) == "Invalid CSCA certificate"

    assert isinstance(peInvalidCrl, PeInvalidOrMissingParam)
    assert str(peInvalidCrl) == "Invalid CRL file"

    assert isinstance(peInvalidDsc, PeInvalidOrMissingParam)
    assert str(peInvalidDsc) == "Invalid DSC certificate"

    assert isinstance(peInvalidEfSod, PeInvalidOrMissingParam)
    assert str(peInvalidEfSod) == "Invalid EF.SOD file"

    assert isinstance(peEfSodMatch, PeConflict)
    assert str(peEfSodMatch) == "Matching EF.SOD file already registered"

    assert isinstance(peEfDg14MissingAAInfo, PePreconditionRequired)
    assert str(peEfDg14MissingAAInfo) == "EF.DG14 file is missing ActiveAuthenticationInfo"

    assert isinstance(peMissingParamAASigAlgo, PeInvalidOrMissingParam)
    assert str(peMissingParamAASigAlgo) == "Missing param aaSigAlgo"

    assert isinstance(peTrustchainCheckFailedExpiredCert, PePreconditionFailed)
    assert str(peTrustchainCheckFailedExpiredCert) == "Expired certificate in the trustchain"

    assert isinstance(peTrustchainCheckFailedNoCsca, PePreconditionFailed)
    assert str(peTrustchainCheckFailedNoCsca) == "Missing issuer CSCA certificate in the trustchain"

    assert isinstance(peTrustchainCheckFailedRevokedCert, PePreconditionFailed)
    assert str(peTrustchainCheckFailedRevokedCert) == "Revoked certificate in the trustchain"

def verify_sod_is_genuine_test(sod: ef.SOD, csca: CscaCertificate, dsc: DocumentSignerCertificate):
    """
    Tests EF.SOD object
    :param sod: The sod object to test.
    :param csca: The `sod` issuing CSCA.
    :param dsc: The DSC certificate which is inserted into DB when SOD is being verified by PortProto._verify_sod_is_genuine
    """
    db = MemoryDB()
    proto = PortProto(db, cttl = 0)

    # Missing CSCA
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidBefore + timedelta(seconds=1)):
        with pytest.raises(PeNotFound, match="CSCA certificate not found"):
            proto._verify_sod_is_genuine(sod)

    # Add CSCA to the DB
    db.addCsca(csca)

    # DSC is not valid yet
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidBefore - timedelta(seconds=1)):
        with pytest.raises(ProtoError, match="DSC certificate is too new or has expired"):
            proto._verify_sod_is_genuine(sod)

    # DSC is expired
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidAfter + timedelta(seconds=1)):
        with pytest.raises(ProtoError, match="DSC certificate is too new or has expired"):
            proto._verify_sod_is_genuine(sod)

    # Now do tests when DSC is valid at present time
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidBefore + timedelta(seconds=1)):
        # Test verifying SOD fails when CSCA is revoked
        with pytest.raises(PePreconditionFailed, match="Revoked certificate in the trustchain"):
            cscaCri = CertificateRevocationInfo(CountryCode(csca.issuerCountry), csca.serial_number, utils.time_now(), crlId = None)
            db.revokeCertificate(cscaCri)
            try:
                proto._verify_sod_is_genuine(sod)
            except Exception as e:
                db.unrevokeCertificate(cscaCri)
                raise e

        # Test verifying SOD fails when DSC is revoked
        with pytest.raises(PePreconditionFailed, match="Revoked certificate in the trustchain"):
            dscCri = CertificateRevocationInfo(CountryCode(sod.dscCertificates[0].issuerCountry),
                 sod.dscCertificates[0].serial_number, utils.time_now(), crlId = None)
            db.revokeCertificate(dscCri)
            try:
                proto._verify_sod_is_genuine(sod)
            except Exception as e:
                db.unrevokeCertificate(dscCri)
                raise e

        # Test EF.SOD verification succeeds
        dscStorage = proto._verify_sod_is_genuine(sod)
        assert dscStorage is not None

        # Test DSC is in the database
        ds = db.findDscBySubjectKey(dsc.subjectKey)
        assert ds            is not None
        assert ds.id         == CertificateId.fromCertificate(dsc)
        assert dsc.dump()    == ds.getCertificate().dump()
        assert dscStorage.id == ds.id
        check_ds_eq_dsc(ds, dsc, CertificateId.fromCertificate(csca))

         # Performe another check, now with DSC in DB
        dscStorage = proto._verify_sod_is_genuine(sod)
        assert dscStorage is not None
        assert dscStorage.id == ds.id

        # Test altering SOD content results in error
        with pytest.raises(PeUnauthorized, match="EF.SOD file not genuine"):
            proto._verify_sod_is_genuine(alter_sod(sod))

        # Test verifying SOD fails when CSCA is revoked
        with pytest.raises(PePreconditionFailed, match="Revoked certificate in the trustchain"):
            cscaCri = CertificateRevocationInfo(CountryCode(csca.issuerCountry), csca.serial_number, utils.time_now(), crlId = None)
            db.revokeCertificate(cscaCri)
            proto._verify_sod_is_genuine(sod)

        # Test verifying SOD fails when DSC is revoked
        with pytest.raises(PePreconditionFailed, match="Revoked certificate in the trustchain"):
            dscCri = CertificateRevocationInfo(CountryCode(sod.dscCertificates[0].issuerCountry),
                 sod.dscCertificates[0].serial_number, utils.time_now(), crlId = None)
            db.revokeCertificate(dscCri)
            proto._verify_sod_is_genuine(sod)

@pytest.mark.datafiles(
    CERTS_DIR / 'csca_de_0130846f22c2.der',
    CERTS_DIR / 'dsc_de_0130846f2b3e.cer',
    LDS_DIR   / 'ef.sod_de_9712AB14.bin',

    CERTS_DIR / 'dsc_de_0142fd5cf927.cer',

    CERTS_DIR / 'csca_si_448831f1.cer',
    CERTS_DIR / 'dsc_si_448833b8.cer',
    LDS_DIR   / 'ef.sod_si_454CB206.bin'
)
def test_verify_sod_is_genuine(datafiles):
    # Test vector taken from https://www.etsi.org/
    # https://www.etsi.org/deliver/etsi_tr/103200_103299/103200/01.01.01_60/tr_103200v010101p.pdf
    # https://docbox.etsi.org/MTS/MTS/05-CONTRIBUTIONS/2011/MTS(11)0044_DMIMTS-00127_ePassport_Prototype_Platform.zip
    with open(datafiles / 'ef.sod_de_9712AB14.bin', "rb") as sod:
        sod = ef.SOD.load(sod.read())
    with open(datafiles / 'csca_de_0130846f22c2.der', "rb") as csca:
        csca:CscaCertificate = CscaCertificate.load(csca.read())
    with open(datafiles / 'dsc_de_0130846f2b3e.cer', "rb") as dsc:
        dsc: DocumentSignerCertificate = DocumentSignerCertificate.load(dsc.read())
    verify_sod_is_genuine_test(sod, csca, dsc)

    # Test vector taken from Slovenian passport
    with open(datafiles / 'ef.sod_si_454CB206.bin', "rb") as sod:
        sod = ef.SOD.load(sod.read())
    with open(datafiles / 'csca_si_448831f1.cer', "rb") as csca:
        csca:CscaCertificate = CscaCertificate.load(csca.read())
    with open(datafiles / 'dsc_si_448833b8.cer', "rb") as dsc:
        dsc: DocumentSignerCertificate = DocumentSignerCertificate.load(dsc.read())
    verify_sod_is_genuine_test(sod, csca, dsc)

    # Test vector taken from German BSI TR-03105-5 ReferenceDataSet
    # https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03105/BSI_TR-03105-5_ReferenceDataSet_zip.html
    # EF_SOD.bin
    # Note, this tv is missing CSCA certificate so not ful test is performed
    db = MemoryDB()
    proto = PortProto(db, cttl = 0)
    tv_sod = bytes.fromhex('7782078A3082078606092A864886F70D010702A082077730820773020103310F300D060960864801650304020105003081E90606678108010101A081DE0481DB3081D8020100300D060960864801650304020105003081C3302502010104204170CA879FCE6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CDBF42B630250201020420A9A1B09DFD598087AB3FCE4AE2EC65B1A1525BD258BFC27DF4419F8A65E5474530250201030420403E4D17C26EBC832411898161D8FD5D99C58EE865CB3759B529AA782C7EDE00302502010E0420CF5004FFCCD64E1A8BD3A42FD53814EC3D4481640BE1906D0ECFEB016EF6A6AE302502010404204C7A0F0DDAA473123834F1B0713ED9453D1D1D58BCE447FB1736D40A0761C17BA08204653082046130820295A00302010202060142FD5CF927304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A50205042204353301E170D3133313231363231343331385A170D3134313231313231343331385A3054310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731183016060355040B0C0F446F63756D656E74205369676E65723112301006035504030C09484A5020504220445330820122300D06092A864886F70D01010105000382010F003082010A02820101009E7CBB065377041232915A044DD3ADC2199AD4C14BC8E58C24A899DBD62A984EEAE2A0006C1D53439246A67A9964D759BC7B9426CE6C4C078363306CF66645F12F39D950FE2C04100E6FF53C310B52F74CD1ED89931496F376D384AB604A570129445F015FCC3595E161B7C591CB5206BC16477D8CDEC09480DBF6262696F62970DA0978807DBA330EE777BF54D471AE1EB257090F1379E198A2D1503344847347BE46764FA00C4E93BACD32143B2E04C6C369CECE7943FD414521849533F9CDB985E42767F1DD792E7EFED3651E3C75DF868FA2101DF45CD5D3D955B23A88DD30A752F4FB9F4E84B518E0CA0F8F2BACE65D61F98115A0EA88DD3A3416017CA30203010001A3523050301F0603551D230418301680141E4D57560C12902366A8FDE11408A37F70EB7D65301D0603551D0E04160414831C30BE878FDF57273010E5B38950E576F7B08A300E0603551D0F0101FF040403020780304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012003820181002984DC43028839BB24786A4C9C9C37E76368FF6264707970E5B00F7934840904ED90E34B018D5D634D7536E49AFE7B0E872F5D093E6D11BF31C910686A9106F9F773F59C57AEFF983DE6335B5CB403E0FF7D3055F09948878F8BE1BC184F2A03C82C14097FC19DEDDCCF61A2EAE6F8BF1A64BE4C0253CE0BC35AD41E10D6FF08C1EE872349E8D02A722F48144CAB665D0FADF9DB3B36BFB2B15AE4A3B13DC4CF64133B599CDB3AF8A365AC6228096899FEA8D56A24F90DA72B3E95B97FD82C4B8EF9CBB499C3D9F09053A5FDDD51E94A13A004530D74F7DD1B0C88163F9BFA098923DC81D247D75E33CAC3C7E27AEAC627B99AB18E6B03D38260E2DCCFA1D638D17614773BC13EBA0D53E2E3E9A202E0742C25DF471072CDA2A88BA2B25648970BC31132DE84F702ABBC98740B4FEE7C66CD149755A763B801DCF9DC1B52191A3ACC514244C51D297F35E5AEA328B8641B33D54DC7C50D2466F9DDDCE98A75F276D48D614B6C4FA675C2017824BED7CC27B46FCBE5B82CE4B433E34AAED2EBEE3182020630820202020101305D3053310B300906035504061302444531173015060355040A0C0E484A5020436F6E73756C74696E6731173015060355040B0C0E436F756E747279205369676E65723112301006035504030C09484A5020504220435302060142FD5CF927300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B46A0D05E280F398EFEEEBFF67E78C736ADD15E75670B1AD4C6C534E8187B9D6304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A20302012004820100761106E9FBD2ED1B2F75027DAF13975A4C7ADFC54D675D2DD2BBA762BC073D9288AF4B1B87BA7987D53FA1D321D1943F58573F4913424E2BCDD080C2D8927A985BE2BDCAF6B8FE21EC99D8227F052ED118B7EAE6029F57889CA723912076916355068EBBCF46F19C3FBB49DCF1E9F3B10DF11E270FAC11BC6D1E3C5ADF68E0E46381A45F737E91EE9F889DB6D418AA2C6C3213C47FBC2787F0134384B343CC921A9A03878EBA79BA00901115495942C3E7B0E4DA09E0916C172228AD28D9DBEC915F32E58D7431480443030C2C3D1DEF840223FED41A92C5B30AA2CE9ED346CBB8BB172A2EFF73E0B8CFEC89071A07DC62627421F808DA541A58A1A572E7583F')
    sod = ef.SOD.load(tv_sod)

    # Missing CSCA
    with mock.patch('port.proto.utils.time_now', return_value=sod.dscCertificates[0].notValidBefore + timedelta(seconds=1)):
        with pytest.raises(PeNotFound, match="CSCA certificate not found"):
            proto._verify_sod_is_genuine(sod)

def _test_register_attestation(dg15: ef.DG15, dg14: Optional[ef.DG14], sod: ef.SOD, dsc: DocumentSignerCertificate, csca: CscaCertificate, aaSigs: dict):
    assert isinstance(dg15, ef.DG15)
    assert isinstance(dg14, (ef.DG14, type(None)))
    assert isinstance(sod, ef.SOD)
    assert isinstance(dsc, DocumentSignerCertificate)
    assert isinstance(csca, CscaCertificate)
    db    = MemoryDB()
    proto = PortProto(db, cttl = 0)
    uid   = UserId(os.urandom(UserId.max_size))
    sodId = SodId.fromSOD(sod)
    dscId = CertificateId.fromCertificate(dsc)
    c     = Challenge.fromhex(aaSigs['challenge'])
    cid   = c.id
    csigs = [bytes.fromhex(sig) for sig in aaSigs['csigs']]

    # Test registration fails when EF.FG15 is altered
    with pytest.raises(ProtoError, match="Invalid EF.DG15 file"):
        proto.register(uid, sod, alter_dg15(dg15), cid, csigs, dg14, allowSodOverride=False)

    assert db.findAccount(uid) is None
    assert db.findSodTrack(sodId) is None
    assert db.findDsc(dscId) is None

    # Test registration fails when CSCA is not present
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidBefore + timedelta(seconds=1)):
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=30))
        with pytest.raises(ProtoError, match="CSCA certificate not found"):
            proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)
        assert db.findAccount(uid) is None
        assert db.findSodTrack(sodId) is None
        assert db.findDsc(dscId) is None

    # Add CSCA to DB
    db.addCsca(csca)

    # Test registration fails when CSCA is not valid yet
    with mock.patch('port.proto.utils.time_now', return_value=csca.notValidBefore - timedelta(seconds=1)):
        db.deleteChallenge(cid)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=30))
        with pytest.raises(ProtoError, match="DSC certificate is too new or has expired"):
            proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)
        assert db.findAccount(uid) is None
        assert db.findSodTrack(sodId) is None
        assert db.findDsc(dscId) is None

    # Test registration fails when CSCA is expired
    with mock.patch('port.proto.utils.time_now', return_value=csca.notValidAfter + timedelta(seconds=1)):
        db.deleteChallenge(cid)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=30))
        with pytest.raises(ProtoError, match="DSC certificate is too new or has expired"):
            proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)

        assert db.findAccount(uid) is None
        assert db.findSodTrack(sodId) is None
        assert db.findDsc(dscId) is None

    # Test registration fails when CSCA is revoked
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidBefore + timedelta(seconds=1)):
        db.deleteChallenge(cid)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=30))
        cscaCri = CertificateRevocationInfo(CountryCode(csca.issuerCountry), csca.serial_number, utils.time_now(), crlId = None)
        db.revokeCertificate(cscaCri)
        with pytest.raises(PePreconditionFailed, match="Revoked certificate in the trustchain"):
            proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)
        db.unrevokeCertificate(cscaCri)

        assert db.findAccount(uid) is None
        assert db.findSodTrack(sodId) is None
        assert db.findDsc(dscId) is None

    # Test registration fails when DSC is not valid yet
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidAfter + timedelta(seconds=1)):
        db.deleteChallenge(cid)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=30))
        with pytest.raises(ProtoError, match="DSC certificate is too new or has expired"):
            proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)
        assert db.findAccount(uid) is None
        assert db.findSodTrack(sodId) is None
        assert db.findDsc(dscId) is None

    # Test registration fails when DSC has expired
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidAfter + timedelta(seconds=1)):
        db.deleteChallenge(cid)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=30))
        with pytest.raises(ProtoError, match="DSC certificate is too new or has expired"):
            proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)
        assert db.findAccount(uid) is None
        assert db.findSodTrack(sodId) is None
        assert db.findDsc(dscId) is None

    # Test registration fails when DSC is revoked
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidBefore + timedelta(seconds=1)):
        db.deleteChallenge(cid)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=30))
        dscCri = CertificateRevocationInfo(CountryCode(dsc.issuerCountry), dsc.serial_number, utils.time_now(), crlId = None)
        db.revokeCertificate(dscCri)
        with pytest.raises(PePreconditionFailed, match="Revoked certificate in the trustchain"):
            proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)
        db.unrevokeCertificate(dscCri)

        assert db.findAccount(uid) is None
        assert db.findSodTrack(sodId) is None
        assert db.findDsc(dscId) is None

    # Test registration fails when EF.SOD is not genuine
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidBefore + timedelta(seconds=1)):
        db.deleteChallenge(cid)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=30))
        with pytest.raises(PeUnauthorized, match="EF.SOD file not genuine"):
            proto.register(uid, alter_sod(sod), dg15, cid, csigs, dg14, allowSodOverride=False)
        assert db.findAccount(uid) is None
        assert db.findSodTrack(sodId) is None

        ds = db.findDsc(dscId)
        assert ds is not None
        check_ds_eq_dsc(ds, dsc, CertificateId.fromCertificate(csca))
        db.deleteDsc(dscId)

    # Test registration fails when csigs is empty
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidBefore + timedelta(seconds=1)):
        db.deleteChallenge(cid)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=30))
        with pytest.raises(PeSigVerifyFailed, match="Challenge signature verification failed"):
            proto.register(uid, sod, dg15, cid, [], dg14, allowSodOverride=False)
        assert db.findAccount(uid) is None
        assert db.findSodTrack(sodId) is None

        ds = db.findDsc(dscId)
        assert ds is not None
        check_ds_eq_dsc(ds, dsc, CertificateId.fromCertificate(csca))
        db.deleteDsc(dscId)

    # Test registration fails when csigs is None
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidBefore + timedelta(seconds=1)):
        db.deleteChallenge(cid)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=30))
        with pytest.raises(PeSigVerifyFailed, match="Challenge signature verification failed"):
            proto.register(uid, sod, dg15, cid, None, dg14, allowSodOverride=False)
        assert db.findAccount(uid) is None
        assert db.findSodTrack(sodId) is None

        ds = db.findDsc(dscId)
        assert ds is not None
        check_ds_eq_dsc(ds, dsc, CertificateId.fromCertificate(csca))
        db.deleteDsc(dscId)

    # Test registration fails when csigs are shuffled
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidBefore + timedelta(seconds=1)):
        db.deleteChallenge(cid)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=30))
        with pytest.raises(PeSigVerifyFailed, match="Challenge signature verification failed"):
            csigsShuffled = copy.deepcopy(csigs)
            random.Random(1).shuffle(csigsShuffled) # 1st element
            proto.register(uid, sod, dg15, cid, csigsShuffled, dg14, allowSodOverride=False)
        with pytest.raises(PeSigVerifyFailed, match="Challenge signature verification failed"):
            random.Random(2).shuffle(csigsShuffled) # 2nd element
            proto.register(uid, sod, dg15, cid, csigsShuffled, dg14, allowSodOverride=False)
        with pytest.raises(PeSigVerifyFailed, match="Challenge signature verification failed"):
            random.Random(8).shuffle(csigsShuffled) # 3rd element
            proto.register(uid, sod, dg15, cid, csigsShuffled, dg14, allowSodOverride=False)

        assert db.findAccount(uid) is None
        assert db.findSodTrack(sodId) is None

        ds = db.findDsc(dscId)
        assert ds is not None
        check_ds_eq_dsc(ds, dsc, CertificateId.fromCertificate(csca))
        db.deleteDsc(dscId)

    # Test registration fails when csigs are altered
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidBefore + timedelta(seconds=1)):
        db.deleteChallenge(cid)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=30))
        for i in range(0, len(csigs)):
            with pytest.raises(PeSigVerifyFailed, match="Challenge signature verification failed"):
                proto.register(uid, sod, dg15, cid, alter_csigs(i, csigs), dg14, allowSodOverride=False)
        assert db.findAccount(uid) is None
        assert db.findSodTrack(sodId) is None

        ds = db.findDsc(dscId)
        assert ds is not None
        check_ds_eq_dsc(ds, dsc, CertificateId.fromCertificate(csca))
        db.deleteDsc(dscId)

    # Test registration succeeds
    with mock.patch('port.proto.utils.time_now', return_value=dsc.notValidBefore + timedelta(seconds=1)):
        db.deleteChallenge(cid)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=30))

        assert db.findAccount(uid) is None
        assert db.findSodTrack(sodId) is None
        assert db.findDsc(dscId) is None
        proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)

        # Check new DSC certificate was inserted into DB
        ds = db.findDsc(dscId)
        check_ds_eq_dsc(ds, dsc, CertificateId.fromCertificate(csca))

        # Check new account is registered
        accnt = db.getAccount(uid)
        accnt = db.findAccount(uid)
        assert accnt is not None
        assert accnt.uid     == uid
        assert accnt.country == ds.country
        assert accnt.sodId   == sodId
        assert accnt.expires is None
        assert accnt.aaPublicKey == dg15.aaPublicKey.dump()
        assert accnt.aaSigAlgo is None if dg14 is None else accnt.aaSigAlgo == dg14.aaSignatureAlgo.dump()
        assert accnt.aaCount == 1
        assert accnt.dg1 is None
        assert accnt.dg2 is None

        # Check new EF.SOD was inserted is registered
        st = db.findSodTrack(sodId)
        assert st is not None
        assert st.id       == sodId
        assert st.dscId    == dscId
        assert st.hashAlgo == sod.ldsSecurityObject.dgHashAlgo['algorithm'].native

        dg1Hash = sod.ldsSecurityObject.find(DataGroupNumber(1))
        dg1Hash = dg1Hash.hash if dg1Hash is not None else None
        assert st.dg1Hash  == dg1Hash

        dg2Hash = sod.ldsSecurityObject.find(DataGroupNumber(2))
        dg2Hash = dg2Hash.hash if dg2Hash is not None else None
        assert st.dg2Hash  == dg2Hash

        dg3Hash = sod.ldsSecurityObject.find(DataGroupNumber(3))
        dg3Hash = dg3Hash.hash if dg3Hash is not None else None
        assert st.dg3Hash  == dg3Hash

        dg4Hash = sod.ldsSecurityObject.find(DataGroupNumber(4))
        dg4Hash = dg4Hash.hash if dg4Hash is not None else None
        assert st.dg4Hash  == dg4Hash

        dg5Hash = sod.ldsSecurityObject.find(DataGroupNumber(5))
        dg5Hash = dg5Hash.hash if dg5Hash is not None else None
        assert st.dg5Hash  == dg5Hash

        dg6Hash = sod.ldsSecurityObject.find(DataGroupNumber(6))
        dg6Hash = dg6Hash.hash if dg6Hash is not None else None
        assert st.dg6Hash  == dg6Hash

        dg7Hash = sod.ldsSecurityObject.find(DataGroupNumber(7))
        dg7Hash = dg7Hash.hash if dg7Hash is not None else None
        assert st.dg7Hash  == dg7Hash

        dg8Hash = sod.ldsSecurityObject.find(DataGroupNumber(8))
        dg8Hash = dg8Hash.hash if dg8Hash is not None else None
        assert st.dg8Hash  == dg8Hash

        dg9Hash = sod.ldsSecurityObject.find(DataGroupNumber(9))
        dg9Hash = dg9Hash.hash if dg9Hash is not None else None
        assert st.dg9Hash  == dg9Hash

        dg10Hash = sod.ldsSecurityObject.find(DataGroupNumber(10))
        dg10Hash = dg10Hash.hash if dg10Hash is not None else None
        assert st.dg10Hash  == dg10Hash

        dg11Hash = sod.ldsSecurityObject.find(DataGroupNumber(11))
        dg11Hash = dg11Hash.hash if dg11Hash is not None else None
        assert st.dg11Hash  == dg11Hash

        dg12Hash = sod.ldsSecurityObject.find(DataGroupNumber(12))
        dg12Hash = dg12Hash.hash if dg12Hash is not None else None
        assert st.dg12Hash  == dg12Hash

        dg13Hash = sod.ldsSecurityObject.find(DataGroupNumber(13))
        dg13Hash = dg13Hash.hash if dg13Hash is not None else None
        assert st.dg13Hash  == dg13Hash

        dg14Hash = sod.ldsSecurityObject.find(DataGroupNumber(14))
        dg14Hash = dg14Hash.hash if dg14Hash is not None else None
        assert st.dg14Hash  == dg14Hash

        dg15Hash = sod.ldsSecurityObject.find(DataGroupNumber(15))
        dg15Hash = dg15Hash.hash if dg15Hash is not None else None
        assert st.dg15Hash  == dg15Hash

        dg16Hash = sod.ldsSecurityObject.find(DataGroupNumber(16))
        dg16Hash = dg16Hash.hash if dg16Hash is not None else None
        assert st.dg16Hash  == dg16Hash

        # Check account has valid attestation
        assert proto._is_account_attested(accnt)
        assert proto._is_account_attested(accnt, st)

        # Test trying to register existing user fails
        with pytest.raises(PeConflict, match="Account already registered"):
            proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)

        # Set account expiration to DSC expiration and
        # test that trying to register existing user fails
        accnt.expires = dsc.notValidAfter
        db.updateAccount(accnt)
        with pytest.raises(PeConflict, match="Account already registered"):
            proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)

        # Expire account and test that re-register with new EF.SOD succeeds
        accnt = db.getAccount(uid)
        accnt.expires = utils.time_now() - timedelta(seconds=1)
        db.updateAccount(accnt)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=60))
        proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)
        accnt = db.getAccount(uid)
        assert accnt is not None
        assert accnt.uid     == uid
        assert accnt.country == ds.country
        assert accnt.sodId   == sodId
        assert accnt.expires is None
        assert accnt.aaPublicKey == dg15.aaPublicKey.dump()
        assert accnt.aaSigAlgo is None if dg14 is None else accnt.aaSigAlgo == dg14.aaSignatureAlgo.dump()
        assert accnt.aaCount == 1
        assert accnt.dg1 is None
        assert accnt.dg2 is None

        # Test that re-register with allowSodOverride=True param succeeds
        accnt = db.getAccount(uid)
        accnt.expires = dsc.notValidAfter
        db.updateAccount(accnt)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=60))
        proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=True)
        accnt = db.getAccount(uid)
        assert accnt is not None
        assert accnt.uid     == uid
        assert accnt.country == ds.country
        assert accnt.sodId   == sodId
        assert accnt.expires is not None
        assert accnt.expires == dsc.notValidAfter
        assert accnt.aaPublicKey == dg15.aaPublicKey.dump()
        assert accnt.aaSigAlgo is None if dg14 is None else accnt.aaSigAlgo == dg14.aaSignatureAlgo.dump()
        assert accnt.aaCount == 1
        assert accnt.dg1 is None
        assert accnt.dg2 is None

        # Test re-register fails when expired account tries to register EF.SOD with different country
        accnt = db.getAccount(uid)
        accnt.country = CountryCode('YZ') # unassigned alpha-2 cc
        accnt.expires = utils.time_now() - timedelta(seconds=1)
        db.updateAccount(accnt)
        db.addChallenge(uid, c, utils.time_now() + timedelta(seconds=60))
        with pytest.raises(PeConflict, match="Country code mismatch"):
            proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)

        # Test re-register fails when account tries to register EF.SOD with different country
        accnt = db.getAccount(uid)
        accnt.country = CountryCode('YZ') # unassigned alpha-2 cc
        accnt.expires = dsc.notValidAfter
        db.updateAccount(accnt)
        with pytest.raises(PeConflict, match="Country code mismatch"):
            proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=True)

        # Test registered but not attested account can't register existing EF.SOD
        accnt = db.getAccount(uid)
        accnt.expires = dsc.notValidAfter
        accnt.country = ds.country
        accnt.sodId = None
        db.updateAccount(accnt)
        with pytest.raises(PeConflict, match="Matching EF.SOD file already registered"):
            proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)

        # Test registered but not attested account can't register matching EF.SOD
        db.deleteSodTrack(st.id)
        st.id = SodId(-1)
        db.addSodTrack(st)
        with pytest.raises(PeConflict, match="Matching EF.SOD file already registered"):
            proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)

        # Test registered but not attested account can't register EF.SOD
        # which matches existing but invalid SodTrack
        db.deleteSodTrack(st.id)
        st.id    = SodId(-1)
        st.dscId = None
        db.addSodTrack(st)
        accnt.sodId = None
        db.updateAccount(accnt)
        with pytest.raises(PeConflict, match="Matching EF.SOD file already registered"):
            proto.register(uid, sod, dg15, cid, csigs, dg14, allowSodOverride=False)

        #TODO: Add tests for DatabaseAPI and DB errors
        #TODO: Add tests for EF.DG1 & EF.DG2 files being transferred to the re-registered account
        #      when new EF.SOD contains old DG hashes

@pytest.mark.datafiles(
    CERTS_DIR / 'csca_si_448831f1.cer',
    CERTS_DIR / 'dsc_si_448833b8.cer',
    LDS_DIR   / 'ef.sod_si_454CB206.bin',
    LDS_DIR   / 'ef.dg15_ef.sod_si_454CB206.bin',

    TV_DIR / 'aa_sigs.json'

)
@pytest.mark.depends(on=[
    'test_verify_sod_is_genuine',
])
def test_register(datafiles):
    # Test vector taken from Slovenian passport
    with open(datafiles / 'aa_sigs.json', "rb") as aa_sigs:
        aa_sigs = json.loads(aa_sigs.read())
    with open(datafiles / 'ef.dg15_ef.sod_si_454CB206.bin', "rb") as dg15:
        dg15 = ef.DG15.load(dg15.read())
    with open(datafiles / 'ef.sod_si_454CB206.bin', "rb") as sod:
        sod = ef.SOD.load(sod.read())
    with open(datafiles / 'csca_si_448831f1.cer', "rb") as csca:
        csca:CscaCertificate = CscaCertificate.load(csca.read())
    with open(datafiles / 'dsc_si_448833b8.cer', "rb") as dsc:
        dsc: DocumentSignerCertificate = DocumentSignerCertificate.load(dsc.read())
    _test_register_attestation(dg15, None, sod, dsc, csca, aa_sigs['ef.dg15_ef.sod_si_454CB206'])
