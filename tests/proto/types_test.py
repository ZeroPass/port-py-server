# pylint: disable=too-many-statements
import os
import py
import pytest
import string

from cryptography.hazmat.primitives.hashes import SHA512_256
from datetime import datetime
from port.proto.types import (
    CID,
    CertificateId,
    Challenge,
    ChallengeError,
    CountryCode,
    CrlId,
    FunctionHook,
    hook,
    IIntegerId,
    SodId,
    UserId,
    UserIdError
)
from port.proto.utils import int_to_bytes
from pymrtd import ef
from pymrtd.pki import  x509
from pymrtd.pki.crl import CertificateRevocationList
from re import escape
from typing import Any, Optional

_dir = os.path.dirname(os.path.realpath(__file__))
TV_DIR    = py.path.local(_dir) /'..'/'tv'
CERTS_DIR = TV_DIR / 'certs'
LDS_DIR   = TV_DIR / 'lds'

# CountryCode tests
# Note, whis test will depend on tests for proto.utils.format_alpha2 when they are finished.
def test_CountryCode():
    def _test_2_letters_for_alphabet(alphabet):
        assert len(alphabet) > 0
        for cl in alphabet:
            for cr in alphabet:
                v = cl+cr
                assert CountryCode(v) == v.upper()

    _test_2_letters_for_alphabet(string.ascii_lowercase)
    _test_2_letters_for_alphabet(string.ascii_uppercase)

    # Fuzz tests
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: '):
        CountryCode('')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: a'):
        CountryCode('a')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: b'):
        CountryCode('b')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: y'):
        CountryCode('y')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: z'):
        CountryCode('z')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: A'):
        CountryCode('A')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: B'):
        CountryCode('B')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: Y'):
        CountryCode('Y')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: Z'):
        CountryCode('Z')

    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 1'):
        CountryCode('1')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 2'):
        CountryCode('2')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 3'):
        CountryCode('3')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 4'):
        CountryCode('4')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 5'):
        CountryCode('5')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 6'):
        CountryCode('6')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 7'):
        CountryCode('7')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 8'):
        CountryCode('8')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 9'):
        CountryCode('9')

    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 0a'):
        CountryCode('0a')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 1b'):
        CountryCode('1b')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 2c'):
        CountryCode('2c')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 3y'):
        CountryCode('3y')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 4z'):
        CountryCode('4z')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 5A'):
        CountryCode('5A')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 6B'):
        CountryCode('6B')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 7C'):
        CountryCode('7C')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 8Y'):
        CountryCode('8Y')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 9Z'):
        CountryCode('9Z')

    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: a0'):
        CountryCode('a0')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: a1'):
        CountryCode('a1')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: a2'):
        CountryCode('a2')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: a3'):
        CountryCode('a3')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: a4'):
        CountryCode('a4')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: B5'):
        CountryCode('B5')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: B6'):
        CountryCode('B6')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: B7'):
        CountryCode('B7')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: B8'):
        CountryCode('B8')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: B9'):
        CountryCode('B9')

    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 10'):
        CountryCode('10')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 21'):
        CountryCode('21')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 32'):
        CountryCode('32')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 43'):
        CountryCode('43')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 54'):
        CountryCode('54')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 65'):
        CountryCode('65')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 76'):
        CountryCode('76')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 87'):
        CountryCode('87')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: 98'):
        CountryCode('98')

    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: aba'):
        CountryCode('aba')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: avb'):
        CountryCode('avb')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: azc'):
        CountryCode('azc')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: auy'):
        CountryCode('auy')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: aez'):
        CountryCode('aez')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: BNA'):
        CountryCode('BNA')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: BLB'):
        CountryCode('BLB')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: BJC'):
        CountryCode('BJC')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: BOY'):
        CountryCode('BOY')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: BIZ'):
        CountryCode('BIZ')

    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: a0a'):
        CountryCode('a0a')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: a1b'):
        CountryCode('a1b')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: a2c'):
        CountryCode('a2c')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: a3y'):
        CountryCode('a3y')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: a4z'):
        CountryCode('a4z')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: B5A'):
        CountryCode('B5A')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: B6B'):
        CountryCode('B6B')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: B7C'):
        CountryCode('B7C')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: B8Y'):
        CountryCode('B8Y')
    with pytest.raises(ValueError, match='Invalid ISO-3166 Alpha-2 country code: B9Z'):
        CountryCode('B9Z')

# IIntegerId and derivate classes tests
def _test_ser_IIntegerId_type(iid, intValue,  strId, hexId, bytesId):
    assert iid                          == intValue
    assert iid                          == iid.__class__(intValue)
    assert iid.hex()                    == hexId
    assert str(iid)                     == strId
    assert iid.toBytes()                == bytesId
    assert iid.__class__.fromHex(hexId) == intValue
    assert iid.__class__.fromHex(hexId) == iid.__class__(intValue)
    assert iid.__class__(hexId, 16)     == intValue
    assert iid.__class__(hexId, 16)     == iid.__class__(intValue)
    assert iid.__class__(strId)         == intValue
    assert iid.__class__(strId)         == iid.__class__(intValue)

def test_IIntegerId():
    class TestId(IIntegerId):
        min = -2147483648
        max = 2147483647

    assert issubclass(TestId, IIntegerId)
    assert isinstance(TestId(0), TestId)
    assert TestId.byteSize()  == 4
    assert TestId.min         == -2147483648
    assert TestId.max         == 2147483647
    assert TestId(0).min      == TestId.min
    assert TestId(0).max      == TestId.max
    assert TestId(TestId.min) == TestId.min
    assert TestId(TestId.max) == TestId.max

    _test_ser_IIntegerId_type(TestId(0), 0, '0', '00000000', bytes.fromhex('00000000'))
    _test_ser_IIntegerId_type(TestId(1), 1, '1', '00000001', bytes.fromhex('00000001'))
    _test_ser_IIntegerId_type(TestId(-1), -1, '-1', 'FFFFFFFF', bytes.fromhex('FFFFFFFF'))
    _test_ser_IIntegerId_type(TestId(10), 10, '10', '0000000A', bytes.fromhex('0000000A'))
    _test_ser_IIntegerId_type(TestId(16), 16, '16', '00000010', bytes.fromhex('00000010'))
    _test_ser_IIntegerId_type(TestId(127), 127, '127', '0000007F', bytes.fromhex('0000007F'))
    _test_ser_IIntegerId_type(TestId(128), 128, '128', '00000080', bytes.fromhex('00000080'))
    _test_ser_IIntegerId_type(TestId(256), 256, '256', '00000100', bytes.fromhex('00000100'))
    _test_ser_IIntegerId_type(TestId(4096), 4096, '4096', '00001000', bytes.fromhex('00001000'))
    _test_ser_IIntegerId_type(TestId(65536), 65536, '65536', '00010000', bytes.fromhex('00010000'))
    _test_ser_IIntegerId_type(TestId(1048576), 1048576, '1048576', '00100000', bytes.fromhex('00100000'))
    _test_ser_IIntegerId_type(TestId(16777216), 16777216, '16777216', '01000000', bytes.fromhex('01000000'))
    _test_ser_IIntegerId_type(TestId(268435456), 268435456, '268435456', '10000000', bytes.fromhex('10000000'))
    _test_ser_IIntegerId_type(TestId(-0x80000000), TestId.min, '-2147483648', '80000000', bytes.fromhex('80000000'))
    _test_ser_IIntegerId_type(TestId(-67440388), -67440388, '-67440388', 'FBFAF0FC', bytes.fromhex('FBFAF0FC'))
    _test_ser_IIntegerId_type(TestId(0x3FFFFFFF), 1073741823, '1073741823', '3FFFFFFF', bytes.fromhex('3FFFFFFF'))
    _test_ser_IIntegerId_type(TestId(0x7FFFFFFF), TestId.max, '2147483647', '7FFFFFFF', bytes.fromhex('7FFFFFFF'))

    # Fuzz tests
    with pytest.raises(ValueError, match='integer out of range to construct TestId. id_value=-2147483649'):
        TestId(TestId.min - 1)

    with pytest.raises(ValueError, match='integer out of range to construct TestId. id_value=2147483648'):
        TestId(TestId.max + 1)

    with pytest.raises(ValueError, match='invalid byte array size to construct TestId'):
        TestId(bytes.fromhex(''))
    with pytest.raises(ValueError, match='invalid byte array size to construct TestId'):
        TestId(bytes.fromhex('00'))
    with pytest.raises(ValueError, match='invalid byte array size to construct TestId'):
        TestId(bytes.fromhex('01'))
    with pytest.raises(ValueError, match='invalid byte array size to construct TestId'):
        TestId(bytes.fromhex('0000'))
    with pytest.raises(ValueError, match='invalid byte array size to construct TestId'):
        TestId(bytes.fromhex('0001'))
    with pytest.raises(ValueError, match='invalid byte array size to construct TestId'):
        TestId(bytes.fromhex('000000'))
    with pytest.raises(ValueError, match='invalid byte array size to construct TestId'):
        TestId(bytes.fromhex('000001'))
    with pytest.raises(ValueError, match='invalid byte array size to construct TestId'):
        TestId(bytes.fromhex('0000000001'))
    with pytest.raises(ValueError, match='invalid byte array size to construct TestId'):
        TestId(bytes.fromhex('10'))
    with pytest.raises(ValueError, match='invalid byte array size to construct TestId'):
        TestId(bytes.fromhex('1000'))
    with pytest.raises(ValueError, match='invalid byte array size to construct TestId'):
        TestId(bytes.fromhex('100000'))
    with pytest.raises(ValueError, match='invalid byte array size to construct TestId'):
        TestId(bytes.fromhex('1000000000'))

    with pytest.raises(ValueError):
        TestId.fromHex('')
    with pytest.raises(ValueError, match=''):
        TestId('', 16)
    with pytest.raises(ValueError):
        TestId.fromHex('0')
    with pytest.raises(ValueError, match=''):
        TestId('0', 16)
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId.fromHex('00')
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId.fromHex('01')
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId.fromHex('0000')
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId('0000', 16)
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId.fromHex('0001')
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId('0001', 16)
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId.fromHex('000000')
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId('000000', 16)
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId.fromHex('000001')
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId('000001', 16)
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId.fromHex('0000000001')
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId('0000000001', 16)
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId('10', 16)
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId('1000', 16)
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId('100000', 16)
    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId('1000000000', 16)

    with pytest.raises(ValueError, match='invalid byte array size to construct TestId'):
        TestId(int_to_bytes(TestId.max + 1, signed=True))

    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId.fromHex(int_to_bytes(TestId.max + 1, signed=True).hex())

    with pytest.raises(ValueError, match='invalid hex string size to construct TestId'):
        TestId(int_to_bytes(TestId.max + 1, signed=True).hex(), 16)

    with pytest.raises(ValueError, match='integer out of range to construct TestId. id_value=2147483648'):
        TestId(str(TestId.max + 1), 10)

@pytest.mark.depends(on=['test_IIntegerId'])
def test_CID():
    assert issubclass(CID, IIntegerId)
    assert isinstance(CID(0), CID)
    assert CID.byteSize() == 4
    assert CID.min        == -2147483648
    assert CID.max        == 2147483647
    assert CID(0).min     == CID.min
    assert CID(0).max     == CID.max
    assert CID(CID.min)   == CID.min
    assert CID(CID.max)   == CID.max

    _test_ser_IIntegerId_type(CID(0), 0, '0', '00000000', bytes.fromhex('00000000'))
    _test_ser_IIntegerId_type(CID(1), 1, '1', '00000001', bytes.fromhex('00000001'))
    _test_ser_IIntegerId_type(CID(-1), -1, '-1', 'FFFFFFFF', bytes.fromhex('FFFFFFFF'))
    _test_ser_IIntegerId_type(CID(-0x80000000), CID.min, '-2147483648', '80000000', bytes.fromhex('80000000'))
    _test_ser_IIntegerId_type(CID(0x3FFFFFFF), 1073741823, '1073741823', '3FFFFFFF', bytes.fromhex('3FFFFFFF'))
    _test_ser_IIntegerId_type(CID(0x7FFFFFFF), CID.max, '2147483647', '7FFFFFFF', bytes.fromhex('7FFFFFFF'))

    # Fuzz tests
    with pytest.raises(ValueError, match='integer out of range to construct CID. id_value=-2147483649'):
        CID(CID.min - 1)
    with pytest.raises(ValueError, match='integer out of range to construct CID. id_value=2147483648'):
        CID(CID.max + 1)

@pytest.mark.depends(on=['test_IIntegerId'])
@pytest.mark.datafiles(
    CERTS_DIR / 'csca_ca_4942cd00.cer',
    CERTS_DIR / 'csca_ch_7b.cer',
    CERTS_DIR / 'csca_de_1.cer',
    CERTS_DIR / 'csca_de_0130846f22c2.der',
    CERTS_DIR / 'csca_de_3e8.cer',
    CERTS_DIR / 'csca_es_3a94cc5fbc77641c5937d67b3832c5e4.cer',
    CERTS_DIR / 'csca_es_187cea1e2397dd6b4ffd64cbf777094c.cer',
    CERTS_DIR / 'csca_fr_1120da5f93b702be966f0005de4bb1aaf079.cer',
    CERTS_DIR / 'csca_it_12f2438f96f2ec10.cer',
    CERTS_DIR / 'csca_it_14e793ea55dcda2.cer',
    CERTS_DIR / 'csca_si_448831f1.cer',
    CERTS_DIR / 'csca_us_4e32d006.cer',
    CERTS_DIR / 'dsc_si_448833b8.cer',
    CERTS_DIR / 'dsc_de_0142fd5cf927.cer',
    CERTS_DIR / 'dsc_de_0130846f2b3e.cer',
    CERTS_DIR / 'lcsca_de_9d.cer', # issuer=csca_de_1.cer, ccsca=csca_de_3e8.cer
    CERTS_DIR / 'lcsca_es_672ef8b92d6ba81c59673b5c8dbcc2cc.cer', # issuer=csca_es_187cea1e2397dd6b4ffd64cbf777094c.cer, ccsca=csca_es_3a94cc5fbc77641c5937d67b3832c5e4.cer
    CERTS_DIR / 'lcsca_it_419cc9e4468248c.cer' # issuer=csca_it_12f2438f96f2ec10.cer, ccsca=csca_it_14e793ea55dcda2.cer
)
def test_certificateId(datafiles):
    assert issubclass(CertificateId, IIntegerId)
    assert isinstance(CertificateId(0), CertificateId)
    assert CertificateId.byteSize()         == 8
    assert CertificateId.min                == -9223372036854775808
    assert CertificateId.max                == 9223372036854775807
    assert CertificateId(0).min             == CertificateId.min
    assert CertificateId(0).max             == CertificateId.max
    assert CertificateId(CertificateId.min) == CertificateId.min
    assert CertificateId(CertificateId.max) == CertificateId.max

    _test_ser_IIntegerId_type(CertificateId(0), 0, '0', '0000000000000000', bytes.fromhex('0000000000000000'))
    _test_ser_IIntegerId_type(CertificateId(1), 1, '1', '0000000000000001', bytes.fromhex('0000000000000001'))
    _test_ser_IIntegerId_type(CertificateId(-1), -1, '-1', 'FFFFFFFFFFFFFFFF', bytes.fromhex('FFFFFFFFFFFFFFFF'))
    _test_ser_IIntegerId_type(CertificateId(0x7FFFFFFF), 2147483647, '2147483647', '000000007FFFFFFF', bytes.fromhex('000000007FFFFFFF'))
    _test_ser_IIntegerId_type(CertificateId(0x80000000), 2147483648, '2147483648', '0000000080000000', bytes.fromhex('0000000080000000'))
    _test_ser_IIntegerId_type(CertificateId(0xFFFFFFFF), 4294967295, '4294967295', '00000000FFFFFFFF', bytes.fromhex('00000000FFFFFFFF'))
    _test_ser_IIntegerId_type(CertificateId(0x0100000000), 4294967296, '4294967296', '0000000100000000', bytes.fromhex('0000000100000000'))
    _test_ser_IIntegerId_type(CertificateId(-0x8000000000000000), CertificateId.min, '-9223372036854775808', '8000000000000000', bytes.fromhex('8000000000000000'))
    _test_ser_IIntegerId_type(CertificateId(0x3FFFFFFFFFFFFFFF), 4611686018427387903, '4611686018427387903', '3FFFFFFFFFFFFFFF', bytes.fromhex('3FFFFFFFFFFFFFFF'))
    _test_ser_IIntegerId_type(CertificateId(0x7FFFFFFFFFFFFFFF), CertificateId.max, '9223372036854775807', '7FFFFFFFFFFFFFFF', bytes.fromhex('7FFFFFFFFFFFFFFF'))

    # test generating Certificate ID from certificates
    # Test vector CertificateIds were generated using script 'certid.sh' with 'OpenSSL 1.1.1k 25 Mar 2021'
    with open(datafiles / 'csca_ca_4942cd00.cer', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('985C2F03E618401F')

    with open(datafiles / 'csca_ch_7b.cer', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('1EB9E30AB20EA742')

    with open(datafiles / 'csca_de_1.cer', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('5AE2C4D33B1F9C33')

    with open(datafiles / 'csca_de_3e8.cer', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('3B532A61526346E2')

    with open(datafiles / 'csca_de_0130846f22c2.der', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('C8575F5A4D572AD4')

    with open(datafiles / 'csca_es_3a94cc5fbc77641c5937d67b3832c5e4.cer', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('DF3CBBA5056AC3F7')

    with open(datafiles / 'csca_es_187cea1e2397dd6b4ffd64cbf777094c.cer', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('5BF2BFD0539126BF')

    with open(datafiles / 'csca_fr_1120da5f93b702be966f0005de4bb1aaf079.cer', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('2F4085A53B5729D5')

    with open(datafiles / 'csca_it_12f2438f96f2ec10.cer', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('47B892BBE1918825')

    with open(datafiles / 'csca_it_14e793ea55dcda2.cer', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('9756E2FA4D4AF071')

    with open(datafiles / 'csca_si_448831f1.cer', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('89C80B37FB51C63A')

    with open(datafiles / 'csca_us_4e32d006.cer', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('2301F913EF6CCEF0')

    with open(datafiles / 'lcsca_de_9d.cer', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) != CertificateId.fromHex('3B532A61526346E2') #ccsca=csca_de_3e8.cer
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('95C3D6A4269A3A49')

    with open(datafiles / 'lcsca_es_672ef8b92d6ba81c59673b5c8dbcc2cc.cer', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) != CertificateId.fromHex('DF3CBBA5056AC3F7') #ccsca=csca_es_3a94cc5fbc77641c5937d67b3832c5e4.cer
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('AEB6C41C54C4F2B5')

    with open(datafiles / 'lcsca_it_419cc9e4468248c.cer', "rb") as csca:
        csca = x509.CscaCertificate.load(csca.read())
        assert CertificateId.fromCertificate(csca) != CertificateId.fromHex('9756E2FA4D4AF071') #ccsca=csca_it_14e793ea55dcda2.cer
        assert CertificateId.fromCertificate(csca) == CertificateId.fromHex('155A15EC01FC760C')

    with open(datafiles / 'dsc_de_0142fd5cf927.cer', "rb") as dsc:
        dsc = x509.DocumentSignerCertificate.load(dsc.read())
        assert CertificateId.fromCertificate(dsc) == CertificateId.fromHex('E0EFBBE4A702BFC8')

    with open(datafiles / 'dsc_de_0130846f2b3e.cer', "rb") as dsc:
        dsc = x509.DocumentSignerCertificate.load(dsc.read())
        assert CertificateId.fromCertificate(dsc) == CertificateId.fromHex('D96387343F322FA3')

    with open(datafiles / 'dsc_si_448833b8.cer', "rb") as dsc:
        dsc = x509.DocumentSignerCertificate.load(dsc.read())
        assert CertificateId.fromCertificate(dsc) == CertificateId.fromHex('C3B1790DFC181609')

    # Fuzz tests
    with pytest.raises(ValueError, match='integer out of range to construct CertificateId. id_value=-9223372036854775809'):
        CertificateId(CertificateId.min - 1)
    with pytest.raises(ValueError, match='integer out of range to construct CertificateId. id_value=9223372036854775808'):
        CertificateId(CertificateId.max + 1)

@pytest.mark.depends(on=['test_CountryCode', 'test_IIntegerId'])
@pytest.mark.datafiles(
    CERTS_DIR   / 'crl_ca_fp_277f80576b.crl',
    CERTS_DIR   / 'crl_cn_fp_3d2e24fd5f.crl',
    CERTS_DIR   / 'crl_cn_fp_814acc723b.crl',
    CERTS_DIR   / 'crl_cn_fp_7235893e75.crl',
    CERTS_DIR   / 'crl_de_fp_e421c6cf21.crl',
    CERTS_DIR   / 'crl_gb_fp_85824ab57b.crl',
    CERTS_DIR   / 'crl_us_fp_ec0ddb2ee9.crl',
)
def test_CrlId(datafiles):
    assert issubclass(CrlId, IIntegerId)
    assert isinstance(CrlId(0), CrlId)
    assert CrlId.byteSize() == 8
    assert CrlId.min        == -9223372036854775808
    assert CrlId.max        == 9223372036854775807
    assert CrlId(0).min     == CrlId.min
    assert CrlId(0).max     == CrlId.max
    assert CrlId(CrlId.min) == CrlId.min
    assert CrlId(CrlId.max) == CrlId.max

    _test_ser_IIntegerId_type(CrlId(0), 0, '0', '0000000000000000', bytes.fromhex('0000000000000000'))
    _test_ser_IIntegerId_type(CrlId(1), 1, '1', '0000000000000001', bytes.fromhex('0000000000000001'))
    _test_ser_IIntegerId_type(CrlId(-1), -1, '-1', 'FFFFFFFFFFFFFFFF', bytes.fromhex('FFFFFFFFFFFFFFFF'))
    _test_ser_IIntegerId_type(CrlId(0x7FFFFFFF), 2147483647, '2147483647', '000000007FFFFFFF', bytes.fromhex('000000007FFFFFFF'))
    _test_ser_IIntegerId_type(CrlId(0x80000000), 2147483648, '2147483648', '0000000080000000', bytes.fromhex('0000000080000000'))
    _test_ser_IIntegerId_type(CrlId(0xFFFFFFFF), 4294967295, '4294967295', '00000000FFFFFFFF', bytes.fromhex('00000000FFFFFFFF'))
    _test_ser_IIntegerId_type(CrlId(0x0100000000), 4294967296, '4294967296', '0000000100000000', bytes.fromhex('0000000100000000'))
    _test_ser_IIntegerId_type(CrlId(-0x8000000000000000), CrlId.min, '-9223372036854775808', '8000000000000000', bytes.fromhex('8000000000000000'))
    _test_ser_IIntegerId_type(CrlId(0x3FFFFFFFFFFFFFFF), 4611686018427387903, '4611686018427387903', '3FFFFFFFFFFFFFFF', bytes.fromhex('3FFFFFFFFFFFFFFF'))
    _test_ser_IIntegerId_type(CrlId(0x7FFFFFFFFFFFFFFF), CrlId.max, '9223372036854775807', '7FFFFFFFFFFFFFFF', bytes.fromhex('7FFFFFFFFFFFFFFF'))

    # Test generating CRL ID from CRL issuer
    with open(datafiles / 'crl_ca_fp_277f80576b.crl', "rb") as crl:
        crl:CertificateRevocationList = CertificateRevocationList.load(crl.read())
        assert CrlId.fromCountryCodeAndIssuer(CountryCode(crl.issuerCountry), crl.issuer.human_friendly) == CrlId.fromHex('6CB94C10DAC1FED4')
        assert CrlId.fromCrlIssuer(crl.issuer) == CrlId.fromHex('6CB94C10DAC1FED4')

    with open(datafiles / 'crl_cn_fp_3d2e24fd5f.crl', "rb") as crl:
        crl:CertificateRevocationList = CertificateRevocationList.load(crl.read())
        assert CrlId.fromCountryCodeAndIssuer(CountryCode(crl.issuerCountry), crl.issuer.human_friendly) == CrlId.fromHex('629A3A95AD835431')
        assert CrlId.fromCrlIssuer(crl.issuer) == CrlId.fromHex('629A3A95AD835431')

    with open(datafiles / 'crl_cn_fp_814acc723b.crl', "rb") as crl:
        crl:CertificateRevocationList = CertificateRevocationList.load(crl.read())
        assert CrlId.fromCountryCodeAndIssuer(CountryCode(crl.issuerCountry), crl.issuer.human_friendly) == CrlId.fromHex('E6353D94A8F54871')
        assert CrlId.fromCrlIssuer(crl.issuer) == CrlId.fromHex('E6353D94A8F54871')

    with open(datafiles / 'crl_cn_fp_7235893e75.crl', "rb") as crl:
        crl:CertificateRevocationList = CertificateRevocationList.load(crl.read())
        assert CrlId.fromCountryCodeAndIssuer(CountryCode(crl.issuerCountry), crl.issuer.human_friendly) == CrlId.fromHex('F0E0DE79AA60A798')
        assert CrlId.fromCrlIssuer(crl.issuer) == CrlId.fromHex('F0E0DE79AA60A798')

    with open(datafiles / 'crl_de_fp_e421c6cf21.crl', "rb") as crl:
        crl:CertificateRevocationList = CertificateRevocationList.load(crl.read())
        assert CrlId.fromCountryCodeAndIssuer(CountryCode(crl.issuerCountry), crl.issuer.human_friendly) == CrlId.fromHex('1AD769250B4C558B')
        assert CrlId.fromCrlIssuer(crl.issuer) == CrlId.fromHex('1AD769250B4C558B')

    with open(datafiles / 'crl_gb_fp_85824ab57b.crl', "rb") as crl:
        crl:CertificateRevocationList = CertificateRevocationList.load(crl.read())
        assert CrlId.fromCountryCodeAndIssuer(CountryCode(crl.issuerCountry), crl.issuer.human_friendly) == CrlId.fromHex('59A10A39A92CB93D')
        assert CrlId.fromCrlIssuer(crl.issuer) == CrlId.fromHex('59A10A39A92CB93D')

    with open(datafiles / 'crl_us_fp_ec0ddb2ee9.crl', "rb") as crl:
        crl:CertificateRevocationList = CertificateRevocationList.load(crl.read())
        assert CrlId.fromCountryCodeAndIssuer(CountryCode(crl.issuerCountry), crl.issuer.human_friendly) == CrlId.fromHex('29B792081E1ACC12')
        assert CrlId.fromCrlIssuer(crl.issuer) == CrlId.fromHex('29B792081E1ACC12')

    # Fuzz tests
    with pytest.raises(ValueError, match='integer out of range to construct CrlId. id_value=-9223372036854775809'):
        CrlId(CrlId.min - 1)
    with pytest.raises(ValueError, match='integer out of range to construct CrlId. id_value=9223372036854775808'):
        CrlId(CrlId.max + 1)

@pytest.mark.depends(on=['test_IIntegerId'])
@pytest.mark.datafiles(
    LDS_DIR   / 'ef.sod_de_9712AB14.bin',
    LDS_DIR   / 'ef.sod_si_454CB206.bin',
)
def test_sodId(datafiles):
    assert issubclass(SodId, IIntegerId)
    assert isinstance(SodId(0), SodId)
    assert SodId.byteSize() == 8
    assert SodId.min        == -9223372036854775808
    assert SodId.max        == 9223372036854775807
    assert SodId(0).min     == SodId.min
    assert SodId(0).max     == SodId.max
    assert SodId(SodId.min) == SodId.min
    assert SodId(SodId.max) == SodId.max

    _test_ser_IIntegerId_type(SodId(0), 0, '0', '0000000000000000', bytes.fromhex('0000000000000000'))
    _test_ser_IIntegerId_type(SodId(1), 1, '1', '0000000000000001', bytes.fromhex('0000000000000001'))
    _test_ser_IIntegerId_type(SodId(-1), -1, '-1', 'FFFFFFFFFFFFFFFF', bytes.fromhex('FFFFFFFFFFFFFFFF'))
    _test_ser_IIntegerId_type(SodId(0x7FFFFFFF), 2147483647, '2147483647', '000000007FFFFFFF', bytes.fromhex('000000007FFFFFFF'))
    _test_ser_IIntegerId_type(SodId(0x80000000), 2147483648, '2147483648', '0000000080000000', bytes.fromhex('0000000080000000'))
    _test_ser_IIntegerId_type(SodId(0xFFFFFFFF), 4294967295, '4294967295', '00000000FFFFFFFF', bytes.fromhex('00000000FFFFFFFF'))
    _test_ser_IIntegerId_type(SodId(0x0100000000), 4294967296, '4294967296', '0000000100000000', bytes.fromhex('0000000100000000'))
    _test_ser_IIntegerId_type(SodId(-0x8000000000000000), SodId.min, '-9223372036854775808', '8000000000000000', bytes.fromhex('8000000000000000'))
    _test_ser_IIntegerId_type(SodId(0x3FFFFFFFFFFFFFFF), 4611686018427387903, '4611686018427387903', '3FFFFFFFFFFFFFFF', bytes.fromhex('3FFFFFFFFFFFFFFF'))
    _test_ser_IIntegerId_type(SodId(0x7FFFFFFFFFFFFFFF), SodId.max, '9223372036854775807', '7FFFFFFFFFFFFFFF', bytes.fromhex('7FFFFFFFFFFFFFFF'))

    # Test generating EF.SOD ID from EF.SOD object
    # Test vector SodIds were generated using 'OpenSSL 1.1.1k 25 Mar 2021'
    with open(datafiles / 'ef.sod_de_9712AB14.bin', "rb") as sod:
        sod = ef.SOD.load(sod.read())
        assert SodId.fromSOD(sod) == SodId.fromHex('3643E6541E49ACF8')

    with open(datafiles / 'ef.sod_si_454CB206.bin', "rb") as sod:
        sod = ef.SOD.load(sod.read())
        assert SodId.fromSOD(sod) == SodId.fromHex('836B852D934F1A38')

    # Fuzz tests
    with pytest.raises(ValueError, match='integer out of range to construct SodId. id_value=-9223372036854775809'):
        SodId(SodId.min - 1)
    with pytest.raises(ValueError, match='integer out of range to construct SodId. id_value=9223372036854775808'):
        SodId(SodId.max + 1)

# UserId tests
def test_UserId():
    assert issubclass(UserId, bytes)
    assert UserId.max_size == 20

    assert UserId(bytes.fromhex("01")) == bytes.fromhex("01")
    assert UserId(bytes.fromhex("0101")) == bytes.fromhex("0101")
    assert UserId(bytes.fromhex("0101DA")) == bytes.fromhex("0101DA")
    assert UserId(bytes.fromhex("0101DAEF")) == bytes.fromhex("0101DAEF")
    assert UserId(bytes.fromhex("F101DAEF02")) == bytes.fromhex("F101DAEF02")
    assert UserId(bytes.fromhex("F101DAEF02A8")) == bytes.fromhex("F101DAEF02A8")
    assert UserId(bytes.fromhex("F101DAEF02A8CC")) == bytes.fromhex("F101DAEF02A8CC")
    assert UserId(bytes.fromhex("F101DAEF02A8CCD7")) == bytes.fromhex("F101DAEF02A8CCD7")
    assert UserId(bytes.fromhex("F101DAEF02A8CCD701")) == bytes.fromhex("F101DAEF02A8CCD701")
    assert UserId(bytes.fromhex("F101DAEF02A8CCD70101")) == bytes.fromhex("F101DAEF02A8CCD70101")
    assert UserId(bytes.fromhex("F101DAEF02A8CCD7010110")) == bytes.fromhex("F101DAEF02A8CCD7010110")
    assert UserId(bytes.fromhex("F101DAEF02A8CCD701011062")) == bytes.fromhex("F101DAEF02A8CCD701011062")
    assert UserId(bytes.fromhex("3121DAEF02A8CCD70101106222")) == bytes.fromhex("3121DAEF02A8CCD70101106222")
    assert UserId(bytes.fromhex("3121DAEF02A8CCD7010110622245")) == bytes.fromhex("3121DAEF02A8CCD7010110622245")
    assert UserId(bytes.fromhex("3121DAEF02A8CCD701011062224588")) == bytes.fromhex("3121DAEF02A8CCD701011062224588")
    assert UserId(bytes.fromhex("3121DAEF02A8CCD70101106222458890")) == bytes.fromhex("3121DAEF02A8CCD70101106222458890")
    assert UserId(bytes.fromhex("3121DAEF02A8CCD7010110622245889057")) == bytes.fromhex("3121DAEF02A8CCD7010110622245889057")
    assert UserId(bytes.fromhex("3121DAEF02A8CCD701011062224588905799")) == bytes.fromhex("3121DAEF02A8CCD701011062224588905799")
    assert UserId(bytes.fromhex("3121DAEF02A8CCD701011062224588905799FE")) == bytes.fromhex("3121DAEF02A8CCD701011062224588905799FE")
    assert UserId(bytes.fromhex("3121DAEF02A8CCD701011062224588905799FEED")) == bytes.fromhex("3121DAEF02A8CCD701011062224588905799FEED")

    assert UserId("t") == bytes.fromhex('74')
    assert UserId("fo") == bytes.fromhex('666f')
    assert UserId("foo") == bytes.fromhex('666f6f')
    assert UserId("foob") == bytes.fromhex('666f6f62')
    assert UserId("fooba") == bytes.fromhex('666f6f6261')
    assert UserId("foobar") == bytes.fromhex('666f6f626172')
    assert UserId("foobar1") == bytes.fromhex('666f6f62617231')
    assert UserId("foobar1ß") == bytes.fromhex('666f6f62617231c39f')
    assert UserId("foobar1ßд") == bytes.fromhex('666f6f62617231c39fd0b4')
    assert UserId("foobar1ßдA") == bytes.fromhex('666f6f62617231c39fd0b441')
    assert UserId("foobar1ßдAv") == bytes.fromhex('666f6f62617231c39fd0b44176')
    assert UserId("foobar1ßдAv ") == bytes.fromhex('666f6f62617231c39fd0b4417620')
    assert UserId("foobar1ßдAv 9") == bytes.fromhex('666f6f62617231c39fd0b441762039')
    assert UserId("foobar1ßдAv 9!") == bytes.fromhex('666f6f62617231c39fd0b44176203921')
    assert UserId("foobar1ßдAv 9!%") == bytes.fromhex('666f6f62617231c39fd0b4417620392125')
    assert UserId("foobar1ßдAv 9!%U") == bytes.fromhex('666f6f62617231c39fd0b441762039212555')
    assert UserId("foobar1ßдAv 9!%Ux") == bytes.fromhex('666f6f62617231c39fd0b44176203921255578')
    assert UserId("foobar1ßдAv 9!%UxZ") == bytes.fromhex('666f6f62617231c39fd0b441762039212555785a')
    assert UserId("testuser") == bytes.fromhex('7465737475736572')
    assert UserId("T\\b9zRob/b7#9G?Tv;kd") == bytes.fromhex('545C62397A526F622F62372339473F54763B6B64')

    assert UserId.fromBase64("AQ==") == bytes.fromhex("01")
    assert UserId.fromBase64("AS8=") == bytes.fromhex("012F")
    assert UserId.fromBase64("AS+H") == bytes.fromhex("012F87")
    assert UserId.fromBase64("AS+HmQ==") == bytes.fromhex("012F8799")
    assert UserId.fromBase64("AS+HmS4=") == bytes.fromhex("012F87992E")
    assert UserId.fromBase64("AS+HmS4A") == bytes.fromhex("012F87992E00")
    assert UserId.fromBase64("AS+HmS4AQw==") == bytes.fromhex("012F87992E0043")
    assert UserId.fromBase64("AS+HmS4AQ/8=") == bytes.fromhex("012F87992E0043FF")
    assert UserId.fromBase64("AS+HmS4AQ/+1") == bytes.fromhex("012F87992E0043FFB5")
    assert UserId.fromBase64("AS+HmS4AQ/+1ag==") == bytes.fromhex("012F87992E0043FFB56A")
    assert UserId.fromBase64("AS+HmS4AQ/+1as8=") == bytes.fromhex("012F87992E0043FFB56ACF")
    assert UserId.fromBase64("AS+HmS4AQ/+1as8f") == bytes.fromhex("012F87992E0043FFB56ACF1F")
    assert UserId.fromBase64("AS+HmS4AQ/+1as8fIg==") == bytes.fromhex("012F87992E0043FFB56ACF1F22")
    assert UserId.fromBase64("AS+HmS4AQ/+1as8fIl0=") == bytes.fromhex("012F87992E0043FFB56ACF1F225D")
    assert UserId.fromBase64("AS+HmS4AQ/+1as8fIl2N") == bytes.fromhex("012F87992E0043FFB56ACF1F225D8D")
    assert UserId.fromBase64("AS+HmS4AQ/+1as8fIl2NRw==") == bytes.fromhex("012F87992E0043FFB56ACF1F225D8D47")
    assert UserId.fromBase64("AS+HmS4AQ/+1as8fIl2NRxM=") == bytes.fromhex("012F87992E0043FFB56ACF1F225D8D4713")
    assert UserId.fromBase64("AS+HmS4AQ/+1as8fIl2NRxMR") == bytes.fromhex("012F87992E0043FFB56ACF1F225D8D471311")
    assert UserId.fromBase64("AS+HmS4AQ/+1as8fIl2NRxMRAQ==") == bytes.fromhex("012F87992E0043FFB56ACF1F225D8D47131101")
    assert UserId.fromBase64("AS+HmS4AQ/+1as8fIl2NRxMRAf4=") == bytes.fromhex("012F87992E0043FFB56ACF1F225D8D47131101FE")

    assert UserId(bytes.fromhex("01")).toBase64() == "AQ=="
    assert UserId(bytes.fromhex("012F")).toBase64() == "AS8="
    assert UserId(bytes.fromhex("012F87")).toBase64() == "AS+H"
    assert UserId(bytes.fromhex("012F8799")).toBase64() == "AS+HmQ=="
    assert UserId(bytes.fromhex("012F87992E")).toBase64() == "AS+HmS4="
    assert UserId(bytes.fromhex("012F87992E00")).toBase64() == "AS+HmS4A"
    assert UserId(bytes.fromhex("012F87992E0043")).toBase64() == "AS+HmS4AQw=="
    assert UserId(bytes.fromhex("012F87992E0043FF")).toBase64() == "AS+HmS4AQ/8="
    assert UserId(bytes.fromhex("012F87992E0043FFB5")).toBase64() == "AS+HmS4AQ/+1"
    assert UserId(bytes.fromhex("012F87992E0043FFB56A")).toBase64() == "AS+HmS4AQ/+1ag=="
    assert UserId(bytes.fromhex("012F87992E0043FFB56ACF")).toBase64() == "AS+HmS4AQ/+1as8="
    assert UserId(bytes.fromhex("012F87992E0043FFB56ACF1F")).toBase64() == "AS+HmS4AQ/+1as8f"
    assert UserId(bytes.fromhex("012F87992E0043FFB56ACF1F22")).toBase64() == "AS+HmS4AQ/+1as8fIg=="
    assert UserId(bytes.fromhex("012F87992E0043FFB56ACF1F225D")).toBase64() == "AS+HmS4AQ/+1as8fIl0="
    assert UserId(bytes.fromhex("012F87992E0043FFB56ACF1F225D8D")).toBase64() == "AS+HmS4AQ/+1as8fIl2N"
    assert UserId(bytes.fromhex("012F87992E0043FFB56ACF1F225D8D47")).toBase64() == "AS+HmS4AQ/+1as8fIl2NRw=="
    assert UserId(bytes.fromhex("012F87992E0043FFB56ACF1F225D8D4713")).toBase64() == "AS+HmS4AQ/+1as8fIl2NRxM="
    assert UserId(bytes.fromhex("012F87992E0043FFB56ACF1F225D8D471311")).toBase64() == "AS+HmS4AQ/+1as8fIl2NRxMR"
    assert UserId(bytes.fromhex("012F87992E0043FFB56ACF1F225D8D47131101")).toBase64() == "AS+HmS4AQ/+1as8fIl2NRxMRAQ=="
    assert UserId(bytes.fromhex("012F87992E0043FFB56ACF1F225D8D47131101FE")).toBase64() == "AS+HmS4AQ/+1as8fIl2NRxMRAf4="

    assert str(UserId(bytes.fromhex("01"))) == ""
    assert str(UserId(bytes.fromhex("0101"))) == ""
    assert str(UserId(bytes.fromhex("0101DA"))) == "0101DA"
    assert str(UserId(bytes.fromhex("0101DAEF"))) == "0101DAEF"
    assert str(UserId(bytes.fromhex("F101DAEF02"))) == "F101DAEF02"
    assert str(UserId(bytes.fromhex("F101DAEF02A8"))) == "F101DAEF02A8"
    assert str(UserId(bytes.fromhex("F101DAEF02A8CC"))) == "F101DAEF02A8CC"
    assert str(UserId(bytes.fromhex("F101DAEF02A8CCD7"))) == "F101DAEF02A8CCD7"
    assert str(UserId(bytes.fromhex("F101DAEF02A8CCD701"))) == "F101DAEF02A8CCD701"
    assert str(UserId(bytes.fromhex("F101DAEF02A8CCD70101"))) == "F101DAEF02A8CCD70101"
    assert str(UserId(bytes.fromhex("F101DAEF02A8CCD7010110"))) == "F101DAEF02A8CCD7010110"
    assert str(UserId(bytes.fromhex("F101DAEF02A8CCD701011062"))) == "F101DAEF02A8CCD701011062"
    assert str(UserId(bytes.fromhex("3121DAEF02A8CCD70101106222"))) == "3121DAEF02A8CCD70101106222"
    assert str(UserId(bytes.fromhex("3121DAEF02A8CCD7010110622245"))) == "3121DAEF02A8CCD7010110622245"
    assert str(UserId(bytes.fromhex("3121DAEF02A8CCD701011062224588"))) == "3121DAEF02A8CCD701011062224588"
    assert str(UserId(bytes.fromhex("3121DAEF02A8CCD70101106222458890"))) == "3121DAEF02A8CCD70101106222458890"
    assert str(UserId(bytes.fromhex("3121DAEF02A8CCD7010110622245889057"))) == "3121DAEF02A8CCD7010110622245889057"
    assert str(UserId(bytes.fromhex("3121DAEF02A8CCD701011062224588905799"))) == "3121DAEF02A8CCD701011062224588905799"
    assert str(UserId(bytes.fromhex("3121DAEF02A8CCD701011062224588905799FE"))) == "3121DAEF02A8CCD701011062224588905799FE"
    assert str(UserId(bytes.fromhex("3121DAEF02A8CCD701011062224588905799FEED"))) == "3121DAEF02A8CCD701011062224588905799FEED"

    assert str(UserId("t")) == "t"
    assert str(UserId("fo")) == "fo"
    assert str(UserId("foo")) == "foo"
    assert str(UserId("foob")) == "foob"
    assert str(UserId("fooba")) == "fooba"
    assert str(UserId("foobar")) == "foobar"
    assert str(UserId("foobar1")) == "foobar1"
    assert str(UserId("foobar1ß")) == "foobar1ß"
    assert str(UserId("foobar1ßд")) == "foobar1ßд"
    assert str(UserId("foobar1ßдA")) == "foobar1ßдA"
    assert str(UserId("foobar1ßдAv")) == "foobar1ßдAv"
    assert str(UserId("foobar1ßдAv ")) == "foobar1ßдAv "
    assert str(UserId("foobar1ßдAv 9")) == "foobar1ßдAv 9"
    assert str(UserId("foobar1ßдAv 9!")) == "foobar1ßдAv 9!"
    assert str(UserId("foobar1ßдAv 9!%")) == "foobar1ßдAv 9!%"
    assert str(UserId("foobar1ßдAv 9!%U")) == "foobar1ßдAv 9!%U"
    assert str(UserId("foobar1ßдAv 9!%Ux")) == "foobar1ßдAv 9!%Ux"
    assert str(UserId("foobar1ßдAv 9!%UxZ")) == "foobar1ßдAv 9!%UxZ"

    assert UserId("testUseR1234").toBase64() == "dGVzdFVzZVIxMjM0"
    assert UserId("foobar1ßдAv 9!%UxZ").toBase64() == "Zm9vYmFyMcOf0LRBdiA5ISVVeFo="
    assert str(UserId.fromBase64(UserId("testUseR1234").toBase64())) == "testUseR1234"
    assert str(UserId.fromBase64(UserId("foobar1ßдAv 9!%UxZ").toBase64())) == "foobar1ßдAv 9!%UxZ"
    assert str(UserId.fromBase64(UserId(bytes.fromhex("3121DAEF02A8CCD701011062224588905799FEED")).toBase64())) == "3121DAEF02A8CCD701011062224588905799FEED"

    # Fuzz testes
    with pytest.raises(UserIdError, match='Invalid userId data'): # empty data
        UserId(bytes.fromhex(""))

    with pytest.raises(UserIdError, match='Invalid userId data'): # empty data
        UserId("")

    with pytest.raises(UserIdError, match='Invalid userId data'): # empty data
        UserId.fromBase64("")

    with pytest.raises(UserIdError, match='Invalid userId data'): # empty data
        UserId.fromhex("")

    with pytest.raises(UserIdError, match='Invalid userId data'): # data too big
        UserId(bytes.fromhex("AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBFF"))

    with pytest.raises(UserIdError, match='Invalid userId data'): # data too big
        UserId("ABCDEFGHIJKLMN1234567")

    with pytest.raises(UserIdError, match='Invalid userId data'): # data too big
        UserId("ABCDEFGHIJKLMN12345Փ")

    with pytest.raises(UserIdError, match='Invalid userId data'): # data too big
        UserId.fromBase64("AS+HmS4AQ/+1as8fIl2NRxMRAf4K")

    with pytest.raises(UserIdError, match='Invalid userId data'): # invalid data type
        UserId(int(5))

    with pytest.raises(UserIdError, match='Invalid userId data'): # invalid data type
        UserId(float(5))

# Challenge tests
@pytest.mark.depends(on=['test_CID'])
def test_Challenge():
    # pylint: disable=protected-access
    assert issubclass(Challenge, bytes)
    assert Challenge._hash_algo == SHA512_256 # pylint: disable=protected-access
    assert Challenge._hash_algo.digest_size == 32

    assert Challenge(bytes.fromhex("51B3DBE6DDC8A152583EC092BD9D482BED2CA0B2E17684B8A7970D6FBBAEBA20")) == bytes.fromhex("51B3DBE6DDC8A152583EC092BD9D482BED2CA0B2E17684B8A7970D6FBBAEBA20")
    assert Challenge.fromhex("51B3DBE6DDC8A152583EC092BD9D482BED2CA0B2E17684B8A7970D6FBBAEBA20") == bytes.fromhex("51B3DBE6DDC8A152583EC092BD9D482BED2CA0B2E17684B8A7970D6FBBAEBA20")

    assert Challenge.fromBase64("UbPb5t3IoVJYPsCSvZ1IK+0soLLhdoS4p5cNb7uuuiA=") == bytes.fromhex("51B3DBE6DDC8A152583EC092BD9D482BED2CA0B2E17684B8A7970D6FBBAEBA20")
    assert Challenge.fromhex("51B3DBE6DDC8A152583EC092BD9D482BED2CA0B2E17684B8A7970D6FBBAEBA20").toBase64() == "UbPb5t3IoVJYPsCSvZ1IK+0soLLhdoS4p5cNb7uuuiA="

    assert Challenge(bytes.fromhex("51B3DBE6DDC8A152583EC092BD9D482BED2CA0B2E17684B8A7970D6FBBAEBA20")).id == CID("51B3DBE6", 16)
    assert Challenge.fromBase64("UbPb5t3IoVJYPsCSvZ1IK+0soLLhdoS4p5cNb7uuuiA=") .id == CID("51B3DBE6", 16)

    assert len(Challenge.generate(datetime.now(), extraData=b'')) == Challenge._hash_algo.digest_size
    assert len(Challenge.generate(datetime.now(), extraData=bytes.fromhex("FF010201FFCA"))) == Challenge._hash_algo.digest_size

    # Test generating 100 random challenges
    for _ in range(0, 100):
        c = Challenge.generate(datetime.now(), extraData=os.urandom(Challenge._hash_algo.digest_size))
        hexc = c.hex()
        assert Challenge.fromhex(hexc) == c
        b64c = c.toBase64()
        assert Challenge.fromBase64(b64c) == c
        assert c.id == CID(c[0:4])

    # Fuzz testes
    with pytest.raises(ChallengeError, match='Invalid challenge length'): # empty data
        Challenge(bytes.fromhex(""))

    with pytest.raises(ChallengeError, match='Invalid challenge length'): # empty data
        Challenge.fromBase64("")

    with pytest.raises(ChallengeError, match='Invalid challenge length'): # empty data
        Challenge.fromhex("")

    with pytest.raises(ChallengeError, match='Invalid challenge length'): # data too small
        Challenge(bytes.fromhex("AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBFF"))

    with pytest.raises(ChallengeError, match='Invalid challenge length'): # data too small
        Challenge(bytes.fromhex("51B3DBE6DDC8A152583EC092BD9D482BED2CA0B2E17684B8A7970D6FBBAEBA"))

    with pytest.raises(ChallengeError, match='Invalid challenge length'): # data too small
        Challenge.fromBase64("AS+HmS4AQ/+1as8fIl2NRxMRAf4K")

    with pytest.raises(ChallengeError, match='Invalid challenge length'): # data too small
        Challenge.fromBase64("UbPb5t3IoVJYPsCSvZ1IK+0soLLhdoS4p5cNb7uuug==")

    with pytest.raises(ChallengeError, match='Invalid challenge length'): # data too big
        Challenge(bytes.fromhex("51B3DBE6DDC8A152583EC092BD9D482BED2CA0B2E17684B8A7970D6FBBAEBA2001"))

    with pytest.raises(ChallengeError, match='Invalid challenge length'): # data too big
        Challenge.fromBase64("UbPb5t3IoVJYPsCSvZ1IK+0soLLhdoS4p5cNb7uuuiAB")

    with pytest.raises(ChallengeError, match='Invalid challenge type'): # invalid data type
        Challenge("")

    with pytest.raises(ChallengeError, match='Invalid challenge type'): # invalid data type
        Challenge("51B3DBE6DDC8A152583EC092BD9D482BED2CA0B2E17684B8A7970D6FBBAEBA21")

    with pytest.raises(ChallengeError, match='Invalid challenge type'): # invalid data type
        Challenge(int(5))

    with pytest.raises(ChallengeError, match='Invalid challenge type'): # invalid data type
        Challenge(float(5))

def test_FunctionHook():
    # pylint: disable=unused-argument, unnecessary-lambda, no-self-use, singleton-comparison, no-member
    @hook
    def test_hooked_func(a,b,c) -> int:
        return 1

    def test_func(a,b, c) -> str:
        return f"test_func return: {a}, {b}, {c}"

    class TestClass:
        @hook
        def test_hooked_method(self, a,b,c) -> str:
            return f"test_hooked_method return: {a}, {b}, {c}"

        def test_method(self, a, b, c) -> str:
            return f"test_method return: {a}, {b}, {c}"

        @hook
        @classmethod
        def test_hooked_classmethod(cls, a, b, c) -> str:
            return f"test_hooked_classmethod return: {a}, {b}, {c}"

        @classmethod
        def test_classmethod(cls, a, b, c) -> str:
            return f"test_classmethod return: {a}, {b}, {c}"

        @hook
        @staticmethod
        def test_hooked_static_method(a,b,c) -> str:
            return f"test_hooked_static_method return: {a}, {b}, {c}"

        @staticmethod
        def test_static_method(a,b,c) -> str:
            return f"test_static_method return: {a}, {b}, {c}"

    tcls = TestClass()

    # Test function & method types and hook attributes
    assert isinstance(test_hooked_func, FunctionHook) == True
    assert hasattr(test_hooked_func, 'onCall')        == True
    assert hasattr(test_hooked_func, 'onReturn')      == True

    assert isinstance(test_func, FunctionHook) == False
    assert hasattr(test_func, 'onCall')        == False
    assert hasattr(test_func, 'onReturn')      == False

    assert isinstance(TestClass.test_hooked_method, FunctionHook) == True
    assert hasattr(TestClass.test_hooked_method, 'onCall')        == True
    assert hasattr(TestClass.test_hooked_method, 'onReturn')      == True

    assert isinstance(tcls.test_hooked_method, FunctionHook) == True
    assert hasattr(tcls.test_hooked_method, 'onCall')        == True
    assert hasattr(tcls.test_hooked_method, 'onReturn')      == True

    assert isinstance(TestClass.test_method, FunctionHook) == False
    assert hasattr(TestClass.test_method, 'onCall')        == False
    assert hasattr(TestClass.test_method, 'onReturn')      == False

    assert isinstance(tcls.test_method, FunctionHook) == False
    assert hasattr(tcls.test_method, 'onCall')        == False
    assert hasattr(tcls.test_method, 'onReturn')      == False

    assert isinstance(TestClass.test_hooked_classmethod, FunctionHook) == True
    assert hasattr(TestClass.test_hooked_classmethod, 'onCall')        == True
    assert hasattr(TestClass.test_hooked_classmethod, 'onReturn')      == True

    assert isinstance(tcls.test_hooked_classmethod, FunctionHook) == True
    assert hasattr(tcls.test_hooked_classmethod, 'onCall')        == True
    assert hasattr(tcls.test_hooked_classmethod, 'onReturn')      == True

    assert isinstance(TestClass.test_classmethod, FunctionHook) == False
    assert hasattr(TestClass.test_classmethod, 'onCall')        == False
    assert hasattr(TestClass.test_classmethod, 'onReturn')      == False

    assert isinstance(tcls.test_classmethod, FunctionHook) == False
    assert hasattr(tcls.test_classmethod, 'onCall')        == False
    assert hasattr(tcls.test_classmethod, 'onReturn')      == False

    assert isinstance(TestClass.test_hooked_static_method, FunctionHook) == True
    assert hasattr(TestClass.test_hooked_static_method, 'onCall')        == True
    assert hasattr(TestClass.test_hooked_static_method, 'onReturn')      == True

    assert isinstance(tcls.test_hooked_static_method, FunctionHook) == True
    assert hasattr(tcls.test_hooked_static_method, 'onCall')        == True
    assert hasattr(tcls.test_hooked_static_method, 'onReturn')      == True

    assert isinstance(TestClass.test_static_method, FunctionHook) == False
    assert hasattr(TestClass.test_static_method, 'onCall')        == False
    assert hasattr(TestClass.test_static_method, 'onReturn')      == False

    assert isinstance(tcls.test_static_method, FunctionHook) == False
    assert hasattr(tcls.test_static_method, 'onCall')        == False
    assert hasattr(tcls.test_static_method, 'onReturn')      == False

    ret_value           = None
    call_hook_invoked   = False
    return_hook_invoked = False
    def reset_test_vars():
        nonlocal ret_value
        ret_value = None
        nonlocal call_hook_invoked
        call_hook_invoked = False
        nonlocal return_hook_invoked
        return_hook_invoked = False

    def check_hook_args(args_in: tuple, kwargs_in: dict, args_cmp: tuple, kwargs_cmp: dict):
        assert args_in   == args_cmp
        assert kwargs_in == kwargs_cmp

    def check_call_hook_args(args_in: tuple, kwargs_in: dict, args_cmp: tuple, kwargs_cmp, overridden_args: Optional[dict] = None) -> None:
        check_hook_args(args_in, kwargs_in, args_cmp, kwargs_cmp)
        nonlocal  call_hook_invoked
        call_hook_invoked = True
        return overridden_args

    def check_return_hook_args(args_in: tuple, kwargs_in: dict, args_cmp: tuple, kwargs_cmp, return_value: Any) -> Any:
        check_hook_args(args_in, kwargs_in, args_cmp, kwargs_cmp)
        nonlocal return_hook_invoked
        return_hook_invoked = True
        return return_value

# Test function hooks
    ret_value = test_hooked_func("a", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == 1
    reset_test_vars()

    # Set call hook
    assert test_hooked_func.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, ("a", 5), {'c': 8})) is None
    ret_value = test_hooked_func("a", 5, c=8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == 1
    reset_test_vars()

    assert test_hooked_func.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, ("a", 5, 8), {})) is not None
    ret_value = test_hooked_func("a", 5, 8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == 1
    reset_test_vars()

    # Set return hook
    assert test_hooked_func.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, (1, "a", 5, 8), {}, return_value = args[0])) is None
    ret_value = test_hooked_func("a", 5, 8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == 1
    reset_test_vars()

    # Set return hook and change return value to 2
    assert test_hooked_func.onReturn(lambda *args, **kwargs:\
         check_return_hook_args(args, kwargs, (1, "a", 5, 8), {}, return_value = 2)) is not None
    ret_value = test_hooked_func("a", 5, 8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == 2
    reset_test_vars()

    # Set call hook with overridden args and return hook
    assert test_hooked_func.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, ("a", 5, 8), {}, overridden_args={'a' : 0xfeed})) is not None
    assert test_hooked_func.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, (1, 0xfeed, 5, 8), {}, return_value = args[0])) is not None
    ret_value = test_hooked_func("a", 5, 8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == 1
    reset_test_vars()

    assert test_hooked_func.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, ("a", 5), {'c' : 8}, overridden_args={'c' : 0x0badf00d})) is not None
    assert test_hooked_func.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, (1, "a", 5), {'c' : 0x0badf00d}, return_value = args[0])) is not None
    ret_value = test_hooked_func("a", 5, c=8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == 1
    reset_test_vars()

    # Set call hook with overridden args and return hook with override value
    assert test_hooked_func.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, ("a", 5), {'c' : 8}, overridden_args={'c' : 0x0badf00d})) is not None
    assert test_hooked_func.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, (1, "a", 5), {'c' : 0x0badf00d}, return_value = 88)) is not None
    ret_value = test_hooked_func("a", 5, c=8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == 88
    reset_test_vars()

    assert test_hooked_func.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, ("a", 5, 8), {}, overridden_args={'a' : 0xfeed})) is not None
    assert test_hooked_func.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, (1, 0xfeed, 5, 8), {}, return_value = 'overridden_value')) is not None
    ret_value = test_hooked_func("a", 5, 8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "overridden_value"
    reset_test_vars()

    # Unset return hook
    assert test_hooked_func.onReturn(None) is not None
    ret_value = test_hooked_func("a", 5, 8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == 1
    reset_test_vars()

    # Unset call hook
    assert test_hooked_func.onCall(None) is not None
    ret_value = test_hooked_func("a", 9, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == 1
    reset_test_vars()

# Test class hooked method
    ret_value = tcls.test_hooked_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 'a', 5, 8"
    reset_test_vars()

    # Set call hook
    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 120, "'2nd arg'"), {'c' : 0.05895})) is None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", c=0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Override call arguments
    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 120, "'2nd arg'"), {'c' : 0.05895}, overridden_args={'b': 5})) is not None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", c=0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 120, 5, 0.05895"
    reset_test_vars()

    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 120, "'2nd arg'"), {'c' : 0.05895}, overridden_args={'c': "'3rd_arg'"})) is not None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", c=0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 120, '2nd arg', '3rd_arg'"
    reset_test_vars()

    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 120, "'2nd arg'"), {'c' : 0.05895}, overridden_args={'a': "'1st_arg was 120'"})) is not None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", c=0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: '1st_arg was 120', '2nd arg', 0.05895"
    reset_test_vars()

    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 120, "'2nd arg'", 0.05895), {})) is not None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 120, "'2nd arg'", 0.05895), {},  overridden_args={'b': 5})) is not None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 120, 5, 0.05895"
    reset_test_vars()

    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 120, "'2nd arg'", 0.05895), {}, overridden_args={'c': "'3rd_arg'"})) is not None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 120, '2nd arg', '3rd_arg'"
    reset_test_vars()

    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 120, "'2nd arg'", 0.05895), {}, overridden_args={'a': "'1st_arg was 120'"})) is not None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: '1st_arg was 120', '2nd arg', 0.05895"
    reset_test_vars()

    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 120, "'2nd arg'", 0.05895), {}, overridden_args={'a': "'1st_arg was 120'", 'b': 6 , 'c': "'3rd_arga'"})) is not None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: '1st_arg was 120', 6, '3rd_arga'"
    reset_test_vars()

    # Reset call hook to not override params
    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 120, "'2nd arg'", 0.05895), {})) is not None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook
    assert tcls.test_hooked_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_method return: 120, '2nd arg', 0.05895", tcls, 120, "'2nd arg'", 0.05895), {}, return_value = args[0])) is None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "test_hooked_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook with changed return value
    assert tcls.test_hooked_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_method return: 120, '2nd arg', 0.05895", tcls, 120, "'2nd arg'", 0.05895), {}, return_value = "return of the Hook")) is not None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Set call hook with overridden param and return hook
    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 120, "'2nd arg'", 0.05895), {}, overridden_args={'a': "'1st_arg was 120'"})) is not None
    assert tcls.test_hooked_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_method return: '1st_arg was 120', '2nd arg', 0.05895", tcls, "'1st_arg was 120'", "'2nd arg'", 0.05895), {}, return_value = args[0])) is not None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "test_hooked_method return: '1st_arg was 120', '2nd arg', 0.05895"
    reset_test_vars()

    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 120, "'2nd arg'", 0.05895), {}, overridden_args={'a': "'1st_arg was 120'", 'b': 6 , 'c': "'3rd_arga'"})) is not None
    assert tcls.test_hooked_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_method return: '1st_arg was 120', 6, '3rd_arga'", tcls, "'1st_arg was 120'", 6, "'3rd_arga'"), {}, return_value = args[0])) is not None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "test_hooked_method return: '1st_arg was 120', 6, '3rd_arga'"
    reset_test_vars()

    # Set call hook with overridden param and return hook with overridden return value
    assert tcls.test_hooked_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_method return: '1st_arg was 120', 6, '3rd_arga'", tcls, "'1st_arg was 120'", 6, "'3rd_arga'"), {}, return_value = "return of the Hook 2")) is not None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook 2"
    reset_test_vars()

    # Unset return hook
    assert tcls.test_hooked_method.onReturn(None) is not None
    ret_value = tcls.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: '1st_arg was 120', 6, '3rd_arga'"
    reset_test_vars()

    # Unset call hook
    assert tcls.test_hooked_method.onCall(None) is not None
    ret_value = tcls.test_hooked_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 'a', 5, 8"
    reset_test_vars()

# Test class hooked classmethod
    ret_value = tcls.test_hooked_classmethod("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_classmethod return: 'a', 5, 8"
    reset_test_vars()

    # Set call hook
    assert tcls.test_hooked_classmethod.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (TestClass, 120, "'2nd arg'"), {'c' : 0.05895})) is None
    ret_value = tcls.test_hooked_classmethod(120, "'2nd arg'", c=0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    assert tcls.test_hooked_classmethod.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (TestClass, 120, "'2nd arg'", 0.05895), {})) is not None
    ret_value = tcls.test_hooked_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook
    assert tcls.test_hooked_classmethod.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_classmethod return: 120, '2nd arg', 0.05895", TestClass, 120, "'2nd arg'", 0.05895), {}, return_value = args[0])) is None
    ret_value = tcls.test_hooked_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "test_hooked_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook with changed return value
    assert tcls.test_hooked_classmethod.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_classmethod return: 120, '2nd arg', 0.05895", TestClass, 120, "'2nd arg'", 0.05895), {}, return_value = "return of the Hook")) is not None
    ret_value = tcls.test_hooked_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Test class type has hooks on classmethod
    ret_value = TestClass.test_hooked_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Unset return hook
    assert tcls.test_hooked_classmethod.onReturn(None) is not None
    ret_value = tcls.test_hooked_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Unset call hook
    assert tcls.test_hooked_classmethod.onCall(None) is not None
    ret_value = tcls.test_hooked_classmethod("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_classmethod return: 'a', 5, 8"
    reset_test_vars()

# Test class hooked classmethod without object instance
    ret_value = TestClass.test_hooked_classmethod("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_classmethod return: 'a', 5, 8"
    reset_test_vars()

    # Set call hook
    assert TestClass.test_hooked_classmethod.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (TestClass, 120, "'2nd arg'"), {'c' : 0.05895})) is None
    ret_value = TestClass.test_hooked_classmethod(120, "'2nd arg'", c=0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    assert TestClass.test_hooked_classmethod.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (TestClass, 120, "'2nd arg'", 0.05895), {})) is not None
    ret_value = TestClass.test_hooked_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook
    assert TestClass.test_hooked_classmethod.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_classmethod return: 120, '2nd arg', 0.05895", TestClass, 120, "'2nd arg'", 0.05895), {}, return_value = args[0])) is None
    ret_value = TestClass.test_hooked_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "test_hooked_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook with changed return value
    assert TestClass.test_hooked_classmethod.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_classmethod return: 120, '2nd arg', 0.05895", TestClass, 120, "'2nd arg'", 0.05895), {}, return_value = "return of the Hook")) is not None
    ret_value = TestClass.test_hooked_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Test class instance has hooks on classmethod
    ret_value = tcls.test_hooked_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Unset return hook
    assert TestClass.test_hooked_classmethod.onReturn(None) is not None
    ret_value = TestClass.test_hooked_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Unset call hook
    assert TestClass.test_hooked_classmethod.onCall(None) is not None
    ret_value = TestClass.test_hooked_classmethod("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_classmethod return: 'a', 5, 8"
    reset_test_vars()

# Test class hooked static method
    ret_value = tcls.test_hooked_static_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_static_method return: 'a', 5, 8"
    reset_test_vars()

    # Set call hook
    assert tcls.test_hooked_static_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (120, "'2nd arg'"), {'c' : 0.05895})) is None
    ret_value = tcls.test_hooked_static_method(120, "'2nd arg'", c=0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    assert tcls.test_hooked_static_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (120, "'2nd arg'", 0.05895), {})) is not None
    ret_value = tcls.test_hooked_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook
    assert tcls.test_hooked_static_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_static_method return: 120, '2nd arg', 0.05895", 120, "'2nd arg'", 0.05895), {}, return_value = args[0])) is None
    ret_value = tcls.test_hooked_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "test_hooked_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook with changed return value
    assert tcls.test_hooked_static_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_static_method return: 120, '2nd arg', 0.05895", 120, "'2nd arg'", 0.05895), {}, return_value = "return of the Hook")) is not None
    ret_value = tcls.test_hooked_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Test class type has also set hook on static methods
    ret_value = TestClass.test_hooked_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Unset return hook
    assert tcls.test_hooked_static_method.onReturn(None) is not None
    ret_value = tcls.test_hooked_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Unset call hook
    assert tcls.test_hooked_static_method.onCall(None) is not None
    ret_value = tcls.test_hooked_static_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_static_method return: 'a', 5, 8"
    reset_test_vars()

# Test class hooked static method without object instance
    ret_value = TestClass.test_hooked_static_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_static_method return: 'a', 5, 8"
    reset_test_vars()

    # Set call hook
    assert TestClass.test_hooked_static_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (120, "'2nd arg'"), {'c' : 0.05895})) is None
    ret_value = TestClass.test_hooked_static_method(120, "'2nd arg'", c=0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    assert TestClass.test_hooked_static_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (120, "'2nd arg'", 0.05895), {})) is not None
    ret_value = TestClass.test_hooked_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook
    assert TestClass.test_hooked_static_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_static_method return: 120, '2nd arg', 0.05895", 120, "'2nd arg'", 0.05895), {}, return_value = args[0])) is None
    ret_value = TestClass.test_hooked_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "test_hooked_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook with changed return value
    assert TestClass.test_hooked_static_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_static_method return: 120, '2nd arg', 0.05895", 120, "'2nd arg'", 0.05895), {}, return_value = "return of the Hook")) is not None
    ret_value = TestClass.test_hooked_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Test class instance has also set hook on static methods
    ret_value = tcls.test_hooked_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Unset return hook
    assert TestClass.test_hooked_static_method.onReturn(None) is not None
    ret_value = TestClass.test_hooked_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Unset call hook
    assert TestClass.test_hooked_static_method.onCall(None) is not None
    ret_value = TestClass.test_hooked_static_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_static_method return: 'a', 5, 8"
    reset_test_vars()

# Test 2 TestClass objects with different hooks
    tcls1 = TestClass()
    assert tcls1.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls1, 120, "'2nd arg'", 0.05895), {})) is None
    assert tcls1.test_hooked_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_method return: 120, '2nd arg', 0.05895", tcls1, 120, "'2nd arg'", 0.05895), {}, return_value = "return of the Hook")) is None
    ret_value = tcls1.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    tcls2 = TestClass()
    ret_value = tcls2.test_hooked_method("'test 1st arg'", 0.5, 81)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 'test 1st arg', 0.5, 81"
    reset_test_vars()

    ret_value = tcls1.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Override call arguments in tcls1.test_hooked_method
    assert tcls1.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls1, 120, "'2nd arg'", 0.05895), {}, overridden_args={'a' : "'no, no, no'"})) is not None
    assert tcls1.test_hooked_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_method return: 'no, no, no', '2nd arg', 0.05895", tcls1, "'no, no, no'", "'2nd arg'", 0.05895), {}, return_value = args[0])) is not None
    ret_value = tcls1.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "test_hooked_method return: 'no, no, no', '2nd arg', 0.05895"
    reset_test_vars()

    ret_value = tcls2.test_hooked_method("'test 1st arg'", 0.5, 81)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 'test 1st arg', 0.5, 81"
    reset_test_vars()

    # Override call arguments in tcls1.test_hooked_method and set return hook with overridden value
    assert tcls1.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls1, 120, "'2nd arg'", 0.05895), {}, overridden_args={'a' : "'no, no, no'"})) is not None
    assert tcls1.test_hooked_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_method return: 'no, no, no', '2nd arg', 0.05895", tcls1, "'no, no, no'", "'2nd arg'", 0.05895), {}, return_value = "return of the Hook 2")) is not None
    ret_value = tcls1.test_hooked_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook 2"
    reset_test_vars()

    ret_value = tcls2.test_hooked_method("'test 1st arg'", 0.5, 81)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 'test 1st arg', 0.5, 81"
    reset_test_vars()

# Add FunctionHook to non-hooked function
    test_func = FunctionHook(test_func)
    assert isinstance(test_func, FunctionHook) == True
    assert hasattr(test_func, 'onCall')        == True
    assert hasattr(test_func, 'onReturn')      == True

    ret_value = test_func("a", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_func return: a, 5, 8"
    reset_test_vars()

    # Set call hook
    assert test_func.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, ("a", 5), {'c': 8})) is None
    ret_value = test_func("a", 5, c=8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_func return: a, 5, 8"
    reset_test_vars()

    assert test_func.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, ("a", 5, 8), {})) is not None
    ret_value = test_func("a", 5, 8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_func return: a, 5, 8"
    reset_test_vars()

    # Set return hook
    assert test_func.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, ("test_func return: a, 5, 8", "a", 5, 8), {}, return_value = args[0])) is None
    ret_value = test_func("a", 5, 8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "test_func return: a, 5, 8"
    reset_test_vars()

    # Set return hook and change return value to 2
    assert test_func.onReturn(lambda *args, **kwargs:\
         check_return_hook_args(args, kwargs, ("test_func return: a, 5, 8", "a", 5, 8), {}, return_value = "return func of test_func hooked")) is not None
    ret_value = test_func("a", 5, 8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return func of test_func hooked"
    reset_test_vars()

    # Unset return hook
    assert test_func.onReturn(None) is not None
    ret_value = test_func("a", 5, 8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_func return: a, 5, 8"
    reset_test_vars()

    # Unset call hook
    assert test_func.onCall(None) is not None
    ret_value = test_func("a", 9, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_func return: a, 9, 8"
    reset_test_vars()

# Add hook to non-hooked class function
    TestClass.test_method = FunctionHook(TestClass.test_method)
    assert isinstance(tcls.test_method, FunctionHook) == True
    assert hasattr(tcls.test_method, 'onCall')        == True
    assert hasattr(tcls.test_method, 'onReturn')      == True

    ret_value = tcls.test_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_method return: 'a', 5, 8"
    reset_test_vars()

    # Set call hook
    assert tcls.test_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 120, "'2nd arg'"), {'c' : 0.05895})) is None
    ret_value = tcls.test_method(120, "'2nd arg'", c=0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    assert tcls.test_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 120, "'2nd arg'", 0.05895), {})) is not None
    ret_value = tcls.test_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook
    assert tcls.test_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_method return: 120, '2nd arg', 0.05895", tcls, 120, "'2nd arg'", 0.05895), {}, return_value = args[0])) is None
    ret_value = tcls.test_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "test_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook with changed return value
    assert tcls.test_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_method return: 120, '2nd arg', 0.05895", tcls, 120, "'2nd arg'", 0.05895), {}, return_value = "return of the Hook")) is not None
    ret_value = tcls.test_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Unset return hook
    assert tcls.test_method.onReturn(None) is not None
    ret_value = tcls.test_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Unset call hook
    assert tcls.test_method.onCall(None) is not None
    ret_value = tcls.test_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_method return: 'a', 5, 8"
    reset_test_vars()

# Add hook to non-hooked classmethod
    TestClass.test_classmethod = FunctionHook(TestClass.test_classmethod)
    ret_value = tcls.test_classmethod("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_classmethod return: 'a', 5, 8"
    reset_test_vars()

    # Set call hook
    assert tcls.test_classmethod.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (TestClass, 120, "'2nd arg'"), {'c' : 0.05895})) is None
    ret_value = tcls.test_classmethod(120, "'2nd arg'", c=0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    assert tcls.test_classmethod.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (TestClass, 120, "'2nd arg'", 0.05895), {})) is not None
    ret_value = tcls.test_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook
    assert tcls.test_classmethod.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_classmethod return: 120, '2nd arg', 0.05895", TestClass, 120, "'2nd arg'", 0.05895), {}, return_value = args[0])) is None
    ret_value = tcls.test_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "test_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook with changed return value
    assert tcls.test_classmethod.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_classmethod return: 120, '2nd arg', 0.05895", TestClass, 120, "'2nd arg'", 0.05895), {}, return_value = "return of the Hook")) is not None
    ret_value = tcls.test_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Test class type has hooks on classmethod
    ret_value = TestClass.test_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Unset return hook
    assert tcls.test_classmethod.onReturn(None) is not None
    ret_value = tcls.test_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Unset call hook
    assert tcls.test_classmethod.onCall(None) is not None
    ret_value = tcls.test_classmethod("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_classmethod return: 'a', 5, 8"
    reset_test_vars()

# Test class hooked classmethod without object instance
    ret_value = TestClass.test_classmethod("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_classmethod return: 'a', 5, 8"
    reset_test_vars()

    # Set call hook
    assert TestClass.test_classmethod.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (TestClass, 120, "'2nd arg'"), {'c' : 0.05895})) is None
    ret_value = TestClass.test_classmethod(120, "'2nd arg'", c=0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    assert TestClass.test_classmethod.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (TestClass, 120, "'2nd arg'", 0.05895), {})) is not None
    ret_value = TestClass.test_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook
    assert TestClass.test_classmethod.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_classmethod return: 120, '2nd arg', 0.05895", TestClass, 120, "'2nd arg'", 0.05895), {}, return_value = args[0])) is None
    ret_value = TestClass.test_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "test_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook with changed return value
    assert TestClass.test_classmethod.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_classmethod return: 120, '2nd arg', 0.05895", TestClass, 120, "'2nd arg'", 0.05895), {}, return_value = "return of the Hook")) is not None
    ret_value = TestClass.test_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Test class instance has hooks on classmethod
    ret_value = tcls.test_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Unset return hook
    assert TestClass.test_classmethod.onReturn(None) is not None
    ret_value = TestClass.test_classmethod(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_classmethod return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Unset call hook
    assert TestClass.test_classmethod.onCall(None) is not None
    ret_value = TestClass.test_classmethod("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_classmethod return: 'a', 5, 8"
    reset_test_vars()

# Add hook to non-hooked static method
    TestClass.test_static_method = FunctionHook(staticmethod(TestClass.test_static_method))
    ret_value = tcls.test_static_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_static_method return: 'a', 5, 8"
    reset_test_vars()

    # Set call hook
    assert tcls.test_static_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (120, "'2nd arg'"), {'c' : 0.05895})) is None
    ret_value = tcls.test_static_method(120, "'2nd arg'", c=0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    assert tcls.test_static_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (120, "'2nd arg'", 0.05895), {})) is not None
    ret_value = tcls.test_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook
    assert tcls.test_static_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_static_method return: 120, '2nd arg', 0.05895", 120, "'2nd arg'", 0.05895), {}, return_value = args[0])) is None
    ret_value = tcls.test_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "test_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook with changed return value
    assert tcls.test_static_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_static_method return: 120, '2nd arg', 0.05895", 120, "'2nd arg'", 0.05895), {}, return_value = "return of the Hook")) is not None
    ret_value = tcls.test_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Test class type has also set hook on static methods
    ret_value = TestClass.test_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Unset return hook
    assert tcls.test_static_method.onReturn(None) is not None
    ret_value = tcls.test_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Unset call hook
    assert tcls.test_static_method.onCall(None) is not None
    ret_value = tcls.test_static_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_static_method return: 'a', 5, 8"
    reset_test_vars()

# Test class hooked static method without object instance
    ret_value = TestClass.test_static_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_static_method return: 'a', 5, 8"
    reset_test_vars()

    # Set call hook
    assert TestClass.test_static_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (120, "'2nd arg'"), {'c' : 0.05895})) is None
    ret_value = TestClass.test_static_method(120, "'2nd arg'", c=0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    assert TestClass.test_static_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (120, "'2nd arg'", 0.05895), {})) is not None
    ret_value = TestClass.test_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook
    assert TestClass.test_static_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_static_method return: 120, '2nd arg', 0.05895", 120, "'2nd arg'", 0.05895), {}, return_value = args[0])) is None
    ret_value = TestClass.test_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "test_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Set return hook with changed return value
    assert TestClass.test_static_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_static_method return: 120, '2nd arg', 0.05895", 120, "'2nd arg'", 0.05895), {}, return_value = "return of the Hook")) is not None
    ret_value = TestClass.test_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Test class instance has also set hook on static methods
    ret_value = tcls.test_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "return of the Hook"
    reset_test_vars()

    # Unset return hook
    assert TestClass.test_static_method.onReturn(None) is not None
    ret_value = TestClass.test_static_method(120, "'2nd arg'", 0.05895)
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_static_method return: 120, '2nd arg', 0.05895"
    reset_test_vars()

    # Unset call hook
    assert TestClass.test_static_method.onCall(None) is not None
    ret_value = TestClass.test_static_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_static_method return: 'a', 5, 8"
    reset_test_vars()

# Test overriding call args with empty dict obj and None does not raise an exception and does not override any arg
    tcls = TestClass()
    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 121, 0.88, "'c'"), {}, overridden_args={})) is None
    ret_value = tcls.test_hooked_method(121, 0.88, "'c'")
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 121, 0.88, 'c'"
    reset_test_vars()

    tcls = TestClass()
    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 121, 0.88, "'c'"), {}, overridden_args=None)) is None
    ret_value = tcls.test_hooked_method(121, 0.88, "'c'")
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 121, 0.88, 'c'"
    reset_test_vars()

# Test set-reset-set-reset hook
    assert tcls.test_hooked_method.onCall(None) is not None
    ret_value = tcls.test_hooked_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 'a', 5, 8"
    reset_test_vars()

    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, 121, 0.88, "'c'"), {})) is None
    ret_value = tcls.test_hooked_method(121, 0.88, "'c'")
    assert call_hook_invoked   == True
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 121, 0.88, 'c'"
    reset_test_vars()

    assert tcls.test_hooked_method.onCall(None) is not None
    ret_value = tcls.test_hooked_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 'a', 5, 8"
    reset_test_vars()

    assert tcls.test_hooked_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_method return: 'a', 5, 8", tcls, "'a'", 5, 8), {}, return_value = args[0])) is None
    ret_value = tcls.test_hooked_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == True
    assert ret_value           == "test_hooked_method return: 'a', 5, 8"
    reset_test_vars()

    assert tcls.test_hooked_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_method return: 'a', 5, 8", tcls, "'a'", 5, 8), {}, return_value = "Return of the captain Hook")) is not None
    ret_value = tcls.test_hooked_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == True
    assert ret_value           == "Return of the captain Hook"
    reset_test_vars()

    assert tcls.test_hooked_method.onReturn(None) is not None
    ret_value = tcls.test_hooked_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 'a', 5, 8"
    reset_test_vars()

    assert tcls.test_hooked_method.onCall(lambda *args, **kwargs: \
        check_call_hook_args(args, kwargs, (tcls, "'a'", 5, 8), {})) is None
    assert tcls.test_hooked_method.onReturn(lambda *args, **kwargs:\
        check_return_hook_args(args, kwargs, \
            ("test_hooked_method return: 'a', 5, 8", tcls, "'a'", 5, 8), {}, return_value = "Return of the captain Hook")) is None
    ret_value = tcls.test_hooked_method("'a'", 5, 8)
    assert call_hook_invoked   == True
    assert return_hook_invoked == True
    assert ret_value           == "Return of the captain Hook"
    reset_test_vars()

    assert tcls.test_hooked_method.onCall(None) is not None
    assert tcls.test_hooked_method.onReturn(None) is not None
    ret_value = tcls.test_hooked_method("'a'", 5, 8)
    assert call_hook_invoked   == False
    assert return_hook_invoked == False
    assert ret_value           == "test_hooked_method return: 'a', 5, 8"
    reset_test_vars()

# Fuzz tests
    with pytest.raises(ValueError, match='Can hook only on function, class function, staticmethod or classmethod'):
        FunctionHook(1)

    with pytest.raises(ValueError, match='Can hook only on function, class function, staticmethod or classmethod'):
        FunctionHook("")

    with pytest.raises(ValueError, match='Can hook only on function, class function, staticmethod or classmethod'):
        FunctionHook("test_str")

    with pytest.raises(ValueError, match='Can hook only on function, class function, staticmethod or classmethod'):
        FunctionHook(b'')

    with pytest.raises(ValueError, match='Can hook only on function, class function, staticmethod or classmethod'):
        FunctionHook(bytes.fromhex('AABBCCDD'))

    with pytest.raises(ValueError, match='Can hook only on function, class function, staticmethod or classmethod'):
        FunctionHook(None)

    with pytest.raises(ValueError, match='Can hook only on function, class function, staticmethod or classmethod'):
        FunctionHook(tcls1)

    with pytest.raises(ValueError, match="'1' is not function"):
        tcls1.test_hooked_method.onCall(1)

    with pytest.raises(ValueError, match="'''' is not function"):
        tcls1.test_hooked_method.onCall("")

    with pytest.raises(ValueError, match="''test'' is not function"):
        tcls1.test_hooked_method.onCall("test")

    with pytest.raises(ValueError, match="'b''' is not function"):
        tcls1.test_hooked_method.onCall(b'')

    with pytest.raises(ValueError, match=escape(f"'{repr(tcls1)}' is not function")):
        tcls1.test_hooked_method.onCall(tcls1)

    with pytest.raises(ValueError, match="'1' is not function"):
        tcls1.test_hooked_method.onReturn(1)

    with pytest.raises(ValueError, match="'''' is not function"):
        tcls1.test_hooked_method.onReturn("")

    with pytest.raises(ValueError, match="''test'' is not function"):
        tcls1.test_hooked_method.onReturn("test")

    with pytest.raises(ValueError, match="'b''' is not function"):
        tcls1.test_hooked_method.onReturn(b'')

    with pytest.raises(ValueError, match=f"'{repr(tcls1)}' is not function"):
        tcls1.test_hooked_method.onReturn(tcls1)

    # Override call arguments with invalid arguments:
    with pytest.raises(ValueError, match=escape("Invalid overridden call arg(s): {'invalid_arg1': 5}")):
        tcls1.test_hooked_method.onCall(lambda *args, **kwargs: {'invalid_arg1' : 5})
        tcls1.test_hooked_method(a=1, b=2, c=3)

    with pytest.raises(ValueError, match=escape("Invalid overridden call arg(s): {'invalid_arg1': 5}")):
        tcls1.test_hooked_method.onCall(lambda *args, **kwargs: {'a' : 8, 'b' : 'overridden_2nd', 'c' : 0.885, 'invalid_arg1' : 5})
        tcls1.test_hooked_method(a=1, b=2, c=3)

    with pytest.raises(ValueError, match=escape("Invalid overridden call arg(s): {'invalid_arg1': 5, 'invalid_arg2': \"'invalid2'\", 'invalid_arg3': 0.55}")):
        tcls1.test_hooked_method.onCall(lambda *args, **kwargs: {'invalid_arg1' : 5, 'invalid_arg2' : "'invalid2'", 'invalid_arg3' : 0.55})
        tcls1.test_hooked_method(a=1, b=2, c=3)

    with pytest.raises(ValueError, match=escape("Invalid overridden call arg(s): {'invalid_arg1': 5, 'invalid_arg2': \"'invalid2'\", 'invalid_arg3': 0.55}")):
        tcls1.test_hooked_method.onCall(lambda *args, **kwargs: {'a' : 8, 'b' : 'overridden_2nd', 'c' : 0.885, 'invalid_arg1' : 5, 'invalid_arg2' : "'invalid2'", 'invalid_arg3' : 0.55})
        tcls1.test_hooked_method(a=1, b=2, c=3)
