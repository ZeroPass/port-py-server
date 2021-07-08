from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import Hash, SHA512_256
import pycountry
from datetime import datetime
from pymrtd.pki.x509 import Certificate

def time_now():
    return datetime.utcnow()

def has_expired(t1: datetime, t2: datetime):
    return t1 < t2

def format_cert_et(cert: Certificate, current_time: datetime = time_now()):
    return "nvb=[{}] nva=[{}] now=[{}]".format(cert.notValidBefore, cert.notValidAfter, current_time)

def code_to_country_name(code: str):
    assert isinstance(code, str)
    code = code.upper()
    if len(code) == 2:
        c = pycountry.countries.get(alpha_2=code)
    else:
        c = pycountry.countries.get(alpha_3=code)
    if c is None:
        return code
    return c.name

def int_count_bytes(n: int):
    ibytes = 0
    while n:
        ibytes += 1
        n >>= 8
    return ibytes

def format_alpha2(code: str):
    """
    Formats the ISO-3166 Alpha-2 country code for storing in database.
    It follows mrtd spec 9303 p3.
    @see https://www.icao.int/publications/Documents/9303_p3_cons_en.pdf

    :param code: - 2 upper case letter.
    :raises: ValueError if code is not exact 2 chars
    """
    if len(code) != 2:
        raise ValueError("Invalid ISO-3166 Alpha-2 country code: " + code)
    return code.upper()

def format_alpha3(code: str):
    """
    Formats the ISO-3166 Alpha-3 country code for storing in database.
    It follows mrtd spec 9303 p3.
    @see https://www.icao.int/publications/Documents/9303_p3_cons_en.pdf

    :param code: - 3 upper case letter with exception to Germany as single 'D' is allowed.
    :raises: ValueError if code is not exact 3 chars or 'D' for Germany.
    """
    code = code.upper()
    if len(code) != 3 and code != 'D':
        raise ValueError("Invalid ISO-3166 Alpha-3 country code: " + code)
    return code

def int_to_bytes(num: int, signed: bool = True) -> bytes:
    """
    Encodes integer num to big-endian bytes.
    :param num: The number to encode
    :param signed: The signed argument determines whether two's complement is used to represent the integer.
    :returns: Big-endian encoded bytes.
    """
    # https://stackoverflow.com/questions/21017698/converting-int-to-bytes-in-python-3/54141411#54141411
    length = ((num + ((num * signed) < 0)).bit_length() + 7 + signed) // 8
    return num.to_bytes(length, byteorder='big', signed=signed)

def bytes_to_int(data: bytes, signed: bool = True) -> int:
    """
    Decodes big-endian integer from bytes.
    :param data: The byte data decode the integer number from.
    :param signed: The signed argument indicates whether two's complement is used to represent the integer.
    :returns: Decoded integer number.
    """
    return int.from_bytes(data, byteorder='big', signed=signed)


def sha512_256(data: bytes) -> bytes:
    """
    Returns hash of SHA-512/256.
    :param data: data to hash.
    :return: hash in bytes
    """
    h = Hash(SHA512_256(), backend=default_backend())
    h.update(data)
    return h.finalize()
