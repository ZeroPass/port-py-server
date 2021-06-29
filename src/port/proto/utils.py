import pycountry
from datetime import datetime
from pymrtd.pki.x509 import Certificate

def time_now():
    return datetime.utcnow()

def has_expired(t1: datetime, t2: datetime):
    return t1 < t2

def format_cert_et(cert: Certificate, current_time: datetime = time_now()):
    """ """
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
    bytes = 0
    while(n):
        bytes += 1
        n >>= 8
    return bytes

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