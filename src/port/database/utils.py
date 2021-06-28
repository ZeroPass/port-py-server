def formatAlpha2(code: str):
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

def formatAlpha3(code: str):
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