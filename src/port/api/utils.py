from base64 import b64decode
from logging import Logger
from port.proto import PeInvalidOrMissingParam
from typing import Final, List, Optional

SUCCESS: Final = 'success'

def try_deserialize(f, errorLog: Optional[Logger] = None):
    try:
        return f()
    except Exception as e:
        if errorLog:
            errorLog.error("An error has occurred while deserializing data: %s", e)
        raise PeInvalidOrMissingParam("Bad parameter") from None

def try_deserialize_csig(str_csigs: List[str], errorLog: Optional[Logger] = None) -> List[bytes]:
    """ Convert list of base64 encoded signatures to list of byte signatures """
    csigs = []
    for scsig in str_csigs:
        csigs.append(try_deserialize(lambda sig=scsig: b64decode(sig), errorLog))
    return csigs

def get_invalid_func_param_msg(e: TypeError) -> Optional[str]:
    msg = str(e)
    if 'got an unexpected keyword argument' in msg or \
       'positional arguments but' in msg or \
       'required positional argument:' in msg:
        return msg.split(' ', 1)[1]
