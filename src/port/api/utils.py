from base64 import b64decode
from port.proto import PeInvalidOrMissingParam
from typing import List

def try_deserialize(f):
    try:
        return f()
    except:
        raise PeInvalidOrMissingParam("Bad parameter") from None

def try_deserialize_csig(str_csigs: List[str]) -> List[bytes]:
    """ Convert list of base64 encoded signatures to list of byte signatures """
    csigs = []
    for scsig in str_csigs:
        csigs.append(try_deserialize(lambda sig=scsig: b64decode(sig)))
    return csigs
