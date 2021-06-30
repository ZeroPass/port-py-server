import base64
import os

from .types import IIntegerId
from datetime import datetime
from cryptography.hazmat.primitives.hashes import Hash, SHA512_256
from cryptography.hazmat.backends import default_backend
from port.proto.utils import int_to_bytes
from typing import cast, Union

class CID(IIntegerId):
    """ Represents challenge id """
    min = -0xFFFFFFFF
    max = 0xFFFFFFFF

class ChallengeError(Exception):
    pass

class Challenge(bytes):
    """ Class generates and holds proto challenge """

    _hash_algo = SHA512_256

    def __new__(cls, challenge: bytes) -> "Challenge":
        if isinstance(challenge, bytes):
            if len(challenge) != cls._hash_algo.digest_size:
                raise ChallengeError("Invalid challenge length")
            return cast(Challenge, super().__new__(cls, challenge))  # type: ignore  # https://github.com/python/typeshed/issues/2630  # noqa: E501
        else:
            raise ChallengeError("Invalid challenge type")

    @property
    def id(self) -> CID:
        if not hasattr(self, "_id"):
            self._id = CID(self)
        return self._id

    @staticmethod
    def fromhex(hexStr: str) -> "Challenge":
        assert isinstance(hexStr, str)
        return Challenge(bytes.fromhex(hexStr))

    @staticmethod
    def fromBase64(b64Str: str) -> "Challenge":
        assert isinstance(b64Str, str)
        return Challenge(base64.b64decode(b64Str))

    def toBase64(self):
        return str(base64.b64encode(self), 'ascii')

    @staticmethod
    def generate(time: datetime, extraData: bytes) -> "Challenge":
        assert isinstance(time, datetime)
        ts = int_to_bytes(int(time.timestamp()))
        rs = os.urandom(Challenge._hash_algo.digest_size)

        h = Hash(Challenge._hash_algo(), backend=default_backend())
        h.update(ts)
        h.update(extraData)
        h.update(rs)
        return Challenge(h.finalize())