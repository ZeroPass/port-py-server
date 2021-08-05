import base64
from typing import cast

class UserIdError(Exception):
    pass

class UserId(bytes):
    """ Represents accounts userId"""

    max_size: int = 20

    def __new__(cls, userId: bytes) -> "UserId":
        if not isinstance(userId, bytes) or \
            len(userId) > UserId.max_size:
            raise UserIdError("Invalid userId data")
        return cast(UserId, super().__new__(cls, userId))  # type: ignore  # https://github.com/python/typeshed/issues/2630  # noqa: E501

    @staticmethod
    def fromBase64(b64Str: str) -> "UserId":
        assert isinstance(b64Str, str)
        return UserId(base64.b64decode(b64Str))

    def toBase64(self):
        return str(base64.b64encode(self), 'ascii')

    def __str__(self) -> str:
        try:
            return self.decode("utf-8")
        except: #pylint: disable=bare-except
            return self.hex()

    def __repr__ (self) -> str:
        return "UserId({!s})".format(self)
