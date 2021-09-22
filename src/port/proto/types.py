from __future__ import annotations
import base64
import os
from asn1crypto.x509 import Name
from cryptography.hazmat.primitives.hashes import Hash, SHA512_256
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from inspect import getfullargspec, isclass, ismethod
from pymrtd import ef
from pymrtd.pki import x509
from typing import Any, Callable, Final, NoReturn, Optional, TypeVar, cast, Union, final

from .utils import bytes_to_int, format_alpha2, int_count_bytes, int_to_bytes, sha512_256

class CountryCode(str):
    """
    Class represents ISO-3166 Alpha-2 country code
    """
    def __new__(cls, content):
        return super().__new__(cls, format_alpha2(content) if content is not None else None)

class IIntegerId(int):
    """
    Class represents fixed size integer ID.
    """

    min:int
    max:int

    _byteSize:int = None

    def __new__(cls, idValue: Union[int, bytes, str], *args, **kwargs): #pylint: disable=unused-argument
        """
        Bytes and hex string representation of ID has to be padded to the required `byteSize` size.
        """
        if isinstance(idValue, int):
            if not (cls.min <= idValue <= cls.max): #pylint: disable=superfluous-parens
                raise ValueError(f'integer out of range to construct {cls.__name__}. id_value={idValue}')
        elif isinstance(idValue, bytes):
            if len(idValue) != cls.byteSize():
                raise ValueError(f'invalid byte array size to construct {cls.__name__}')
            idValue = bytes_to_int(idValue, signed=True)
            return cls(idValue)
        elif isinstance(idValue, str):
            if len(args) > 0 and args[0] == 16:
                return cls.fromHex(idValue)
            idValue = int(idValue, *args)
            return cls(idValue)
        else:
            raise ValueError(f'invalid type to construct {cls.__name__}. id_type={type(idValue)}')
        return cast(cls, super().__new__(cls, idValue))

    @classmethod
    def byteSize(cls) -> int:
        """
        Returns the size of ID integer when encoded to bytes.
        """
        if cls._byteSize is None:
            mn = max(abs(cls.min), abs(cls.max))
            nb = int_count_bytes(mn)
            cls._byteSize = nb
        return cls._byteSize

    def toBytes(self):
        """
        Returns big-endian encoded bytes of self.
        """
        return int_to_bytes(self, signed=True, encodeLength=self.byteSize())

    @classmethod
    def fromHex(cls, hexstr: str):
        assert isinstance(hexstr, str)
        if len(hexstr) != (cls.byteSize() * 2):
            raise ValueError(f'invalid hex string size to construct {cls.__name__}')
        return cls(bytes.fromhex(hexstr))

    def hex(self):
        mn = max(abs(self.min), abs(self.max))
        nb = int_count_bytes(mn)
        return self.toBytes().hex().upper().rjust(nb * 2, '0')

class CertificateId(IIntegerId):
    """
    Represents x509.Certificate ID as uint64
    CertificateId is calculated by taking the first 8 bytes of SHA-512/256 hash
    over ASN.1 DER encoded bytes of x509.Certificate.tbs_certificate fields
    """

    min = -9223372036854775808 # min 64 bit int
    max = 9223372036854775807  # max 64 bit int

    @classmethod
    def fromCertificate(cls, crt: x509.Certificate) -> "CertificateId":
        """
        Returns `CertificateId` generated from SHA512-256(`crt`.tbs_certificate).
        Note, the reason for calculating ID from TBS certificate is to get the same ID
        when certificate signature is different but TBS certificates are the same.
        :param `crt`: X509 certificate to generate the `CertificateId` from.
        :return: New `CertificateId` object from `crt`.
        """
        assert isinstance(crt, x509.Certificate)
        return cls(sha512_256(crt['tbs_certificate'].dump())[0:8])

class CrlId(IIntegerId):
    """
    CrlId represents unique ID of country CRL based on country code and issuer DN.
    i.e. sha512-256(country_code + issuer_dn)[0:8]
    """
    min = -9223372036854775808 # min 64 bit int
    max = 9223372036854775807  # max 64 bit int

    @classmethod
    def fromCountryCodeAndIssuer(cls, country: CountryCode, issuer: str) -> "CrlId":
        assert isinstance(country, CountryCode)
        assert isinstance(issuer, str)
        h = sha512_256((country + issuer).encode('utf-8'))
        return cls(h[0:8])

    @classmethod
    def fromCrlIssuer(cls, issuer: Name) -> "CrlId":
        assert isinstance(issuer, Name)
        c = CountryCode(issuer.native['country_name'])
        i = issuer.human_friendly
        return CrlId.fromCountryCodeAndIssuer(c, i)

class SodId(IIntegerId):
    """
    Represents ef.SOD ID as uint64.
    SodId is calculated by taking the first 8 bytes of SHA-512/256 hash
    over ASN.1 DER encoded bytes of EF.SOD.ldsSecurityObject.
    """

    min = -9223372036854775808 # min 64 bit int
    max = 9223372036854775807  # max 64 bit int

    @classmethod
    def fromSOD(cls, sod: ef.SOD) -> "SodId":
        """
        Generates SodId from `sod`.
        The SodId is generated from SHA-512/256 hash of
        ASN.1 DER encoded bytes of EF.SOD.ldsSecurityObject.
        Going this way should produce exact same SodId for 2 EF.SODs
        with equal LdsSecurityObject content but different or altered signers.
        This prevents EF.SOD registration melability.

        :param sod: The EF.SOD to generate SodId.
        :return: SodId of `sod`.
        """
        assert isinstance(sod, ef.SOD)
        return cls(sha512_256(sod.ldsSecurityObject.dump())[0:8])

class UserIdError(Exception):
    pass

class UserId(bytes):
    """
    Represents account user ID.
    User ID can be UTF-8 string or `bytes`.
    Internally UserId is represented as `bytes`.
    Max user ID size is 20 bytes.
    """

    max_size: int = 20

    def __new__(cls, userId: Union[bytes, str]) -> "UserId":
        if isinstance(userId, str):
            userId = userId.encode("utf-8")
        if not isinstance(userId, bytes) \
            or len(userId) < 1 \
            or len(userId) > UserId.max_size:
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
            return self.hex().upper().rjust(2, '0')

    def __repr__ (self) -> str:
        return f'UserId({self!s})'

class CID(IIntegerId):
    """ Represents challenge id """
    min = -2147483648
    max = 2147483647

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
        raise ChallengeError("Invalid challenge type")

    @property
    def id(self) -> CID:
        if not hasattr(self, "_id"):
            self._id = CID(self[0:4]) #pylint: disable=attribute-defined-outside-init
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

@final
class FunctionHook:
    """
    Wrapper class which hooks on function call and function return.
    To set function call hook use `onCall` method.
    To set function return hook use `onReturn` method.

    e.g.:
    ```
       def some_func(x, y, z) -> int:
           return 1

       fh = FunctionHook(some_func)
       fh.onCall(lambda *args, *kwargs: print("calling some_func with args: ", *args, *kwargs))
       fh.onReturn(lambda ret: print("some_func returned: ", ret))
       fh("a", 5, 8)
       # Should print
       # "calling some_func with args: a, 5, 8"
       # "some_func returned: 1"
    ```
    """

    _hooked_func: Callable
    __storage_prefix_name: Final   = f'__{__module__}.__func_hook_.'
    __call_hf_tag: Final[str]   = '__call_hf__'
    __return_hf_tag: Final[str] = '__return_hf__'

    def onCall(self, func: Callable) -> Optional[Callable]:
        """
        Function call hook.
        :param `func`: The function called prior to call hooked function.
                       Pass None to unset call hook.

                       The `func` function signature:

                            - function hook: `(args_of_hooked_function) -> Optional[dict]`

                            - class function hook: `(class_instance, args_of_hooked_function) -> Optional[dict]`

                            - classmethod hook: `(class_type, args_of_hooked_function) -> Optional[dict]`

                            - static class function hook: `(args_of_hooked_function) -> Optional[dict]`

                       The `func` optional return dictionary is the kwargs of overridden call arguments.
                       e.g.:
                       ```
                           def f(a, b, c)
                           f.onCall(lambda *args, *kwargs: {'a' : 5})
                           f(1, 2, 3) <- the param 'a' (1st param) will be overridden with value 5 and passed to hooked function.
                       ```

        :return: Previous hook function or None.
        :raises `ValueError`: If `func` is not callable or None.
        """
        return self._set_hook_func(self.__call_hf_tag, func)

    def onReturn(self, func: Callable) -> Optional[Callable]:
        """
        Function return hook.
        Note, the `func` object is responsible for returning value.
        :param `func`: The function to call after hooked function returns.
                       Pass None to unset return hook.

                       The `func` function signature:

                            - function hook: `(hooked_function_return_value, args_of_hooked_function) -> None`

                            - class method hook: `(hooked_function_return_value, class_instance, args_of_hooked_function) -> None`

        :return: Previous hook function or None.
        :raises `ValueError`: If `func` is not callable or None.
        """
        return self._set_hook_func(self.__return_hf_tag, func)

    def __init__(self, func: TypeVar("T", Callable, staticmethod)) -> None:
        """
        Creates new `FunctionHook` wrapper for `func` function.
        :param `func`: A function, class function, class static function or classmethod.
        :raises `ValueError`: If `func` is not callable function.
        """
        if not callable(func) \
            and not isinstance(func, (classmethod, staticmethod)):
            raise ValueError("Can hook only on function, class function, staticmethod or classmethod")
        self._hooked_func = func

    def _get_hooked_function_name(self):
        if isinstance(self._hooked_func, (classmethod, staticmethod)):
            return self._hooked_func.__func__.__name__
        return self._hooked_func.__name__

    def _get_storage_key(self, name):
        return FunctionHook.__storage_prefix_name + \
               self._get_hooked_function_name() + name

    def __get__(self, obj, obj_type):
        func = self._hooked_func.__get__(obj, obj_type)
        #TODO: Try to cache new instance
        return self.__class__(func)

    def _get_hook_func(self, name: str):
        return self._get_hook_storage() \
            .get(self._get_storage_key(name))

    def _set_hook_func(self, name: str, func: Callable) -> Optional[Callable]:
        if func is not None and not callable(func):
            raise ValueError(f"'{repr(func)}' is not function")
        name = self._get_storage_key(name)
        s    = self._get_hook_storage()
        old_hook = s.get(name)
        s[name] = func
        return old_hook

    def _get_self_obj_of_hooked_function(self) -> Optional[Any]:
        return getattr(self._hooked_func, '__self__', None)

    def _get_hook_storage(self) -> dict:
        obj = self._get_self_obj_of_hooked_function()
        if obj and not isclass(obj): # if object is instantaned and not class type
            return obj.__dict__
        return self._hooked_func.__dict__

    def _on_call(self, *args: Any, **kwds: Any) -> Optional[dict]:
        r = self._call_hook(self.__call_hf_tag, NoReturn, *args, **kwds)
        return r if r is not NoReturn else None

    def _on_return(self, ret: Any, *args: Any, **kwds: Any):
        return self._call_hook(self.__return_hf_tag, ret, *args, **kwds)

    def _call_hook(self, fname: str, ret: Union[Any, NoReturn], *args: Any, **kwds: Any):
        func = self._get_hook_func(fname)
        if func:
            o = self._get_self_obj_of_hooked_function()
            if o:
                # Prepend class instance or class type (classmethod) to the args
                args = (o, *args)
            if ret is not NoReturn:
                args = (ret, *args)
            ret = func(*args, **kwds)
        return ret

    def _merge_args(self, new_args: Optional[dict], *args, **kwds) -> tuple(tuple, dict): # returns (*args, **kwargs)
        if isinstance(new_args, dict) and new_args:
            fargs = getfullargspec(self._hooked_func)[0]
            if ismethod(self._hooked_func):
                fargs = fargs[1:]

            largs = list(args)
            for idx, p in enumerate(fargs):
                if p in new_args:
                    if idx < len(largs):
                        largs[idx] = new_args.pop(p)
                    else:
                        kwds[p] = new_args.pop(p)
            if len(new_args):
                raise ValueError(f"Invalid overridden call arg(s): {new_args}")
        return (tuple(largs), kwds)

    def __call__(self, *args: Any, **kwds: Any) -> Any:
        new_args = self._on_call(*args, **kwds)
        if new_args:
            args, kwds = self._merge_args(new_args, *args, **kwds)
        fret = self._hooked_func(*args, **kwds)
        return self._on_return(fret, *args, **kwds)

def hook(func: Callable) -> FunctionHook:
    """
    The function decorator which wraps `func` in `FunctionHook` instance.
    :param `func`: The function to hook on.
    :return: `FunctionHook` object.

    e.g.:
    ```
       @hook
       def some_func(x, y, z) -> int:
           return 1

       some_func.onCall(lambda *args, *kwargs: print("calling some_func with args: ", *args, *kwargs))
       some_func.onReturn(lambda ret: print("some_func returned: ", ret))
       some_func("a", 5, 8)
       # Should print
       # "calling some_func with args: a, 5, 8"
       # "some_func returned: 1"
    ```
    """
    return FunctionHook(func)
