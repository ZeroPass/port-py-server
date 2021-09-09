import ssl
import collections
import inspect
from dataclasses import asdict, dataclass, fields, is_dataclass, MISSING
from pathlib import Path
from port import log
from port.database import DatabaseDialect
from typing import Any, Final, get_type_hints, Optional

def _issubclass_safe(cls, cls_type):
    try:
        return issubclass(cls, cls_type)
    except Exception:
        return False

def _isinstance_safe(obj, cls_type):
    try:
        return isinstance(obj, cls_type)
    except Exception:
        return False

def _is_optional(cls):
    if hasattr(cls, '__args__') and len(cls.__args__) == 2 \
        and cls.__args__[1] is type(None):
        return True
    return False

def _get_optional_type(cls):
    if _is_optional(cls):
        return cls.__args__[0]
    return cls

@dataclass
class IConfig:
    def toJson(self) -> dict[str, Any]:
        def fix_values(di: dict[str, Any]):
            rmv = []
            for k,v in di.items():
                if v is None:
                    rmv.append(k)
                elif isinstance(v, dict):
                    di[k] = fix_values(v)
                elif isinstance(v, Path):
                    di[k] = str(v)
            for k in rmv:
                del di[k]
            return di
        return fix_values(asdict(self))

    @classmethod
    def fromJson(cls, json: dict[str, Any], inferMissing = True, strict: bool = True):
        """
        Constructs new `cls` from JSON dictionary.
        Note, the optional fields should be margked with `typing.Optional` type hint.

        :param `cls`: The `IConfig` type to construct the new config object from.
        :param `json`: JSON dictionary to construct new `cls` object from.
        :param `inferMissing`: Auto add missing `cls` fields that are missing in `json` dictionary. Only for optional fields.
        :param `strict`: If True function requires that all fields in `json` belongs to `cls`.
        :return: New `cls` object.
        :raises `ValueError`: If `strict=True` and parser encounters field that is not part of `cls`.
        :raises `ValueError`: If `None` value is encountered for non-optional field.
        :raises `ValueError`: If the field value type differs the field type.
        """
        json = {} if json is None and inferMissing else json
        clsFields = {field.name : field for field in fields(cls)}
        for f in json.keys():
            if strict and f not in clsFields:
                raise ValueError(f"Parameter '{f}' not part of {cls.__name__}")
        missing_fields = {field for field in clsFields.values() if field.name not in json}

        for field in missing_fields:
            if field.default is not MISSING:
                json[field.name] = field.default
            elif field.default_factory is not MISSING:
                json[field.name] = field.default_factory()
            elif inferMissing:
                json[field.name] = None

        initKwargs = {}
        types = get_type_hints(cls)
        for field in clsFields.values():
            # Skip field since it doesn't have constructor function
            if not field.init:
                continue

            fvalue = json[field.name]
            ftype  = types[field.name]
            if fvalue is None:
                if not _is_optional(ftype):
                    raise ValueError(f"Expected value for non-optional parameter '{cls.__name__}.{field.name}'")
                continue

            while True:
                if not (inspect.isfunction(ftype) \
                    and hasattr(ftype, "__supertype__")):
                    break
                ftype = ftype.__supertype__

            ftype = _get_optional_type(ftype)
            if _issubclass_safe(ftype, IConfig):
                if not isinstance(fvalue, IConfig):
                    fvalue = ftype.fromJson(fvalue, inferMissing)
                initKwargs[field.name] = fvalue
            elif _isinstance_safe(fvalue, ftype):
                initKwargs[field.name] = fvalue
            elif _isinstance_safe(fvalue, str) and _issubclass_safe(ftype, Path):
                initKwargs[field.name] = Path(fvalue)
            else:
                raise ValueError(f"Expected {cls.__name__}.{field.name} parameter value of type '{ftype.__name__}' got '{type(fvalue).__name__}'")

        return cls(**initKwargs)

class DbDialectValidator:
    __name__ = getattr(str, '__name__') # Fake the name, so ArgumentParser shows error msg: '.. invalid str value..'

    def __call__(self, dialect: str) -> str:
        '''
        Validates `dialect` begins with valid database dialect value.
        i.e.: 'mdb' or any of the enumerator values of `DatabaseDialect`.

        Expected `dialect` string is in format that is specified by SQLAlchemy.
        i.e.: '<dialect_name>[+optional_db_api_driver]'

        Function doesn't validate DB API driver(e.g. +pymysql, +psycopg2)

        :param `dialect` : Database dialect.
        :return: `dialect`
        :raises `ValueError`: If `dialect` is not valid.
        '''
        for e in ['mdb', *DatabaseDialect]: # pylint: disable=not-an-iterable
            v = e if type(e) is str else e.value
            if dialect.startswith(v):
                return dialect
        raise ValueError(f'Unsupported database dialect: {dialect}')

_levelToLogLevel: Final = {
    'verbose'  : log.getLevelName(log.VERBOSE),
    'debug'    : log.getLevelName(log.DEBUG),
    'info'     : log.getLevelName(log.INFO),
    'warning'  : log.getLevelName(log.WARNING),
    'error'    : log.getLevelName(log.ERROR),
    'critical' : log.getLevelName(log.CRITICAL)
}

class LogLevelValidator:
    __name__ = getattr(str, '__name__') # Fake the name, so ArgumentParser shows error msg: '.. invalid str value..'

    def __call__(self, level: str) -> str:
        """
        Converts `level` to value in _levelToLogLevel.
        :raises `ValueError`: If `dialect` is not valid.
        """
        l = _levelToLogLevel.get(level.lower())
        if l is None:
            raise ValueError(f'Unsupported log level: {level}')
        return l

@dataclass
class DbConfig(IConfig):
    def _setdialect(self, value: str):
        self.__dict__["dialect"] = DbDialectValidator()(value)
    def _getdialect(self) -> str:
        return self.__dict__.get("dialect")

    dialect: str  = property(_getdialect, _setdialect) # database dialect, e.g.: postgresql, mysql ...
    url: str      = ''
    name: str     = '' # database name
    user: str     = ''
    password: str = ''
    del _setdialect, _getdialect

@dataclass
class MrtdPkd(IConfig):
    path: Path
    allow_self_issued_csca: bool = True # allow selfsigned CSCA certificate when loading CSCAs from path

@dataclass
class HttpServerConfig(IConfig):
    host: str
    port: int
    timeout_keep_alive: int  = 10 # close 'Keep-Alive' connection after response if no data is received for n seconds
    log_level: Optional[str] = None
    tls_cert: Optional[Path] = None
    tls_key: Optional[Path]  = None

@dataclass
class ServerConfig(IConfig):
    database: DbConfig
    api: Optional[HttpServerConfig] = None
    challenge_ttl: int              = 600 # 10 minutes
    job_interval: int               = 3600  # 1 hour, an interval at which server does maintenance job and other tasks. (e.g.: delete expired proto challenges from DB)
    log_level: str                  = 'verbose'
    mrtd_pkd: Optional[MrtdPkd]     = None # MRTD certificate folder to load into database when server starts

