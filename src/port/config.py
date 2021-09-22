import argparse
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

_abbrev: Final = {
    'database' : 'db',
    'password' : 'pwd'
}

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
        return cls._buildFromJson(json, inferMissing, strict)

    @classmethod
    def _buildFromJson(cls, json: dict[str, Any], inferMissing, strict: bool, baseName = None):
        json = {} if json is None and inferMissing else json
        clsFields = {field.name : field for field in fields(cls)}
        for f in json.keys():
            if strict and f not in clsFields:
                raise ValueError(f"Parameter '{f}' is not part of {baseName or cls.__name__}")
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
                    raise ValueError(f"Expected value for non-optional parameter '{baseName + '-' if baseName else ''}{field.name}'")
                continue

            while True:
                if not (inspect.isfunction(ftype) \
                    and hasattr(ftype, "__supertype__")):
                    break
                ftype = ftype.__supertype__

            ftype = _get_optional_type(ftype)
            if _issubclass_safe(ftype, IConfig):
                if not isinstance(fvalue, IConfig):
                    fvalue = ftype._buildFromJson(fvalue, inferMissing, strict, baseName=field.name) # pylint: disable=protected-access
                initKwargs[field.name] = fvalue
            elif _isinstance_safe(fvalue, ftype):
                initKwargs[field.name] = fvalue
            elif _isinstance_safe(fvalue, str) and _issubclass_safe(ftype, Path):
                initKwargs[field.name] = Path(fvalue)
            else:
                raise ValueError(f"Expected {baseName + '-' if baseName else ''}{field.name} parameter value of type '{ftype.__name__}' got '{type(fvalue).__name__}'")

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
            v = e if isinstance(e, str) else e.value
            if dialect.startswith(v):
                return dialect
        raise ValueError(f'Unsupported database dialect: {dialect}')

_levelToLogLevel: Final = {
    'verbose'  : log.VERBOSE,
    'debug'    : log.DEBUG,
    'info'     : log.INFO,
    'warning'  : log.WARNING,
    'error'    : log.ERROR,
    'critical' : log.CRITICAL
}

class LogLevelValidator:
    """Converts string log level to int level"""
    __name__ = getattr(str, '__name__') # Fake the name, so ArgumentParser shows error msg: '.. invalid str value..'

    def __call__(self, level: str) -> int:
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
    api: Optional[HttpServerConfig]  = None
    papi: Optional[HttpServerConfig] = None
    challenge_ttl: int               = 600 # 10 minutes
    job_interval: int                = 3600  # 1 hour, an interval at which server does maintenance job and other tasks. (e.g.: delete expired proto challenges from DB)
    log_level: str                   = 'verbose'
    mrtd_pkd: Optional[MrtdPkd]      = None # MRTD certificate folder to load into database when server starts

    @classmethod
    def fromArgs(cls, args: argparse.Namespace, infer_missing = True, strict: bool = True):
        """
        Creates `cls` from parsed command-line arguments.
        Note: All string and `Path` config values that are equal to 'None' will be converted to `None`.
        :param `args`: The command-line arguments to create new `cls`.
        :param `inferMissing`: See `IConfig.fromJson`.
        :param `strict`: See `IConfig.fromJson`.
        :raises `ValueError`: If `strict=True` and parser encounters field that is not part of `cls`.
        :raises `ValueError`: If `None` value is encountered for non-optional field.
        :raises `ValueError`: If the field value type differs the field type.
        """
        jcfg = cls._argsToJson(args)
        return cls.fromJson(jcfg, inferMissing=infer_missing, strict=strict)

    def update(self, args: argparse.Namespace, infer_missing = True, strict: bool = True):
        """
        Overrides config with parsed command-line `args`.
        Note: All string and `Path` config values that are equal to 'None' will be converted to `None`.
        :param `args`: The command-line arguments to override config with.
        :param `inferMissing`: See `IConfig.fromJson`.
        :param `strict`: See `IConfig.fromJson`.
        :raises `ValueError`: If `strict=True` and parser encounters field that is not part of ServerConfig.
        :raises `ValueError`: If `None` value is encountered for non-optional field.
        :raises `ValueError`: If the field value type differs the field type.
        """
        jargs = {}
        jargs_dflt = {}
        # throw out default values, so they
        # don't override existing values
        for k, v in vars(args).items():
            if not isArgDefultValue(v):
                jargs[k] = v
            elif v is not None:
                jargs_dflt[k] = stripDefaultArgWrapper(v) #Strip-off _DefaultArg type

        args = argparse.Namespace(**jargs)
        jcfg = self.toJson()
        for k, v in type(self)._argsToJson(args).items():
            if isinstance(v, dict):
                if k not in jcfg:
                    jcfg[k] = {}
                jcfg[k] |= v
            else:
                jcfg[k] = v

        # Add default values for non-optional fields that are not set
        def setDefaultArgs(d, ddflt):
            for k, v in ddflt.items():
                if isinstance(v, dict):
                    if k not in d:
                        d[k] = {}
                        d[k] |= v
                    else:
                        d[k] |= setDefaultArgs(d[k],v)
                else:
                    if k not in d:
                        d[k] = v
            return d
        args = argparse.Namespace(**jargs_dflt)
        jcfg = setDefaultArgs(jcfg, type(self)._argsToJson(args))
        self.__dict__ = self.fromJson(jcfg, infer_missing, strict).__dict__

    @staticmethod
    def argumentParser(parser: argparse.ArgumentParser, dbDialectRequired=True) -> argparse.ArgumentParser:
        """
        Adds & formats cmd arguments of `ServerConfig` to the `parser`.
        :param `parser`: The `ArgumentParser` to add arguments to.
        :param `dbDialectRequired`: If True `--db-dialect` is required argument.
        :return: Updated parser.
        """

        class _KeepDfltStrWrapper(str):
            """Forces the argparser to use _DefaultArg instead of underlaying str type"""
            __name__ = getattr(str, '__name__')
            def __call__(self, v):
                return v

        # Database
        db = parser.add_argument_group('Database')
        dbcmdg = _abbrev.get('database', 'database')
        db.add_argument(f'--{dbcmdg}-dialect', type=DbDialectValidator(), required=dbDialectRequired,
            help='Database dialect with optional DB driver.\n  e.g.: mdb, mysql, postgresql, sqlite, sqlite+pysqlite etc...')

        db.add_argument(f'--{dbcmdg}-url', type=_KeepDfltStrWrapper(), default=defaultArg(DbConfig.url),
            help='Database URL. For SQLite it is the database file path')

        db.add_argument(f'--{dbcmdg}-name', type=_KeepDfltStrWrapper(), default=defaultArg(DbConfig.name),
            help='Database name.')

        db.add_argument(f'--{dbcmdg}-user', type=_KeepDfltStrWrapper(), default=defaultArg(DbConfig.user),
            help='Database user name.')

        pwd = _abbrev.get('password', 'password')
        db.add_argument(f'--{dbcmdg}-{pwd}', type=_KeepDfltStrWrapper(), default=defaultArg(DbConfig.password),
            help='Database password.')

        # Public API
        api = parser.add_argument_group('Public API server')
        api.add_argument('--api-host', type=_KeepDfltStrWrapper(), default=defaultArg('127.0.0.1'),
            help='Server listening host.')

        api.add_argument('--api-port', type=int, default=defaultArg(8080),
            help='Server listening port.')

        api.add_argument('--api-timeout-keep-alive', type=int, default=defaultArg(HttpServerConfig.timeout_keep_alive),
            help="Close 'Keep-Alive' connections if no new data\nis received within this timeout.")

        api.add_argument('--api-tls-cert', type=Path,
            help='A path to the TLS certificate file to use for secure connection.')

        api.add_argument('--api-tls-key', type=Path,
            help='A path to the TLS private key file to use for secure connection.')

        api.add_argument('--api-log-level', type=_KeepDfltStrWrapper(), default=defaultArg(HttpServerConfig.log_level),
            choices=_levelToLogLevel.keys(), help='Set the API log level. Default is --log-level')

        # Private API
        papi = parser.add_argument_group('Private API server')
        papi.add_argument('--papi-host', type=_KeepDfltStrWrapper(), default=defaultArg('127.0.0.1'),
            help='Server listening host.')

        papi.add_argument('--papi-port', type=int, default=defaultArg(9090),
            help='Server listening port.')

        papi.add_argument('--papi-timeout-keep-alive', type=int, default=defaultArg(HttpServerConfig.timeout_keep_alive),
            help="Close 'Keep-Alive' connections if no new data\nis received within this timeout.")

        papi.add_argument('--papi-tls-cert', type=Path,
            help='A path to the TLS certificate file to use for secure connection.')

        papi.add_argument('--papi-tls-key', type=Path,
            help='A path to the TLS private key file to use for secure connection.')

        api.add_argument('--papi-log-level', type=_KeepDfltStrWrapper(), default=defaultArg(HttpServerConfig.log_level),
            choices=_levelToLogLevel.keys(), help='Set the PAPI log level. Default is --log-level')

        # Proto
        srv = parser.add_argument_group('Server')
        srv.add_argument('--challenge-ttl', default=defaultArg(ServerConfig.challenge_ttl),
            type=int, help='The number of seconds before protocol challenge expires.')

        # Server
        srv.add_argument('--job-interval', default=defaultArg(ServerConfig.job_interval),
            type=int, help='An interval in seconds at which the server schedule maintenance job and other tasks.\n  e.g.: Delete expired protocol challenges from database')

        # Loglevel
        parser.add_argument('--log-level', type=_KeepDfltStrWrapper(), default=defaultArg(ServerConfig.log_level),
            choices=_levelToLogLevel.keys(), help='Set the log level.')

        # MRTD PKD
        pkd = parser.add_argument_group('MRTD PKD', 'MRTD PKI trustchain certificates & CRLs to load into DB at server start')
        pkd.add_argument('--mrtd-pkd', type=Path,
            help='A path to the PKD root folder.')

        pkd.add_argument('--mrtd-pkd-allow-self-issued-csca', type=bool, default=defaultArg(MrtdPkd.allow_self_issued_csca),
            action=argparse.BooleanOptionalAction, help='Allow self-issued CSCA to be loaded into DB.')

        return parser

    @classmethod
    def _argsToJson(cls, args: argparse.Namespace) -> dict[str, Any]:
        """
        Converts parsed command-line arguments to Config JSON format.
        Note: 'mrtd_pkd' is removed from returned JSON if 'path' is not set.
        Note: All string and `Path` config values that are equal to 'None' will be converted to `None`.
        """
        def genClsFieldDict(c):
            # makes dict of arg-keys : {cfg:field} from cls fields
            # e.g.: {'db_dialect' : { 'database' : 'dialect'}}
            cfg_dict = collections.defaultdict(dict)
            for f in fields(c):
                name = _abbrev.get(f.name, f.name)
                ft = _get_optional_type(f.type)
                if is_dataclass(ft):
                    flds = genClsFieldDict(ft)
                    for cfk, cfv in flds.items():
                        cfg_dict[name + '_' + cfk][f.name] = cfv
                else:
                    cfg_dict[name] = f.name
            return cfg_dict

        cfg_dict = genClsFieldDict(cls)
        if 'mrtd_pkd_path' in cfg_dict:
            cfg_dict['mrtd_pkd'] = cfg_dict.pop('mrtd_pkd_path')

        def updateValue(val):
            # Convert all 'None' string and Path values to None
            if isinstance(val, str) and val == 'None':
                val = None
            if isinstance(val, Path) and val == Path('None'):
                val = None
            return val

        # Parse args to json-config
        jcfg = collections.defaultdict(dict)
        for argk, argv in vars(args).items():
            argv = stripDefaultArgWrapper(argv) #Strip-off _DefaultArg type
            argv = updateValue(argv)
            jf = cfg_dict.get(argk, argk) # If argk not in cfg_dict, the cls.fromJson should throw if `strict=True`
            if isinstance(jf, dict):
                def construct(d, v):
                    # Constructs {'field': 'type_field'}
                    # e.g.: { 'database' : 'dialect'}
                    fd =  collections.defaultdict(dict)
                    for k, kv in d.items():
                        if isinstance(v, dict):
                            kv = construct(kv, v) # pylint: disable=cell-var-from-loop
                            fd[k] = kv
                        else:
                            fd[k][kv] = v
                    return fd
                for k, v in construct(jf, argv).items():
                    jcfg[k] |= v
            else:
                jcfg[jf] = argv

        # Remove 'mrtd_pkd' if pkd path was not set
        if 'mrtd_pkd' in jcfg and 'path' not in jcfg['mrtd_pkd']:
            del jcfg['mrtd_pkd']
        return jcfg

def defaultArg(val):
    """
    Returns `val` wrapped in private `_DefaultArgVal` so default value is tagged, and
    `isArgDefultValue` can be used to determine if argument value was set by user or is default value.
    """
    if val is None:
        return None
    if type(val) is bool: # pylint: disable=unidiomatic-typecheck, no-else-return
        class _DefaultArg:
            _val: bool
            __base_type__ = bool
            def __init__(self, v:bool):
                self._val = v
            _isDefaultArg_ = True
            def __bool__(self):
                return self._val
            def __str__(self):
                return str(self._val)
            def __repr__(self) -> str:
                return repr(self._val)
        return _DefaultArg(val)
    else:
        class _DefaultArg(type(val)):
            __base_type__ = type(val)
            _isDefaultArg_ = True
        return _DefaultArg(val)

def stripDefaultArgWrapper(argv):
    # Strip-off _DefaultArg type
    if argv is not None and isArgDefultValue(argv):
        argv = argv.__base_type__(argv)
    return argv

def isArgDefultValue(val):
    clsn = getattr(val, '__class__', '')
    clsn = getattr(clsn, '__name__', '')
    return val is None or (clsn == '_DefaultArg' and hasattr(val, '_isDefaultArg_')) # pylint: disable=protected-access

class ArgumentHelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    """
    Same as ArgumentDefaultsHelpFormatter but doesn't print 'default: None' and default: ''
    and allows line breaks in description text.
    """
    def _get_help_string(self, action):
        if action.default is not None \
            and (not isinstance(action.default, str) or len(action.default) > 0):
            return super()._get_help_string(action)
        return action.help

    def _split_lines(self, text, width):
        ## allow line breaks in description text
        return text.splitlines()
