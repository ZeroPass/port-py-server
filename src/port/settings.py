import ssl
from typing import NamedTuple


class DbConfig(NamedTuple):
    dialect: str
    url: str      = ''
    name: str     = '' # database name
    user: str     = ''
    password: str = ''

class MrtdPkd(NamedTuple):
    path: Path
    allow_self_issued_csca: bool = True # allow selfsigned CSCA certificate when loading CSCAs from path

class HttpServerConfig(NamedTuple):
    host: str
    port: int
    timeout_keep_alive: int  = 10 # close 'Keep-Alive' connection after response if no data is received for n seconds
    log_level: Optional[str] = None
    tls_cert: Optional[Path] = None
    tls_key: Optional[Path]  = None

class ServerConfig(NamedTuple):
    database: DbConfig
    api: Optional[HttpServerConfig] = None
    challenge_ttl: int              = 600 # 10 minutes
    job_interval: int               = 3600  # 1 hour, an interval at which server does maintenance job and other tasks. (e.g.: delete expired proto challenges from DB)
    log_level: str                  = 'verbose'
    mrtd_pkd: Optional[MrtdPkd]     = None # MRTD certificate folder to load into database when server starts

