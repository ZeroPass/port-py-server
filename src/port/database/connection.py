from port import log
import sqlalchemy
from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    TypeDecorator,
    VARBINARY,
    UniqueConstraint
)
from sqlalchemy.future import Engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import mapper, sessionmaker, scoped_session
from sqlalchemy.orm.session import Session

from .account import AccountStorage
from .challenge import ChallengeStorage
from .sod import SodTrack
from .x509 import (
    CertificateRevocationInfo,
    CrlUpdateInfo,
    CscaStorage,
    DscStorage,
    PkiDistributionUrl
)

from port.proto.types import (
    CertificateId,
    Challenge,
    CID,
    CountryCode,
    CrlId,
    SodId,
    UserId
)

from typing import Final, Optional

@compiles(VARBINARY, "postgresql")
def compile_varbinary_postgresql(type_, compiler, **kw): #pylint: disable=unused-argument
    return "BYTEA"

class CrlIdSqlType(TypeDecorator): #pylint: disable=abstract-method
    impl = BigInteger # 64bit signed integer
    python_type = CrlId
    cache_ok = True
    def process_result_value(self, value, dialect):
        return CrlId(value) if value is not None else value

class CertIdSqlType(TypeDecorator): #pylint: disable=abstract-method
    impl = BigInteger # 64bit signed integer
    python_type = CertificateId
    cache_ok = True
    def process_result_value(self, value, dialect):
        return CertificateId(value) if value is not None else value

class ChallengeSqlType(TypeDecorator): #pylint: disable=abstract-method
    impl = LargeBinary(32)
    python_type = Challenge
    cache_ok = True
    def process_result_value(self, value, dialect):
        return Challenge(value) if value is not None else value

class CidSqlType(TypeDecorator): #pylint: disable=abstract-method
    impl = Integer # 32bit signed integer
    python_type = CID
    cache_ok = True
    def process_result_value(self, value, dialect):
        return CID(value) if value is not None else value

class CountryCodeSqlType(TypeDecorator): #pylint: disable=abstract-method
    # ISO-3166 Alpha-2 country code
    impl = String(2)
    python_type = CountryCode
    cache_ok = True
    def process_result_value(self, value, dialect):
        return CountryCode(value) if value is not None else value

class SodIdSqlType(TypeDecorator): #pylint: disable=abstract-method
    impl = BigInteger # 64bit signed integer
    python_type = SodId
    cache_ok = True
    def process_result_value(self, value, dialect):
        return SodId(value) if value is not None else value

class UserIdSqlType(TypeDecorator): #pylint: disable=abstract-method
    impl = VARBINARY(20)
    python_type = UserId
    cache_ok = True
    def process_result_value(self, value, dialect):
        return UserId(value) if value is not None else value


# Database structures
metadata: Final = MetaData()

# table contains CRL update info for country
crlUpdateInfo: Final = Table('crl_update_info', metadata,
    Column('id'        , CrlIdSqlType            , primary_key=True          ), # entry unique ID tied to country and issuer, see CrlId
    Column('country'   , CountryCodeSqlType()    , nullable=False, index=True), # ISO alpha 2 country code
    Column('issuer'    , Text                    , nullable=False            ),
    Column('crlNumber' , LargeBinary(20)         , nullable=True             ),
    Column('thisUpdate', DateTime(timezone=False), nullable=False            ),
    Column('nextUpdate', DateTime(timezone=False), nullable=False            )
)
mapper(CrlUpdateInfo, crlUpdateInfo)

# certificate revocation table contains list of infos about revoked certificates
crt: Final = Table('crt', metadata,
    Column('id'            , BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True), # SQLite requires 'INTEGER' for autoincrement primary key column.
    Column('serial'        , VARBINARY(20)           , nullable=False, unique=False      ), # revoked certificate serial number
    Column('country'       , CountryCodeSqlType()    , nullable=False, unique=False      ),
    Column('crlId'         , CrlIdSqlType(),
        ForeignKey('crl_update_info.id')             , nullable=True , unique=False      ), # Note: if NULL it means the revocation was manually added and is not part of any CRL.
    Column('certId'        , CertIdSqlType           , nullable=True , unique=True       ), # revoked certificate id i.e. foreign key in csca or dsc table.
                                                                                            # The column could be NULL if cert is not found in the coresponding tables when inserting.
    Column('revocationDate', DateTime(timezone=False), nullable=False                    ),
    UniqueConstraint('serial', 'country', name='ser_cc_idx')
)
mapper(CertificateRevocationInfo, crt)

# table contains eMRTD distribution URLs for country. i.e.: distribution URLs fo countries CSCA, DSC and CRL
pkiDistributionInfo: Final = Table('pki_distribution_info', metadata,
    Column('id'     , BigInteger                    , primary_key=True, autoincrement=False            ), # Unique ID tied to the country code, url and type. See PkiDistributionUrl._gen_id
    Column('country', CountryCodeSqlType()          , unique=False    , nullable=False     , index=True),
    Column('type'   , Enum(PkiDistributionUrl.Type) , unique=False    , nullable=False                 ),
    Column('url'    , Text                          , unique=False    , nullable=False                 ), # distribution URL.
)
mapper(PkiDistributionUrl, pkiDistributionInfo)

# x.509 certificate table scheme
def certColumns(issuerCertTable: Optional[str] = None):
    hasIssuer = issuerCertTable is not None
    return [
        Column('id'            , CertIdSqlType            , primary_key=True, autoincrement=False),
        Column('country'       , CountryCodeSqlType()     , nullable=False  , index=True         ),
        Column('serial'        , VARBINARY(20)            , nullable=False  , index=True         ),
        Column('notValidBefore', DateTime(timezone=False) , nullable=False                       ),
        Column('notValidAfter' , DateTime(timezone=False) , nullable=False                       ),
        Column('issuerId'      , CertIdSqlType,
            ForeignKey(issuerCertTable + '.id') if hasIssuer else None,
            nullable = (not hasIssuer), index=True
        ),
        Column('issuer'      , Text         , nullable=(not hasIssuer) ),
        Column('authorityKey', VARBINARY(32), nullable=True, index=True),
        Column('subject'     , Text         , nullable=False           ),
        Column('subjectKey'  , VARBINARY(32), nullable=True, index=True),
        Column('certificate' , LargeBinary  , nullable=False           )
    ]

# tables of country CSCA and DSC certificates
csca: Final = Table('csca', metadata, *certColumns())
dsc: Final  = Table('dsc' , metadata, *certColumns(issuerCertTable='csca'))
mapper(DscStorage, dsc)
mapper(CscaStorage, csca)

# table for storing Port protocol challenges used for passport active authentication
protoChallenge: Final = Table('proto_challenge', metadata,
    Column('id'       , CidSqlType              , primary_key=True, autoincrement=False            ),
    Column('uid'      , UserIdSqlType()         , nullable=False  , unique=True        , index=True), # ForeignKey('account.uid'). Note: must not be set to foregin key since the account might not exist yet
    Column('challenge', ChallengeSqlType()      , nullable=False                                   ),
    Column("expires"  , DateTime(timezone=False), nullable=False                                   )
)
mapper(ChallengeStorage, protoChallenge)

# table contais info about MRTD EF.SOD files which were used to attest accounts
sod: Final = Table('sod', metadata,
    Column('id'       , SodIdSqlType    , primary_key=True, autoincrement=False                          ),
    Column('dscId'    , CertIdSqlType() , ForeignKey('dsc.id'), nullable=False, unique=False, index=True ),
    Column('hashAlgo' , String(256)     , nullable=False, unique=False, index=True                       ),
    Column('dg1Hash'  , VARBINARY(256)  , nullable=True , unique=True, index=True                        ),
    Column('dg2Hash'  , VARBINARY(256)  , nullable=True , unique=True, index=True                        ),
    Column('dg3Hash'  , VARBINARY(256)  , nullable=True , unique=True, index=True                        ),
    Column('dg4Hash'  , VARBINARY(256)  , nullable=True , unique=True, index=True                        ),
    Column('dg5Hash'  , VARBINARY(256)  , nullable=True , unique=True, index=True                        ),
    Column('dg6Hash'  , VARBINARY(256)  , nullable=True , unique=True, index=True                        ),
    Column('dg7Hash'  , VARBINARY(256)  , nullable=True , unique=True, index=True                        ),
    Column('dg8Hash'  , VARBINARY(256)  , nullable=True , unique=True, index=True                        ),
    Column('dg9Hash'  , VARBINARY(256)  , nullable=True , unique=True, index=True                        ),
    Column('dg10Hash'  , VARBINARY(256) , nullable=True , unique=True, index=True                        ),
    Column('dg11Hash'  , VARBINARY(256) , nullable=True , unique=True, index=True                        ),
    Column('dg12Hash'  , VARBINARY(256) , nullable=True , unique=True, index=True                        ),
    Column('dg13Hash'  , VARBINARY(256) , nullable=True , unique=True, index=True                        ),
    Column('dg14Hash'  , VARBINARY(256) , nullable=True , unique=True, index=True                        ),
    Column('dg15Hash'  , VARBINARY(256) , nullable=True , unique=True, index=True                        ),
    Column('dg16Hash'  , VARBINARY(256) , nullable=True , unique=True, index=True                        ),
)
mapper(SodTrack, sod)

# table contains info about attested account
account: Final = Table('account', metadata,
    Column('uid'        , UserIdSqlType()         , primary_key=True                                            ), # uid = UserId
    Column('country'    , CountryCodeSqlType()    , nullable=False      , index=True                            ), # The country code of attestation Passport at first registration. Used for pinning account to the country, since sodId can be None.
    Column('sodId'      , SodIdSqlType            , ForeignKey('sod.id'), nullable=True, unique=True, index=True), # If null, the account is not attested
    Column('expires'    , DateTime(timezone=False), nullable=True                                               ), # Usually set to DSC expiration time. If NULL, expires when EF.SOD TC expires
    Column('aaPublicKey', LargeBinary             , nullable=False                                              ),
    Column('aaSigAlgo'  , LargeBinary             , nullable=True                                               ),
    Column('aaCount'    , Integer                 , default=0                                                   ), # Counts number of successful ActiveAuthentications. When greater than 0 account is ActiveAuthenticated.
    Column('dg1'        , LargeBinary             , nullable=True                                               ),
    Column('dg2'        , LargeBinary             , nullable=True                                               )
)
mapper(AccountStorage, account)

class PortDbConnectionError(Exception):
    pass

class PortDatabaseConnection:
    """Manage ORM connection to save/load objects in database"""

    _engine = None
    _session = None
    _base = None

    @property
    def engine(self) -> Engine:
        return self._engine

    @property
    def session(self) -> scoped_session:
        return self._session

    def __init__(self, dialect:str, host:str, db: str, username: str, password: str, connectionRecycle: int = 3600, debugLogging: bool = False, logPool: bool = True):
        '''
        Creates new ORM database connection.
        :param dialect: The database dialect e.g.:  mariadb, mysql, oracle, postgresql, sqlite.
        :param host: The database urlhost. Can be empty string in case of sqlite.
        :param db: The database path.
        :param username: The database username.
        :param password: The database password.
        :param connectionRecycle: Causes the connection pool to recycle connections after the given number of seconds has passed.
            Useful for example to prevent the MySql server (default configured) to automatically disconnect from the client after 8 hours of inactivity.
            Set to -1 for no recycle.
            Default is 3600 secs i.e. 1 hour.
        :param debugLogging: If True, the sqlalchemy engine will log all statements.``
        :param logPool: if True, the connection pool will log informational output such as when connections are invalidated as well as when connections are recycled.
        :raises: PortDbConnectionError on error.
        '''
        try:
            self._log = log.getLogger("port.db.sql")
            self._log.debug('Creating SQL engine with config:')
            self._log.debug("  dialect='%s'", dialect)
            self._log.debug("  host='%s'", host)
            self._log.debug("  db='%s'", db)
            self._log.debug("  username='%s'", username)
            self._log.verbose("  password='%s'", password) # Maybe should not log password?
            self._log.debug("  connectionRecycle'=%s'", connectionRecycle)

            url = PortDatabaseConnection.__buildUrl(dialect, host, db, username, password)
            self._engine = sqlalchemy.create_engine(url,
                encoding     = 'utf-8',
                pool_recycle = connectionRecycle,
                echo         = debugLogging,
                echo_pool    = logPool,
                future       = True  # future=True -> support sqlalchemy v 2.0
            )

            # we create session object to use it later
            self._log.debug("Initializing SQL session from created engine.")
            self._base = declarative_base()
            S = sessionmaker(bind=self._engine, expire_on_commit=True, future=True) # future=True -> support sqlalchemy v 2.0
            self._session = scoped_session(S)
            self.initTables()

        except Exception as e:
            self._log.error("An error has occurred while establishing connection to SQL DB. url='%s'", url)
            self._log.error(  "e='%s'", e)
            raise PortDbConnectionError(e) from e

    def getEngine(self):
        """ It returns engline object"""
        return self._engine

    def getSession(self) -> Session:
        """ It returns session to use it in the actual storage objects/instances"""
        return self._session

    def initTables(self):
        self._log.debug("Initializing Port DB tables.")
        self._base.metadata.create_all(self._engine, tables=[
            crlUpdateInfo,
            crt,
            pkiDistributionInfo,
            dsc,
            csca,
            protoChallenge,
            sod,
            account
        ])

    @staticmethod
    def __buildUrl(dialect:str, host:str, db: str, username: str, password: str):
        url = '{}://'.format(dialect)
        if 'sqlite' not in  dialect:
            if len(username) != 0:
                url += '{}:{}'.format(username, password)
            if len(host) != 0:
                url += '@{}'.format(host)
        elif len(password) != 0: # sqlite
            url += ':{}@/'.format(password)
        if len(db):
            url += '/{}'.format(db)
        return url

def truncateAll(connection: PortDatabaseConnection):
    """Truncate all tables"""
    try:
        sql_raw_query = 'select \'TRUNCATE table "\' || tablename || \'" cascade;\' from pg_tables where schemaname=\'public\';'
        for result in connection.getEngine().execute(sql_raw_query):
            connection.getEngine().execute(result[0])
    except Exception as e:
        raise IOError("Failed to truncate DB") from e
