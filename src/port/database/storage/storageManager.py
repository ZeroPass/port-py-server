import sqlalchemy
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    future,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    TypeDecorator,
    VARBINARY
)

from sqlalchemy.ext.compiler import compiles
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import mapper, sessionmaker, scoped_session
from sqlalchemy.orm.session import Session
from port.database.storage.accountStorage import AccountStorage
from port.database.storage.challengeStorage import ChallengeStorage
from port.database.storage.x509Storage import CertificateRevocationInfo, CrlUpdateInfo, CscaStorage, DscStorage, PkiDistributionUrl

from port.proto.challenge import Challenge, CID
from port.proto.types import CertificateId, CountryCode, SodId
from port.proto.user import UserId

from typing import Final, Optional

@compiles(VARBINARY, "postgresql")
def compile_varbinary_postgresql(type_, compiler, **kw): #pylint: disable=unused-argument
    return "BYTEA"

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
    Column('country'   , CountryCodeSqlType()    , primary_key=True), # ISO alpha 2 country code
    Column('crlNumber' , LargeBinary(20)         , nullable=True   ),
    Column('thisUpdate', DateTime(timezone=False), nullable=False  ),
    Column('nextUpdate', DateTime(timezone=False), nullable=False  )
)

# certificate revocation table contains list of infos about revoked certificates
crt: Final = Table('crt', metadata,
    Column('serial'        , VARBINARY(20)           , nullable=False, primary_key=True), # revoked certificate serial number
    Column('country'       , CountryCodeSqlType()    , nullable=False, unique=False    ),
    Column('certId'        , CertIdSqlType           , nullable=True , unique=True     ), # revoked certificate id i.e. foreign key in csca or dsc table.
                                                                                          # The column could be NULL if cert is not found in the coresponding tables when inserting.
    Column('revocationDate', DateTime(timezone=False), nullable=False                  ),
)

# table contains eMRTD distribution URLs for country. i.e.: distribution URLs fo countries CSCA, DSC and CRL
pkiDistributionInfo: Final = Table('pki_distribution_info', metadata,
    Column('id'     , BigInteger                    , primary_key=True, autoincrement=False            ), # Unique ID tied to the country code, url and type. See PkiDistributionUrl._gen_id
    Column('country', CountryCodeSqlType()          , unique=False    , nullable=False     , index=True),
    Column('type'   , Enum(PkiDistributionUrl.Type) , unique=False    , nullable=False                 ),
    Column('url'    , Text                          , unique=False    , nullable=False                 ), # distribution URL.
)

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

# table for storing Port protocol challenges used for passport active authentication
protoChallenges: Final = Table('proto_challenges', metadata,
    Column('id'       , CidSqlType              , primary_key=True, autoincrement=False            ),
    Column('uid'      , UserIdSqlType()         , nullable=False  , unique=True        , index=True), # ForeignKey('accounts.uid'). Note: must not be set to foregin key since the account might not exist yet
    Column('challenge', ChallengeSqlType()      , nullable=False                                   ),
    Column("expires"  , DateTime(timezone=False), nullable=False                                   )
)

# table contains info about attested accounts
accounts: Final = Table('accounts', metadata,
    Column('uid'        , UserIdSqlType(), primary_key=True), # uid = UserId
    Column('sod'        , LargeBinary    , nullable=False  ),
    Column('aaPublicKey', LargeBinary    , nullable=False  ),
    Column('aaSigAlgo'  , LargeBinary    , nullable=True   ),
    Column('dg1'        , LargeBinary    , nullable=True   ),
    Column('session'    , LargeBinary    , nullable=False  ), # Note: Should be moved to separate table
    Column('validUntil' , DateTime(timezone=False)         ),
    Column('loginCount' , Integer        , default=0       ),
    Column('isValid'    , Boolean                          )
)

class PortDbConnectionError(Exception):
    pass

class PortDatabaseConnection:
    """Manage ORM connection to save/load objects in database"""

    _engine = None
    _session = None
    _base = None

    @property
    def engine(self) -> future.Engine:
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
            # The return value of create_engine() is our connection object
            url = PortDatabaseConnection.__buildUrl(dialect, host, db, username, password)
            self._engine = sqlalchemy.create_engine(url,
                encoding     = 'utf-8',
                pool_recycle = connectionRecycle,
                echo         = debugLogging,
                echo_pool    = logPool,
                future       = True  # future=True -> support sqlalchemy v 2.0
            )

            # we create session object to use it later
            self._base = declarative_base()
            S = sessionmaker(bind=self._engine, expire_on_commit=True, future=True) # future=True -> support sqlalchemy v 2.0
            self._session = scoped_session(S) #Session()

            self.initTables()

        except Exception as e:
            raise PortDbConnectionError(e) from e

    def getEngine(self):
        """ It returns engline object"""
        return self._engine

    def getSession(self) -> Session:
        """ It returns session to use it in the actual storage objects/instances"""
        return self._session

    def initTables(self):
        """Initialize tables for usage in database"""

        #CertificateRevocationList
        mapper(CrlUpdateInfo, crlUpdateInfo)
        mapper(CertificateRevocationInfo, crt)
        mapper(PkiDistributionUrl, pkiDistributionInfo)

        #DocumentSignerCertificate
        mapper(DscStorage, dsc)

        # CSCAStorage
        mapper(CscaStorage, csca)

        # challenge
        mapper(ChallengeStorage, protoChallenges)

        # account
        mapper(AccountStorage, accounts)

        #creating tables
        self._base.metadata.create_all(self._engine, tables=[crlUpdateInfo, crt, pkiDistributionInfo, dsc, csca, protoChallenges, accounts])

    @staticmethod
    def __buildUrl(dialect:str, host:str, db: str, username: str, password: str):
        url = '{}://'.format(dialect)
        if len(username) != 0:
            url += '{}:{}'.format(username, password)
        if len(host) != 0:
            url += '@{}'.format(host)
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
