import sqlalchemy
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
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
from sqlalchemy.orm import mapper, sessionmaker
from sqlalchemy.orm.session import Session

from port.proto.challenge import Challenge, CID
from port.proto.types import CertificateId, CountryCode, SodId
from port.proto.user import UserId

from typing import Optional

@compiles(VARBINARY, "postgresql")
def compile_varbinary_postgresql(type_, compiler, **kw):
    return "BYTEA"

class CertIdSqlType(TypeDecorator): # CertificateId
    impl = BigInteger
    cache_ok = True
    def process_result_value(self, value, dialect):
        return CertificateId(value) if value is not None else value

class ChallengeSqlType(TypeDecorator):
    impl = LargeBinary(32)
    cache_ok = True
    def process_result_value(self, value, dialect):
        return Challenge(value) if value is not None else value

class CidSqlType(TypeDecorator):
    impl = Integer
    cache_ok = True
    def process_result_value(self, value, dialect):
        return CID(value) if value is not None else value

class CountryCodeSqlType(TypeDecorator):
    # ISO-3166 Alpha-2 country code
    impl = String(2)
    cache_ok = True
    def process_result_value(self, value, dialect):
        return CountryCode(value) if value is not None else value

class SodIdSqlType(TypeDecorator):
    impl = BigInteger
    cache_ok = True
    def process_result_value(self, value, dialect):
        return SodId(value) if value is not None else value

class UserIdSqlType(TypeDecorator):
    impl = VARBINARY(20)
    cache_ok = True
    def process_result_value(self, value, dialect):
        return UserId(value) if value is not None else value


"""Database structures"""
metadata = MetaData()
crl = Table('crl', metadata,
    Column('id', Integer, primary_key=True),
    Column('object', LargeBinary),
    Column('issuerCountry', String),
    Column('size', Integer),
    Column('thisUpdate', DateTime),
    Column('nextUpdate', DateTime),
    Column('signatureAlgorithm', String),
    Column('signatureHashAlgorithm', String)
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
csca = Table('csca', metadata, *certColumns())
dsc  = Table('dsc' , metadata, *certColumns(issuerCertTable='csca'))

# table for storing Port protocol challenges used for passport active authentication
protoChallenges = Table('protoChallenges', metadata,
    Column('id'       , CidSqlType              , primary_key=True, autoincrement=False            ),
    Column('uid'      , UserIdSqlType()         , nullable=False  , unique=True        , index=True), # ForeignKey('accounts.uid'), must not be set as account might not exist yet
    Column('challenge', ChallengeSqlType()      , nullable=False                                   ),
    Column("expires"  , DateTime(timezone=False), nullable=False                                   )
)

# table contains info about attested accounts
accounts = Table('accounts', metadata,
    Column('uid'        , UserIdSqlType(), primary_key=True), # uid = UserId
    Column('sod'        , LargeBinary    , nullable=False  ),
    Column('aaPublicKey', LargeBinary    , nullable=False  ),
    Column('sigAlgo'    , LargeBinary    , nullable=True   ),
    Column('dg1'        , LargeBinary    , nullable=True   ),
    Column('session'    , LargeBinary    , nullable=False  ), # Note: Should be moved to separate table
    Column('validUntil' , DateTime(timezone=False)         ),
    Column('loginCount' , Integer        , default=0       ),
    Column('isValid'    , Boolean                          )
)

class PortDbConnectionError(Exception):
    pass

Base = declarative_base()

class PortDatabaseConnection:
    """Manage ORM connection to save/load objects in database"""

    connectionObj = None
    metaData = None
    session = None

    def __init__(self, dialect:str, host:str, db: str, username: str, password: str, debugLogging=False):
        '''
        Creates new ORM database connection.
        :param dialect: The database dialect e.g.:  mariadb, mysql, oracle, postgresql, sqlite.
        :param host: The database urlhost. Can be empty string in case of sqlite.
        :param db: The database path.
        :param username: The database username.
        :param password: The database password.
        :param debugLogging: If True, the sqlalchemy engine will log all statements.``
        :raises: PortDbConnectionError on error.
        '''
        try:
            # The return value of create_engine() is our connection object
            url = PortDatabaseConnection.__buildUrl(dialect, host, db, username, password)
            self.connectionObj = sqlalchemy.create_engine(url, encoding='utf-8', echo=debugLogging)

            # We then bind the connection to MetaData()
            self.metaData = MetaData(bind=self.connectionObj)
            self.metaData.reflect()

            # we create session object to use it later
            Session = sessionmaker(bind=self.connectionObj)
            self.session = Session()

            self.initTables()

        except Exception as e:
            raise PortDbConnectionError(e) from e

    def getEngine(self):
        """ It returns engline object"""
        return self.connectionObj

    def getSession(self) -> Session:
        """ It returns session to use it in the actual storage objects/instances"""
        return self.session

    def initTables(self):
        """Initialize tables for usage in database"""

        #imports - to avoid circle imports
        from port.database.storage.crlStorage import CrlStorage
        from port.database.storage.x509Storage import DscStorage, CscaStorage
        from port.database.storage.challengeStorage import ChallengeStorage
        from port.database.storage.accountStorage import AccountStorage

        #CertificateRevocationList
        mapper(CrlStorage, crl)

        #DocumentSignerCertificate
        mapper(DscStorage, dsc)

        # CSCAStorage
        mapper(CscaStorage, csca)

        # challenge
        mapper(ChallengeStorage, protoChallenges)

        # account
        mapper(AccountStorage, accounts)

        #creating tables
        Base.metadata.create_all(self.connectionObj, tables=[crl, dsc, csca, protoChallenges, accounts])

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