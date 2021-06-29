from typing import Optional
import sqlalchemy
from sqlalchemy import Table, Column, Integer, String, DateTime, MetaData, LargeBinary, Boolean
from sqlalchemy.orm import mapper, sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.sql import func

#creating base class from template
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql.schema import ForeignKey
Base = declarative_base()

class PortDbConnectionError(Exception):
    pass

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

def certColumns(issuerCertTable: Optional[str] = None):
    hasIssuer = issuerCertTable is not None
    return [
        Column('id', BigInteger, primary_key=True),
        Column('country', String(2), nullable=False, index=True),
        Column('serial', String),
        Column('notValidBefore', DateTime, nullable=False),
        Column('notValidAfter', DateTime, nullable=False),
        Column('issuerId', BigInteger,
            ForeignKey(issuerCertTable + '.id') if hasIssuer else None,
            nullable = (not hasIssuer)
        ),
        Column('issuer', String),
        Column('authorityKey', LargeBinary),
        Column('subject', String, nullable=False),
        Column('subjectKey', LargeBinary),
        Column('certificate', LargeBinary, nullable=False)
    ]

csca = Table('csca', metadata, *certColumns())
dsc  = Table('dsc', metadata, *certColumns(issuerCertTable='csca'))

protoChallenges = Table('protoChallenges', metadata,
    Column('id', Integer, primary_key=True),
    Column('uid', LargeBinary(20), ForeignKey('accounts.uid'), unique=True),
    Column('challenge', LargeBinary(32), nullable=False),
    Column("expires", DateTime(timezone=True), nullable=False)
)

accounts = Table('accounts', metadata,
    Column('uid', LargeBinary(20), primary_key=True), # uid = UserId
    Column('sod', LargeBinary, nullable=False),
    Column('aaPublicKey', LargeBinary, nullable=False),
    Column('sigAlgo', LargeBinary, nullable=True),
    Column('dg1', LargeBinary, nullable=True),
    Column('session', LargeBinary, nullable=False), # Note: Should be moved to separate table
    Column('validUntil', DateTime),
    Column('loginCount', Integer, default=0),
    Column('isValid', Boolean)
)

class PortDatabaseConnection:
    """Manage ORM connection to save/load objects in database"""

    connectionObj = None
    metaData = None
    session = None

    def __init__(self, dialect:str, host:str, db: str, username: str, password: str):
        '''
        Creates new ORM database connection.
        :param dialect: The database dialect e.g.:  mariadb, mysql, oracle, postgresql, sqlite.
        :param host: The database urlhost. Can be empty string in case of sqlite.
        :param db: The database path.
        :param username: The database username.
        :param password: The database password.
        :raises: PortDbConnectionError on error.
        '''
        try:
            # The return value of create_engine() is our connection object
            url = PortDatabaseConnection.__buildUrl(dialect, host, db, username, password)
            self.connectionObj = sqlalchemy.create_engine(url, client_encoding='utf8', echo=True)

            # We then bind the connection to MetaData()
            self.metaData = MetaData(bind=self.connectionObj)
            self.metaData.reflect()

            # we create session object to use it later
            Session = sessionmaker(bind=self.connectionObj)
            self.session = Session()

            self.initTables()

        except Exception as e:
            raise PortDbConnectionError(e)

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
        raise IOError("Failed to truncate: " + str(e))