from port.database import DatabaseAPI
from sqlalchemy.orm import make_transient

def getSQLiteDB(dbName= '', dbLog = False):
    return DatabaseAPI('sqlite', host='', db=dbName, username='', password='', dbLog=dbLog) #nosec

def saMakeTransient(obj):
    if hasattr(obj, '_sa_class_manager'):
        make_transient(obj)
