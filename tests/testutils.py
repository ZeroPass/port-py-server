from port.database import DatabaseAPI
from pymrtd import ef
from sqlalchemy.orm import make_transient

def getSQLiteDB(dbName= '', dbLog = False):
    return DatabaseAPI('sqlite', host='', db=dbName, username='', password='', dbLog=dbLog) #nosec

def saMakeTransient(obj):
    if hasattr(obj, '_sa_class_manager'):
        make_transient(obj)

def sodStripSigners(sod: ef.SOD) -> ef.SOD:
    sod_cpy = sod.copy()
    for i in range(0, len(sod_cpy.signers)):
        del sod_cpy.signers[i]
    return sod_cpy
