import re
from ldif3 import LDIFParser
from asn1crypto import crl, x509
from .storage.storageManager import PortDatabaseConnection
#from database.storage.DSC import CertX509
from .storage.crlStorage import writeToDB_CRL, readFromDB_CRL
from pymrtd.pki.crl import CertificateRevocationList

conn = PortDatabaseConnection("postgresql", "localhost:5432", "port", "nejko", "nejko", )

certificateList = {}
revocationList = {}
parser = LDIFParser(open('C://Users/nejko/Desktop/ZeroPass/B1/random/parseCSCAandCRL/database/icaopkd-001-dsccrl-003749.ldif', 'rb'))
for dn, entry in parser.parse():
    if 'userCertificate;binary' in entry:
        countryCode = re.findall(r'[c,C]{1}=(.*)(,dc=database){1}', dn)[0][0]
        cert = x509.Certificate.load(*entry['userCertificate;binary'])
        if countryCode not in certificateList:
            certificateList[countryCode] = {}
        certificateList[countryCode][cert.serial_number] = cert

    if 'certificateRevocationList;binary' in entry:
        countryCode = re.findall(r'[c,C]{1}=(.*)(,dc=database){1}', dn)[0][0]
        ##revocationList[countryCode] = x509.load_der_x509_crl(*entry['certificateRevocationList;binary'], default_backend())
        revocationList[countryCode] = crl.CertificateList.load(*entry['certificateRevocationList;binary'])
        revocationListInObject = revocationList[countryCode]
        #revocationListInObject1 = CertificateRevocationList(revocationListInObject)
        revocationListInObject.__class__ = CertificateRevocationList
        revocationListInObject.__init__()

        writeToDB_CRL(revocationListInObject, conn)
        #conn.writeToDB(revocationListInObject, conn)
        readFromDB_CRL(conn)

        ##print("country:" + countryCode
        ##      + ",created: " + revocationList[countryCode].last_update.strftime("%Y-%m-%d %H:%M")
        ##      + ",next: " + revocationList[countryCode].next_update.strftime("%Y-%m-%d %H:%M")
        ##      + (" ***out of date : " + str(present - revocationList[countryCode].next_update) if revocationList[countryCode].next_update < present else ""))
