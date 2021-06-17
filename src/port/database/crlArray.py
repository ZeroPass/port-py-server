import logging
from pymrtd.pki.crl import CertificationRevocationList
from port.settings import *


class CRLArray:
    """Class: array of CRL(arrays)"""

    crls = {}

    def __init__(self, crl):
        item = CertificationRevocationList(crl)
        self._log = logging.getLogger(CRLArray.__name__)
        #add to dictonary with key 'countryName'
        self.crls[item.countryName] = item

    def getCountry(self, countryName) -> CertificationRevocationList:
        """Function returns country of CRL issuer """
        foundItem = self.crls[countryName] if countryName in self.crls else None
        self._log.info("Getting country with countryName: " + countryName + ", found/not found" + True if foundItem is not None else False)
        return foundItem
