from datetime import datetime
from port.proto.types import CountryCode, SodId, UserId
from pymrtd import ef
from pymrtd.pki.keys import AAPublicKey, SignatureAlgorithm
from typing import Optional

class AccountStorage:
    """Class for interaction between code structure and database"""
    uid: UserId
    country: CountryCode            # The country code of attestation Passport at first registration. Used for pinning account to the country, since sodId can be None.
    sodId: Optional[SodId]          # If None, account is not attested by passport
    expires: Optional[datetime]     # The date the account attestation expires, usually set to dsc expiration time
    aaPublicKey: Optional[bytes]    # Optional, active authentication public key is only available in some passports
    aaSigAlgo: Optional[bytes]
    aaCount: int                    # ActiveAuthentication counter, counts how many AAs have been done. When greater than 0, account is ActiveAuthenticated with eMRTD.
    aaLastAuthn: Optional[datetime] # The date of last successful Active Authentication.
    dg1: Optional[bytes]
    dg2: Optional[bytes]

    def __init__(self, uid: UserId, country: CountryCode, sodId: Optional[SodId], expires: Optional[datetime], \
        aaPublicKey: Optional[AAPublicKey], aaSigAlgo: Optional[SignatureAlgorithm], aaCount: int, aaLastAuthn: Optional[datetime], dg1: Optional[ef.DG1], dg2: Optional[bytes]):
        """Initialization object"""
        assert isinstance(uid, UserId)
        assert isinstance(country, CountryCode)
        assert isinstance(sodId, (SodId, type(None)))
        assert isinstance(expires, (datetime, type(None)))
        assert isinstance(aaPublicKey, (AAPublicKey, type(None)))
        assert isinstance(aaSigAlgo, (SignatureAlgorithm, type(None)))
        assert isinstance(aaCount, int)
        assert isinstance(aaLastAuthn, (datetime, type(None)))
        assert isinstance(dg1, (ef.DG1, type(None)))
        assert isinstance(dg2, (bytes, type(None)))
        if aaPublicKey is not None:
            aaPublicKey = aaPublicKey.dump()
        if aaSigAlgo is not None:
            aaSigAlgo = aaSigAlgo.dump()
        if dg1 is not None:
            dg1 = dg1.dump()

        self.uid         = uid
        self.country     = country
        self.sodId       = sodId
        self.expires     = expires
        self.aaPublicKey = aaPublicKey
        self.aaSigAlgo   = aaSigAlgo
        self.aaCount     = aaCount
        self.aaLastAuthn = aaLastAuthn
        self.dg1         = dg1
        self.dg2         = dg2

    def getAAPublicKey(self) -> Optional[AAPublicKey]:
        if self.aaPublicKey is None:
            return None
        return AAPublicKey.load(self.aaPublicKey)

    def getAASigAlgo(self) -> Optional[SignatureAlgorithm]:
        if self.aaSigAlgo is None:
            return None
        return SignatureAlgorithm.load(self.aaSigAlgo)

    def getDG1(self) -> Optional[ef.DG1]:
        if self.dg1 is None:
            return None
        return ef.DG1.load(self.dg1)

    def setDG1(self, dg1:  Optional[ef.DG1]):
        assert isinstance(dg1, (ef.DG1, type(None)))
        if dg1 is not None:
            dg1 = dg1.dump()
        self.dg1 = dg1
