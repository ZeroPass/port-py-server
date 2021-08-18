from port.proto.types import CountryCode, SodId, UserId
from port.proto.session import Session

from pymrtd import ef
from pymrtd.pki.keys import AAPublicKey, SignatureAlgorithm

from datetime import datetime
from typing import Optional

class AccountStorage:
    """Class for interaction between code structure and database"""
    uid: UserId
    country: CountryCode # The country code of attestation Passport at first registration. Used for pinning account to the country, since sodId can be None.
    sodId: Optional[SodId] # If None, account is not attested by passport
    expires: Optional[datetime] # The date the account attestation expires, usually set to dsc expiration time
    aaPublicKey: bytes
    aaSigAlgo: Optional[bytes]
    dg1: Optional[bytes]
    dg2: Optional[bytes]
    session: bytes
    loginCount: int

    def __init__(self, uid: UserId, country: CountryCode, sodId: Optional[SodId], expires: Optional[datetime], \
        aaPublicKey: AAPublicKey, aaSigAlgo: Optional[SignatureAlgorithm], dg1: Optional[ef.DG1], dg2: Optional[bytes], session: Session, loginCount: int = 0):
        """Initialization object"""
        assert isinstance(uid, UserId)
        assert isinstance(country, CountryCode)
        assert isinstance(sodId, (SodId, type(None)))
        assert isinstance(expires, (datetime, type(None)))
        assert isinstance(aaPublicKey, AAPublicKey)
        assert isinstance(aaSigAlgo, (SignatureAlgorithm, type(None)))
        assert isinstance(dg1, (ef.DG1, type(None)))
        assert isinstance(dg2, (bytes, type(None)))
        assert isinstance(session, Session)

        assert isinstance(loginCount, int)

        if aaSigAlgo is not None:
            aaSigAlgo = aaSigAlgo.dump()
        if dg1 is not None:
            dg1 = dg1.dump()

        self.uid         = uid
        self.country     = country
        self.sodId       = sodId
        self.expires     = expires
        self.aaPublicKey = aaPublicKey.dump()
        self.aaSigAlgo   = aaSigAlgo
        self.dg1         = dg1
        self.dg2         = dg2
        self.session     = session.bytes()
        self.loginCount  = loginCount

    def getAAPublicKey(self) -> AAPublicKey:
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

    def getSession(self) -> Session:
        return Session.fromBytes(self.session)

    def setSession(self, s: Session):
        assert isinstance(s, Session)
        self.session = s.bytes()
