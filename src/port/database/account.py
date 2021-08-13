from port.proto.types import SodId, UserId
from port.proto.session import Session

from pymrtd import ef
from pymrtd.pki.keys import AAPublicKey, SignatureAlgorithm

from datetime import datetime
from typing import Optional

class AccountStorage:
    """Class for interaction between code structure and database"""
    uid: UserId
    sodId: SodId
    aaPublicKey: bytes
    aaSigAlgo: Optional[bytes]
    dg1: Optional[bytes]
    session: bytes
    validUntil: datetime
    loginCount: int
    isValid: bool

    def __init__(self, uid: UserId, sodId: SodId, aaPublicKey: AAPublicKey, aaSigAlgo: Optional[SignatureAlgorithm], dg1: Optional[ef.DG1], session: Session, validUntil: datetime, loginCount: int = 0):
        """Initialization object"""
        assert isinstance(uid, UserId)
        assert isinstance(sodId, SodId)
        assert isinstance(aaPublicKey, AAPublicKey)
        assert isinstance(aaSigAlgo, (SignatureAlgorithm, type(None)))
        assert isinstance(dg1, (ef.DG1, type(None)))
        assert isinstance(session, Session)
        assert isinstance(validUntil, datetime)
        assert isinstance(loginCount, int)

        if aaSigAlgo is not None:
            aaSigAlgo = aaSigAlgo.dump()
        if dg1 is not None:
            dg1 = dg1.dump()

        self.uid         = uid
        self.sodId       = sodId
        self.aaPublicKey = aaPublicKey.dump()
        self.aaSigAlgo   = aaSigAlgo
        self.dg1         = dg1
        self.session     = session.bytes()
        self.validUntil  = validUntil
        self.loginCount  = loginCount
        self.isValid     = True

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

    def getValidUntil(self) -> datetime:
        return self.validUntil

    def getIsValid(self) -> bool:
        """Return isValid from object"""
        return self.isValid
