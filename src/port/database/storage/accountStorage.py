from port.proto.user import UserId
from port.proto.session import Session

from pymrtd import ef
from pymrtd.pki.keys import AAPublicKey, SignatureAlgorithm

from datetime import datetime
from typing import Union

class AccountStorage:
    """Class for interaction between code structure and database"""
    uid: UserId
    sod: bytes
    aaPublicKey: bytes
    aaSigAlgo: bytes
    dg1: bytes
    session: bytes
    validUntil: datetime
    loginCount: int
    isValid: bool

    def __init__(self, uid: UserId, sod: ef.SOD, aaPublicKey: AAPublicKey, aaSigAlgo: Union[SignatureAlgorithm, None], dg1: Union[ef.DG1, None], session: Session, validUntil: datetime, loginCount: int = 0):
        """Initialization object"""
        assert isinstance(uid, UserId)
        assert isinstance(sod, ef.SOD)
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
        self.sod         = sod.dump()
        self.aaPublicKey = aaPublicKey.dump()
        self.aaSigAlgo   = aaSigAlgo
        self.dg1         = dg1
        self.session     = session.bytes()
        self.validUntil  = validUntil
        self.loginCount  = loginCount
        self.isValid     = True

    def getSOD(self) -> ef.SOD:
        """Return SOD from object"""
        return ef.SOD.load(self.sod)

    def getAAPublicKey(self) -> AAPublicKey:
        return AAPublicKey.load(self.aaPublicKey)

    def getAASigAlgo(self) -> Union[SignatureAlgorithm, None]:
        if self.aaSigAlgo is None:
            return None
        return SignatureAlgorithm.load(self.aaSigAlgo)

    def getDG1(self) -> Union[ef.DG1, None]:
        if self.dg1 is None:
            return None
        return ef.DG1.load(self.dg1)

    def setDG1(self, dg1:  Union[ef.DG1, None]):
        assert isinstance(dg1, (ef.DG1, type(None)))
        if dg1 is not None:
            dg1 = dg1.dump()
        self.dg1 = dg1

    def getSession(self) -> Union[Session, None]:
        return Session.fromBytes(self.session)

    def setSession(self, s: Session):
        assert isinstance(s, Session)
        self.session = s.bytes()

    def getValidUntil(self) -> datetime:
        return self.validUntil

    def getIsValid(self) -> bool:
        """Return isValid from object"""
        return self.isValid
