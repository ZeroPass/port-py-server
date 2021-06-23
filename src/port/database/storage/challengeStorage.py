from datetime import datetime
from port.proto.challenge import CID, Challenge

class ChallengeStorage(object):
    """Class for interaction between code structure and database"""
    id: CID
    challenge: str
    createTime: datetime

    def __init__(self):
        self.id = None
        self.challenge = None
        self.createTime = None

    @staticmethod
    def fromChallenge(challenge: Challenge, timedate: datetime) -> "ChallengeStorage":
        assert isinstance(challenge, Challenge)
        cs            = ChallengeStorage()
        cs.id         = challenge.id
        cs.challenge  = challenge.toBase64()
        cs.createTime = timedate
        return cs

    def getChallenge(self) -> Challenge:
        return Challenge.fromBase64(self.challenge)