from datetime import datetime
from port.proto.types import Challenge, CID, UserId

class ChallengeStorage:
    """Class for interaction between code structure and database"""
    id: CID
    uid: UserId
    challenge: Challenge
    expires: datetime

    def __init__(self, uid: UserId, challenge: Challenge, expires: datetime):
        self.id = challenge.id
        self.uid = uid
        self.challenge = challenge
        self.expires = expires
