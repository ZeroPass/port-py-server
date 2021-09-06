from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from port.proto.types import CertificateId, SodId
from pymrtd import ef
from pymrtd.ef.dg import DataGroup, DataGroupNumber
from pymrtd.ef.sod import DataGroupHash, DataGroupHashValues
from pymrtd.pki import algo_utils
from typing import Optional

class SodTrack:
    id: SodId
    dscId: CertificateId      # DSC certificate that issued SOD. Note: This field shouldn't be null but could be NULL in query cases.
    hashAlgo: str             # hash algorithm used to produce DG hashes. Note: This field shouldn't be null but could be NULL in query cases.
    dg1Hash: Optional[bytes]  # hash of EF.DG1 calculated with hashAlgo
    dg2Hash: Optional[bytes]  # hash of EF.DG2 calculated with hashAlgo
    dg3Hash: Optional[bytes]  # hash of EF.DG3 calculated with hashAlgo
    dg4Hash: Optional[bytes]  # hash of EF.DG4 calculated with hashAlgo
    dg5Hash: Optional[bytes]  # hash of EF.DG5 calculated with hashAlgo
    dg6Hash: Optional[bytes]  # hash of EF.DG6 calculated with hashAlgo
    dg7Hash: Optional[bytes]  # hash of EF.DG7 calculated with hashAlgo
    dg8Hash: Optional[bytes]  # hash of EF.DG8 calculated with hashAlgo
    dg9Hash: Optional[bytes]  # hash of EF.DG9 calculated with hashAlgo
    dg10Hash: Optional[bytes] # hash of EF.DG10 calculated with hashAlgo
    dg11Hash: Optional[bytes] # hash of EF.DG11 calculated with hashAlgo
    dg12Hash: Optional[bytes] # hash of EF.DG12 calculated with hashAlgo
    dg13Hash: Optional[bytes] # hash of EF.DG13 calculated with hashAlgo
    dg14Hash: Optional[bytes] # hash of EF.DG14 calculated with hashAlgo
    dg15Hash: Optional[bytes] # hash of EF.DG15 calculated with hashAlgo
    dg16Hash: Optional[bytes] # hash of EF.DG16 calculated with hashAlgo

    def __init__(self, sodId: SodId, dscId: Optional[CertificateId], hashAlgo: Optional[str], dgHashes: Optional[DataGroupHashValues]):
        """
        Constructs new SodTrack.
        Note, some parameters can be None for the query purposes.
        :param sodId: The ID of EF.SOD file.
        :param dscId (Optional): The ID of DSC certificate which issued EF.SOD.
                                 Must not be None when inserting into DB,
                                 but can be None when querying the DB via ORM.
        :param hashAlgo (Optional): The hash Algorithm which produces EF.DG hash values in `dgHashes`.
                                 Must not be None when inserting into DB,
                                 but can be None when querying the DB via ORM.
        :param dgHashes (Optional): The list of EF.DG hashes.
        """
        assert isinstance(sodId, SodId)
        assert dscId is None or isinstance(dscId, CertificateId)
        assert hashAlgo is None or isinstance(hashAlgo, str)
        assert dgHashes is None or isinstance(dgHashes, DataGroupHashValues)

        self.id       = sodId
        self.dscId    = dscId
        self.hashAlgo = hashAlgo
        self.dg1Hash  = None
        self.dg2Hash  = None
        self.dg3Hash  = None
        self.dg4Hash  = None
        self.dg5Hash  = None
        self.dg6Hash  = None
        self.dg7Hash  = None
        self.dg8Hash  = None
        self.dg9Hash  = None
        self.dg10Hash = None
        self.dg11Hash = None
        self.dg12Hash = None
        self.dg13Hash = None
        self.dg14Hash = None
        self.dg15Hash = None
        self.dg16Hash = None

        dg: DataGroupHash
        for dg in (dgHashes or []):
            if dg.number == DataGroupNumber(1):
                self.dg1Hash = dg.hash
            elif dg.number == DataGroupNumber(2):
                self.dg2Hash = dg.hash
            elif dg.number == DataGroupNumber(3):
                self.dg3Hash = dg.hash
            elif dg.number == DataGroupNumber(4):
                self.dg4Hash = dg.hash
            elif dg.number == DataGroupNumber(5):
                self.dg5Hash = dg.hash
            elif dg.number == DataGroupNumber(6):
                self.dg6Hash = dg.hash
            elif dg.number == DataGroupNumber(7):
                self.dg7Hash = dg.hash
            elif dg.number == DataGroupNumber(8):
                self.dg8Hash = dg.hash
            elif dg.number == DataGroupNumber(9):
                self.dg9Hash = dg.hash
            elif dg.number == DataGroupNumber(10):
                self.dg10Hash = dg.hash
            elif dg.number == DataGroupNumber(11):
                self.dg11Hash = dg.hash
            elif dg.number == DataGroupNumber(12):
                self.dg12Hash = dg.hash
            elif dg.number == DataGroupNumber(13):
                self.dg13Hash = dg.hash
            elif dg.number == DataGroupNumber(14):
                self.dg14Hash = dg.hash
            elif dg.number == DataGroupNumber(15):
                self.dg15Hash = dg.hash
            elif dg.number == DataGroupNumber(16):
                self.dg16Hash = dg.hash
            else:
                raise ValueError(f"The list of EF.DG hashes contains unknown EF.DG number '{dg.number.native}'")

    @classmethod
    def fromSOD(cls, sod: ef.SOD, dscId: CertificateId) -> "SodTrack":
        """
        Returns EF.SOD track generated from `sod` and `dscId`
        :param `sod`: EF.SOD file.
        :param `dscId` (Optional): The ID of issuing DSC certificate which signed `sod`.
        :return: SodTrack
        """
        assert isinstance(sod, ef.SOD)
        assert isinstance(dscId, CertificateId)
        sodId = SodId.fromSOD(sod)
        hashAlgo = sod.ldsSecurityObject.dgHashAlgo['algorithm'].native
        return cls(sodId, dscId, hashAlgo, sod.ldsSecurityObject.dgHashes)

    def dgHash(self, dgNumber: DataGroupNumber) -> Optional[bytes]:
        """
        Returns hash value for the EF.DataGroup number.
        :param dgNumber: EF.DataGroup number
        :return: Bytes hash if `dgNumber` is found, otherwise None.
        """
        if dgNumber == DataGroupNumber(1):
            return self.dg1Hash
        if dgNumber == DataGroupNumber(2):
            return dgNumber
        if dgNumber == DataGroupNumber(3):
            return self.dg3Hash
        if dgNumber == DataGroupNumber(4):
            return self.dg4Hash
        if dgNumber == DataGroupNumber(5):
            return self.dg5Hash
        if dgNumber == DataGroupNumber(6):
            return self.dg6Hash
        if dgNumber == DataGroupNumber(7):
            return self.dg7Hash
        if dgNumber == DataGroupNumber(8):
            return self.dg8Hash
        if dgNumber == DataGroupNumber(9):
            return self.dg9Hash
        if dgNumber == DataGroupNumber(10):
            return self.dg10Hash
        if dgNumber == DataGroupNumber(11):
            return self.dg11Hash
        if dgNumber == DataGroupNumber(12):
            return self.dg12Hash
        if dgNumber == DataGroupNumber(13):
            return self.dg13Hash
        if dgNumber == DataGroupNumber(14):
            return self.dg14Hash
        if dgNumber == DataGroupNumber(15):
            return self.dg15Hash
        if dgNumber == DataGroupNumber(16):
            return self.dg16Hash
        return None

    def getDgHasher(self) -> hashes.Hash:
        ''' Returns hashes.Hash object of hashAlgo '''
        h = algo_utils.get_hash_algo_by_name(self.hashAlgo)
        return hashes.Hash(h, backend=default_backend())

    def contains(self, dg: DataGroup) -> bool:
        """
        Verifies if this contains hash of `dg` object.
        The function calculates hash of `dg` object using hash algorithm `hashAlgo` and
        then compares calculated hash to stored hash of `dg<num>Hash`.
        :param dg: EF.DataGroup to verify.
        :return: True if this contains the same hash of `dg` object, False otherwise.
        """
        d = self.dgHash(dg.number)
        if d is None:
            return False
        h = self.getDgHasher()
        h.update(dg.dump())
        return h.finalize() == d
