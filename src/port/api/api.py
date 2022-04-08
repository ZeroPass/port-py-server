import os

from base64 import b64decode
from port.proto import (
    Challenge,
    CID,
    ProtoError,
    UserId
)
from port.proto.utils import bytes_to_int

from pymrtd import ef
from typing import List, Optional

from .base import JsonRpcApi, portapi
from .utils import try_deserialize, try_deserialize_csig

class PortApi(JsonRpcApi):
    """
    Port public JSON-RPC API.
    """
    __name__ = 'api' # api name used for logging

# RPC API methods
    # API: port.ping
    @portapi
    def ping(self, ping: int) -> dict: # pylint: disable=no-self-use
        """
        Play ping-pong with server.
        :`ping`: Client ping number.
        :return: `pong` number.
        """
        pong = (bytes_to_int(os.urandom(4)) + ping) % 0xFFFFFFFF
        return { "pong": pong }

    # API: port.get_challenge
    @portapi
    def get_challenge(self, uid: str) -> dict:
        """
        Function returns challenge that passport needs to sign.
        Challenge is base64 encoded.
        :param `uid`: Base64 encoded UserId to generate the challenge for
        :return:
                `challenge` - base64 encoded challenge.
                `expires`   - unix timestamp of time when challenge will expire.
        """
        uid = try_deserialize(lambda: UserId.fromBase64(uid), self._log)
        c, cet = self._proto.getChallenge(uid)
        return { "challenge": c.toBase64(), "expires": int(cet.timestamp()) }

    # API: port.cancel_challenge
    @portapi
    def cancel_challenge(self, challenge: str) -> None:
        """
        Function erases challenge from server.
        :param `challenge`: base64 encoded string
        :return:
                 Nothing if success, else error
        """
        challenge = try_deserialize(lambda: Challenge.fromBase64(challenge), self._log)
        self._proto.cancelChallenge(challenge.id)

    # API: port.register
    @portapi
    def register(self, uid: str, sod: str, dg15: Optional[str] = None, dg14: Optional[str] = None, override: Optional[bool] = None) -> dict:
        """
        Register new user account with eMRTD attestation.

        :param `uid`:   Base64 encoded UserId.
        :param `sod`:   Base64 encoded eMRTD SOD file.
        :param `dg15`:  Base64 encoded eMRTD DG15 file (optional but required if passport supports AA).
        :param `dg14`:  Base64 encoded eMRTD DG14 file (optional but required if pubkey in dg15 uses EC key).
        :param `override`: If True, override the existing attestation for `uid`.
        :return: Dictionary object, specific to the server implementation.
        """
        if override:
            ProtoError("Registration override not supported")
        uid   = try_deserialize(lambda: UserId.fromBase64(uid), self._log)
        sod   = try_deserialize(lambda: ef.SOD.load(b64decode(sod)), self._log)
        if dg15 is not None:
            dg15  = try_deserialize(lambda: ef.DG15.load(b64decode(dg15)), self._log)
        if dg14 is not None:
            dg14 = try_deserialize(lambda: ef.DG14.load(b64decode(dg14)), self._log)
        return self._proto.register(uid, sod, dg15, dg14, override if override is not None else False)

    # API: port.get_assertion
    @portapi
    def get_assertion(self, uid: str, cid: str, csigs: List[str]) -> dict:
        """
        Returns authn assertion for eMRTD active authentication.
        :param `uid`:   User id
        :param `cid`:   Base64 encoded Challenge id.
        :param `csigs`: Base64 encoded challenge signatures.
        :return: Dictionary object, specific to the server implementation
        """
        uid = try_deserialize(lambda: UserId.fromBase64(uid), self._log)
        cid = try_deserialize(lambda: CID.fromHex(cid))
        csigs = try_deserialize_csig(csigs, self._log)
        return self._proto.getAssertion(uid, cid, csigs)
