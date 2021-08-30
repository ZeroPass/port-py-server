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

# RPC API methods
    # API: port.ping
    @portapi
    def ping(self, ping: int) -> dict:
        """
        Play ping-pong with server.
        :`ping`: Client ping number.
        :return: `pong` number.
        """
        try:
            pong = (bytes_to_int(os.urandom(4)) + ping) % 0xFFFFFFFF
            return { "pong": pong }
        except Exception as e:
            self._handle_exception(e)

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
        try:
            uid = try_deserialize(lambda: UserId.fromBase64(uid))
            c, cet = self._proto.createNewChallenge(uid)
            return { "challenge": c.toBase64(), "expires": int(cet.timestamp()) }
        except Exception as e:
            self._handle_exception(e)

    # API: port.cancel_challenge
    @portapi
    def cancel_challenge(self, challenge: str) -> None:
        """
        Function erases challenge from server.
        :param `challenge`: base64 encoded string
        :return:
                 Nothing if success, else error
        """
        try:
            challenge = try_deserialize(lambda: Challenge.fromBase64(challenge))
            self._proto.cancelChallenge(challenge.id)
            return None
        except Exception as e:
            self._handle_exception(e)

    # API: port.register
    @portapi
    def register(self, uid: str, sod: str, dg15: str, cid: str, csigs: List[str], dg14: Optional[str] = None, override: Optional[bool] = None) -> dict:
        """
        Register new user. It returns back empty dict.

        :param `uid`:   Base64 encoded UserId.
        :param `sod`:   Base64 encoded eMRTD SOD file.
        :param `dg15`:  Base64 encoded eMRTD DG15 file.
        :param `cid`:   Hex encoded Challenge id.
        :param `csigs`: Base64 encoded challenge signatures.
        :param `dg14`:  Base64 encoded eMRTD DG14 file (optional).
        :param `override`: If True, override the existing attestation for `uid`.
        :return: Dictionary object, specific to server implementation.
        """
        try:
            if override:
                ProtoError("Registration override not supported")
            uid   = try_deserialize(lambda: UserId.fromBase64(uid))
            sod   = try_deserialize(lambda: ef.SOD.load(b64decode(sod)))
            dg15  = try_deserialize(lambda: ef.DG15.load(b64decode(dg15)))
            cid   = try_deserialize(lambda: CID.fromHex(cid))
            csigs = try_deserialize_csig(csigs)
            if dg14 is not None:
                dg14 = try_deserialize(lambda: ef.DG14.load(b64decode(dg14)))
            return self._proto.register(uid, sod, dg15, cid, csigs, dg14)
        except Exception as e:
            self._handle_exception(e)

    # API: port.get_assertion
    @portapi
    def get_assertion(self, uid: str, cid: str, csigs: List[str]) -> dict:
        """
        Returns authn assertion for eMRTD active authentication.
        :param `uid`:   User id
        :param `cid`:   Base64 encoded Challenge id.
        :param `csigs`: Base64 encoded challenge signatures.
        :return: Dictionary object, specific to server implementation
        """
        try:
            uid = try_deserialize(lambda: UserId.fromBase64(uid))
            cid = try_deserialize(lambda: CID.fromHex(cid))
            csigs = try_deserialize_csig(csigs)
            return self._proto.getAssertion(uid, cid, csigs)
        except Exception as e:
            self._handle_exception(e)
