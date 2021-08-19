import os
import port.log as log

from base64 import b64decode
from jsonrpc import Dispatcher, JSONRPCResponseManager as JRPCRespMgr
from jsonrpc.exceptions import JSONRPCDispatchException
from port import proto
from port.settings import Config
from pymrtd import ef
from werkzeug.wrappers import Request, Response
from werkzeug.serving import run_simple
from typing import Callable, List, NoReturn

def try_deser(f):
    try:
        return f()
    except:
        raise proto.ProtoError("Bad parameter") from None

def _b64csigs_to_bcsigs(str_csigs: List[str]) -> List[bytes]:
    """ Convert list of base64 encoded signatures to list of byte signatures """
    csigs = []
    for scsig in str_csigs:
        csigs.append(try_deser(lambda sig=scsig: b64decode(sig)))
    return csigs

class PortApiServer:
    """ Port Api server """
    api_method_prefix = "port"

    def __init__(self, db: proto.StorageAPI, config: Config):
        self._conf  = config.api_server
        self._proto = proto.PortProto(db, config.challenge_ttl)
        self._log   = log.getLogger("port.api")

        # Register rpc api methods
        self.__init_api()

    def start(self):
        self._proto.start()
        run_simple(self._conf.host, self._conf.port, self.__handle_request, use_reloader=False, ssl_context=self._conf.ssl_ctx, threaded=True)

    def stop(self):
        self._proto.stop()

    def portapi(api_f: Callable): #pylint: disable=no-self-argument
        def wrapped_api_f(self, *args, **kwargs):
            self.__log_api_call(api_f, **kwargs) #pylint: disable=protected-access
            ret=api_f(self, *args, **kwargs) #pylint: disable=not-callable
            self.__log_api_response(api_f, ret) #pylint: disable=protected-access
            return ret
        return wrapped_api_f

# RPC API methods
    # API: port.ping
    @portapi
    def ping(self, ping: int) -> dict:
        """
        Function returns challenge that passport needs to sign.
        Challenge is base64 encoded.
        """
        try:
            pong = (proto.utils.bytes_to_int(os.urandom(4)) + ping) % 0xFFFFFFFF
            return { "pong": pong }
        except Exception as e:
            self.__handle_exception(e)

    # API: port.getChallenge
    @portapi
    def getChallenge(self, uid: str) -> dict:
        """
        Function returns challenge that passport needs to sign.
        Challenge is base64 encoded.
        :param uid: base64 encoded UserId to generate the challenge for
        :return:
                'challenge' - base64 encoded challenge
                'expires'   - unix timestamp of time when challenge will expire
        """
        try:
            uid = try_deser(lambda: proto.UserId.fromBase64(uid))
            c, cet = self._proto.createNewChallenge(uid)
            return { "challenge": c.toBase64(), "expires": int(cet.timestamp()) }
        except Exception as e:
            self.__handle_exception(e)

    # API: port.cancelChallenge
    @portapi
    def cancelChallenge(self, challenge: str) -> None:
        """
        Function erases challenge from server.
        :param challenge: base64 encoded string
        :return:
                 Nothing if success, else error
        """
        try:
            challenge = try_deser(lambda: proto.Challenge.fromBase64(challenge))
            self._proto.cancelChallenge(challenge.id)
            return None
        except Exception as e:
            self.__handle_exception(e)

    # API: port.register
    @portapi
    def register(self, uid: str, sod: str, dg15: str, cid: str, csigs: List[str], dg14: str = None) -> dict:
        """
        Register new user. It returns back empty dict.

        :param uid:   base64 encoded UserId
        :param sod:   base64 encoded eMRTD SOD file
        :param dg15:  base64 encoded eMRTD DG15 file
        :param cid:   hex encoded Challenge id
        :param csigs: base64 encoded challenge signatures
        :param dg14:  base64 encoded eMRTD DG14 file (optional)
        :return: Dictionary object, specific to server implementation
        """
        try:
            uid   = try_deser(lambda: proto.UserId.fromBase64(uid))
            sod   = try_deser(lambda: ef.SOD.load(b64decode(sod)))
            dg15  = try_deser(lambda: ef.DG15.load(b64decode(dg15)))
            cid   = try_deser(lambda: proto.CID.fromHex(cid))
            csigs = _b64csigs_to_bcsigs(csigs)
            if dg14 is not None:
                dg14 = try_deser(lambda: ef.DG14.load(b64decode(dg14)))
            return self._proto.register(uid, sod, dg15, cid, csigs, dg14)
        except Exception as e:
            self.__handle_exception(e)

    # API: port.get_assertion
    @portapi
    def get_assertion(self, uid: str, cid: str, csigs: List[str]) -> dict:
        """
        Returns authn assertion for eMRTD active authentication.
        :param uid:   User id
        :param cid:   base64 encoded Challenge id
        :param csigs: base64 encoded challenge signatures
        :return: Dictionary object, specific to server implementation
        """
        try:
            uid = try_deser(lambda: proto.UserId.fromBase64(uid))
            cid = try_deser(lambda: proto.CID.fromHex(cid))
            csigs = _b64csigs_to_bcsigs(csigs)
            return self._proto.getAssertion(uid, cid, csigs)
        except Exception as e:
            self.__handle_exception(e)

    def __handle_exception(self, e: Exception)-> NoReturn:
        if isinstance(e, proto.ProtoError):
            self._log.warning("Request proto error: %s", e)
            raise JSONRPCDispatchException(e.code, str(e)) from e

        if isinstance(e, proto.SeEntryNotFound):
            self._log.warning("Request storage error: %s", e)
            raise JSONRPCDispatchException(404, str(e)) from e

        if isinstance(e, proto.SeEntryAlreadyExists):
            self._log.warning("Request storage error: %s", e)
            raise JSONRPCDispatchException(409, str(e)) from e

        self._log.error("Unhandled exception encountered, e=%s", e)
        raise JSONRPCDispatchException(500, "Internal Server Error") from e

# Request handler
    @Request.application
    def __handle_request(self, request) -> Response:
        response = JRPCRespMgr.handle(
            request.data,
            self._req_disp
        )
        if response is not None:
            return Response(response.json, mimetype='application/json')
        return Response()

    def __init_api(self):
        self._req_disp = Dispatcher()

        def add_api_meth(api_f, name):
            # method format: <api_prefix>.<methodName>
            port_api_f = lambda *args, **kwargs: api_f(self, *args, **kwargs)
            self._req_disp.add_method(port_api_f, "{}.{}".format(PortApiServer.api_method_prefix, name))

        # register methods with @portapi decorator as rpc api handler
        import inspect
        meths = inspect.getmembers(PortApiServer, predicate=inspect.isfunction)
        for m in meths:
            if m[1].__name__ == "wrapped_api_f":
                add_api_meth(m[1], m[0])

    def __log_api_call(self, f, **kwargs):
        if self._log.level <= log.VERBOSE:
            self._log.debug(":%s() ==>", f.__name__)
            for a, v in kwargs.items():
                self._log.verbose(" %s: %s", a, v)

    def __log_api_response(self, f, resp: dict):
        if self._log.level <= log.VERBOSE:
            self._log.debug(":%s() <==", f.__name__)
            if resp is not None:
                for a, v in resp.items():
                    self._log.verbose(" %s: %s", a, v)
