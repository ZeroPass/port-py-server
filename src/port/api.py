import os, port.log as log

from base64 import b64decode

from jsonrpc import Dispatcher, JSONRPCResponseManager as JRPCRespMgr
from jsonrpc.exceptions import JSONRPCDispatchException, JSONRPCServerError, JSONRPCInternalError

from port import proto
from port.settings import Config

from pymrtd import ef
from typing import Callable, List, Union

from werkzeug.wrappers import Request, Response
from werkzeug.serving import run_simple

def try_deser(f):
    try:
        return f()
    except:
        raise proto.ProtoError("Bad parameter")

def _b64csigs_to_bcsigs(str_csigs: List[str]) -> List[bytes]:
    """ Convert list of base64 encoded signatures to list of byte signatures """
    csigs = []
    for scsig in str_csigs:
        csigs.append(try_deser(lambda: b64decode(scsig)))
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
        run_simple(self._conf.host, self._conf.port, self.__handle_request, use_reloader=True, ssl_context=self._conf.ssl_ctx, threaded=True)

    def stop(self):
        self._proto.stop()

    def portapi(api_f: Callable): # pylint: disable=no-self-argument
        def wrapped_api_f(self, *args, **kwargs):
            self.__log_api_call(api_f, **kwargs)
            ret=api_f(self, *args, **kwargs) # pylint: disable=not-callable
            self.__log_api_response(api_f, ret)
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
            pong = int.from_bytes(os.urandom(4), 'big')
            return { "pong": pong }
        except Exception as e:
            return self.__handle_exception(e)

    # API: port.getChallenge
    @portapi
    def getChallenge(self, uid: str) -> dict:
        """
        Function returns challenge that passport needs to sign.
        Challenge is base64 encoded.
        :param uid: base64 encoded UserId to generate the challenge for
        """
        try:
            uid = try_deser(lambda: proto.UserId.fromBase64(uid))
            c   = self._proto.createNewChallenge(uid)
            return { "challenge": c.toBase64() }
        except Exception as e:
            return self.__handle_exception(e)

    # API: port.cancelChallenge
    @portapi
    def cancelChallenge(self, challenge: str) -> Union[None, dict]:
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
            return self.__handle_exception(e)

    # API: port.register
    @portapi
    def register(self, uid: str, sod: str, dg15: str, cid: str, csigs: List[str], dg14: str = None) -> dict:
        """
        Register new user. It returns back to the client userId which is publicKey address,
        session key and session expiration time.

        :param uid:   base64 encoded UserId
        :param sod:   base64 encoded eMRTD SOD file
        :param dg15:  base64 encoded eMRTD DG15 file
        :param cid:   hex encoded Challenge id
        :param csigs: base64 encoded challenge signatures
        :param dg14:  base64 encoded eMRTD DG14 file (optional)
        :return:
                 'uid'         - base64 encoded user id
                 'session_key' - base64 encoded session key
                 'expires'     - unix timestamp of time when session will expire
        """

        try:
            uid   = try_deser(lambda: proto.UserId.fromBase64(uid))
            sod   = try_deser(lambda: ef.SOD.load(b64decode(sod)))
            dg15  = try_deser(lambda: ef.DG15.load(b64decode(dg15)))
            cid   = try_deser(lambda: proto.CID.fromHex(cid))
            csigs = _b64csigs_to_bcsigs(csigs)
            if dg14 is not None:
                dg14 = try_deser(lambda: ef.DG14.load(b64decode(dg14)))

            uid, sk, set = self._proto.register(uid, sod, dg15, cid, csigs, dg14)
            return { "uid": uid.toBase64(), "session_key": sk.toBase64(), "expires": int(set.timestamp()) }
        except Exception as e:
            return self.__handle_exception(e)

    # API: port.login
    @portapi
    def login(self, uid: str, cid: str, csigs: List[str], dg1: str = None) -> dict:
        """
        It returns back session key and session expiration time.

        :param uid:   User id
        :param cid:   base64 encoded Challenge id
        :param csigs: base64 encoded challenge signatures
        :return:
                 'session_key' - base64 encoded session key
                 'expires'     - unix timestamp of time when session will expire
        """
        try:
            uid = try_deser(lambda: proto.UserId.fromBase64(uid))
            cid = try_deser(lambda: proto.CID.fromHex(cid))
            csigs = _b64csigs_to_bcsigs(csigs)
            if dg1 is not None:
                dg1 = try_deser(lambda: ef.DG1.load(b64decode(dg1)))

            sk, set = self._proto.login(uid, cid, csigs, dg1)
            return { "session_key": sk.toBase64(), "expires": int(set.timestamp()) }
        except Exception as e:
            return self.__handle_exception(e)

    # API: port.sayHello
    @portapi
    def sayHello(self, uid: str, mac: str) -> dict:
        """
        It returns back greeting message based on whether user is anonymous or not.

        :param uid: User id
        :param mac: session mac over api name and uid
        :return:
                 'msg' - greeting message
        """
        try:
            uid = try_deser(lambda: proto.UserId.fromBase64(uid))
            mac = try_deser(lambda: b64decode(mac))
            msg = self._proto.sayHello(uid, mac)
            return { "msg": msg }
        except Exception as e:
            return self.__handle_exception(e)

# Request handler
    @Request.application
    def __handle_request(self, request):
        response = JRPCRespMgr.handle(
            request.data,
            self._req_disp
        )
        if response is not None:
            return Response(response.json, mimetype='application/json')
        return Response()

    def __handle_exception(self, e: Exception)-> dict:
        if isinstance(e, proto.ProtoError):
            self._log.debug("Request proto error: {}".format(e))
            raise JSONRPCDispatchException(e.code, str(e))

        if isinstance(e, proto.SeEntryNotFound):
            self._log.debug("Request storage error: {}".format(e))
            raise JSONRPCDispatchException(404, str(e))

        if isinstance(e, proto.SeEntryAlreadyExists):
            self._log.debug("Request storage error: {}".format(e))
            raise JSONRPCDispatchException(409, str(e))

        self._log.error("Unhandled exception encountered, e={}".format(e))
        raise JSONRPCDispatchException(500, "Internal Server Error")

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
            self._log.debug(":{}() ==>".format(f.__name__))
            for a, v in kwargs.items():
                self._log.verbose(" {}: {}".format(a, v))

    def __log_api_response(self, f, resp: dict):
        if self._log.level <= log.VERBOSE:
            self._log.debug(":{}() <==".format(f.__name__))
            if(resp is not None):
                for a, v in resp.items():
                    self._log.verbose(" {}: {}".format(a, v))