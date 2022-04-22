import inspect
import orjson

from abc import abstractmethod
from functools import wraps

from jsonrpc import Dispatcher, JSONRPCResponseManager
from jsonrpc.exceptions import (
    JSONRPCDispatchException,
    JSONRPCInvalidRequest,
    JSONRPCInvalidRequestException,
    JSONRPCParseError
)
from jsonrpc.jsonrpc2 import JSONRPC20Request, JSONRPC20Response

from port import log
from port.database import SeEntryAlreadyExists, SeEntryNotFound
from port.proto import (
    PeConflict,
    PeInvalidOrMissingParam,
    PeNotFound,
    PortProto,
    ProtoError
)

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse, Response
from starlette.requests import Request
from starlette.routing import Route

from typing import Any, Callable, NoReturn, Optional

from .utils import get_invalid_func_param_msg

class JsonRpcApiError(Exception):
    pass

def portapi(api_f: Callable):
    @wraps(api_f)
    def _wrapped_api_f(*args, **kwargs): # pylint: disable=inconsistent-return-statements
        assert len(args) > 0 and isinstance(args[0], IApi)
        self = args[0]
        try:
            self._log_api_call(api_f, **kwargs) #pylint: disable=protected-access
            ret  = api_f(*args, **kwargs)
            self._log_api_response(api_f, ret) #pylint: disable=protected-access
            return ret
        except Exception as e:
            self._handle_exception(e) # pylint: disable=protected-access
    setattr(_wrapped_api_f, '__is_portapi_func__', True)
    return _wrapped_api_f

class IApi:
    """ Base API interface.  """

    def __init__(self, proto: PortProto, logLevel: Optional[log.LogLevelType] = None):
        self._proto = proto
        self._log   = log.getLogger(
            "port." + getattr(self, "__name__", type(self).__name__),
            logLevel = logLevel
        )
        # Register rpc API  methods
        self._init_api()

    @abstractmethod
    def _init_api(self):
        pass

    @abstractmethod
    def _raise_api_exception(self, code: int, msg: str, e: Optional[Exception]) -> NoReturn:
        pass

    def _handle_exception(self, e: Exception)-> NoReturn:
        if isinstance(e, ProtoError):
            self._log.warning("Request proto error: %s", e)
            self._raise_api_exception(e.code, str(e), e)

        if isinstance(e, SeEntryNotFound):
            self._log.warning("Request storage error: %s", e)
            self._raise_api_exception(PeNotFound.code, str(e), e)

        if isinstance(e, SeEntryAlreadyExists):
            self._log.warning("Request storage error: %s", e)
            self._raise_api_exception(PeConflict.code, str(e), e)

        if isinstance(e, TypeError):
            msg = get_invalid_func_param_msg(e)
            if msg:
                self._log.warning("Invalid parameters: %s", e)
                self._raise_api_exception(PeInvalidOrMissingParam.code, 'Invalid params: ' + msg, e)

        self._log.error("Unhandled exception encountered, e='%s'", e)
        self._log.exception(e)
        self._raise_api_exception(500, 'Internal Server Error', e)

    def _build_api(self, register_api: Callable[[str, Callable], None]):
        # register methods with @portapi decorator as rpc api handler
        methods = inspect.getmembers(self, predicate=inspect.ismethod)
        for name, method in methods:
            if getattr(method, '__is_portapi_func__', False):
                register_api(name, method)

    def _log_api_call(self, f, **kwargs):
        if self._log.level <= log.DEBUG:
            self._log.debug(":%s() ==>", f.__name__)
            if self._log.level <= log.VERBOSE:
                for a, v in kwargs.items():
                    self._log.verbose(" %s: %s", a, v)

    def _log_api_response(self, f, resp: Any):
        if self._log.level <= log.DEBUG:
            self._log.debug(":%s() <==", f.__name__)
            if self._log.level <= log.VERBOSE:
                if resp is not None and self._log.level :
                    if isinstance(resp, dict):
                        for a, v in resp.items():
                            self._log.verbose(" %s: %s", a, v)
                    else:
                        self._log.verbose(resp)

def _orjson_dumps_default(obj):
    if isinstance(obj, bytes):
        # Expects utf-8 encoded string e.g. what b64encode returns
        return obj.decode(encoding='utf-8')
    return obj

class ORJSONResponse(JSONResponse):
    media_type = "application/json"

    def render(self, content: Any) -> bytes:
        return orjson.dumps(content, default=_orjson_dumps_default) # pylint: disable=no-member

class JsonRpcApi(IApi, Starlette):
    """
    Class implements JSON-RPC API interface from IApi as `Starlette` application.
    It acts as intermedian layer between IApi and API implementation for JSON RPC based API.
    API Methods of subclass are automatically registered through `@portapi` function decorator.
    """

    _api_method_prefix = "port"

    def __init__(self, proto: PortProto, logLevel: Optional[log.LogLevelType] = None, debug = False):
        """
        Constructs new JSON RPC API.
        :param `proto`: Port protocol object.
        :param `debug`: If true `Starlette` will be initialized in debug mode.
        :raises `JsonRpcApiError`: If there is duplicate API method.
        """

        self._req_dispatcher = Dispatcher()
        IApi.__init__(self, proto, logLevel=logLevel)

        # init Starlette
        routes = [
            Route("/", endpoint=self._handle_request, methods=["POST"])
        ]

        middleware = [
            Middleware(CORSMiddleware,
                       allow_methods=['*'],
                       allow_origins=['*'],
                       allow_credentials=True)
        ]
        Starlette.__init__(self, debug=debug, routes=routes,  middleware=middleware)

    @property
    def count(self):
        """ Returns the number of registered API methods. """
        return len(self._req_dispatcher)

    def registerApiMethod(self, name, func):
        """"
        Registers new API method.
        :param `name`: API method name.
        :param `func`: API method function.
        """
        self._log.debug("Registering API method: '%s.%s'", self._api_method_prefix, name)
        if name in self._req_dispatcher:
            self._log.error("Can't register existing API method: '%s'", name)
            raise JsonRpcApiError(f"Can't register existing API method: '{name}'")
        self._req_dispatcher.add_method(func, \
            f'{self._api_method_prefix}.{name}')

    def unregisterApiMethod(self, method: str):
        """
        Unregisters API `method`.
        :param `method`: The API method to unregister
        """
        if self._api_method_prefix and \
            not method.startswith(f'{self._api_method_prefix}'):
            method = f'{self._api_method_prefix}.{method}'
        if method in self._req_dispatcher:
            del self._req_dispatcher[method]
            self._log.info("API method '%s' was unregistered.", method)

    def _init_api(self):
        self._build_api(self.registerApiMethod)

    async def _handle_request(self, request: Request) -> Response:
        ct = request.headers['content-type'].split(';')
        if len(ct) == 0 or ct[0].strip() != 'application/json':
            return Response('Invalid content type. API only supports application/json.',
                status_code=415, media_type='text/plain')
        return self._make_response(await self._dispatch_request(request))

    async def _dispatch_request(self, request: Request) -> Optional[JSONRPC20Response]:
        try:
            data = orjson.loads(await request.body()) # pylint: disable=no-member
        except (orjson.JSONDecodeError, ValueError): # pylint: disable=no-member
            return JSONRPC20Response(error=JSONRPCParseError()._data) # pylint: disable=protected-access
        try:
            request = JSONRPC20Request.from_data(data)
        except JSONRPCInvalidRequestException:
            return JSONRPC20Response(error=JSONRPCInvalidRequest()._data) # pylint: disable=protected-access

        return await run_in_threadpool(
            JSONRPCResponseManager.handle_request, request, self._req_dispatcher
        )

    @staticmethod
    def _make_response(jrpcResponse: Optional[JSONRPC20Response]) -> Response:
        return ORJSONResponse(jrpcResponse.data if jrpcResponse else None, media_type='application/json')

    def _raise_api_exception(self, code: int, msg: str, e: Optional[Exception]) -> NoReturn:
        raise JSONRPCDispatchException(code, msg) from e
