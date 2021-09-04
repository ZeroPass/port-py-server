import inspect
import orjson

from abc import abstractmethod

from jsonrpc import Dispatcher, JSONRPCResponseManager
from jsonrpc.exceptions import (
    JSONRPCDispatchException,
    JSONRPCInvalidRequest,
    JSONRPCInvalidRequestException,
    JSONRPCParseError
)
from jsonrpc.jsonrpc2 import JSONRPC20Request, JSONRPC20Response

from port import log
from port.proto import (
    PeConflict,
    PeNotFound,
    PortProto,
    ProtoError,
    SeEntryAlreadyExists,
    SeEntryNotFound
)

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse, Response
from starlette.requests import Request
from starlette.routing import Route

from typing import Any, Callable, NoReturn, Optional

class PortApiError(Exception):
    pass

def portapi(api_f: Callable): #pylint: disable=no-self-argument
    def _wrapped_api_f(*args, **kwargs):
        assert len(args) > 0 and isinstance(args[0], IApi)
        self = args[0]
        try:
            self._log_api_call(api_f, **kwargs) #pylint: disable=protected-access
            ret  = api_f(*args, **kwargs) #pylint: disable=not-callable
            self._log_api_response(api_f, ret) #pylint: disable=protected-access
            return ret
        except Exception as e:
            self._handle_exception(e) # pylint: disable=protected-access
    return _wrapped_api_f

class IApi:
    """ Base API interface.  """

    api_name = 'api' # api name used for logging

    def __init__(self, proto: PortProto):
        self._proto = proto
        self._log   = log.getLogger("port." + self.api_name)

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

        self._log.error("Unhandled exception encountered, e='%s'", e)
        self._raise_api_exception(500, 'Internal Server Error', e)

    def _build_api(self, register_api: Callable[[str, Callable], None]):
        # register methods with @portapi decorator as rpc api handler
        methods = inspect.getmembers(self, predicate=inspect.ismethod)
        for name, method in methods:
            if method.__name__ == "_wrapped_api_f":
                self._log.debug("Registering API function: '%s'", name)
                register_api(name, method)

    def _log_api_call(self, f, **kwargs):
        if self._log.level <= log.VERBOSE:
            self._log.debug(":%s() ==>", f.__name__)
            for a, v in kwargs.items():
                self._log.verbose(" %s: %s", a, v)

    def _log_api_response(self, f, resp: dict):
        if self._log.level <= log.VERBOSE:
            self._log.debug(":%s() <==", f.__name__)
            if resp is not None:
                for a, v in resp.items():
                    self._log.verbose(" %s: %s", a, v)

class ORJSONResponse(JSONResponse):
    media_type = "application/json"

    def render(self, content: Any) -> bytes:
        return orjson.dumps(content)

class JsonRpcApi(IApi, Starlette):
    """
    Class implements JSON-RPC API interface from IApi as `Starlette` application.
    It acts as intermedian layer between IApi and API implementation for JSON RPC based API.
    API Methods of subclass are automatically registered through `@portapi` function decorator.
    """

    _api_method_prefix = "port"

    def __init__(self, proto: PortProto, debug = False):
        """
        Constructs new JSON RPC API.
        :param `proto`: Port protocol object.
        :param `debug`: If true `Starlette` will be initialized in debug mode.
        :raises `PortApiError`: If there is duplicate API method.
        """

        self._req_dispatcher = Dispatcher()
        IApi.__init__(self, proto)

        # init Starlette
        routes = [
            Route("/", endpoint=self._handle_request, methods=["POST"])
        ]
        Starlette.__init__(self, debug=debug, routes=routes)

    def unregisterApiMethod(self, name: str):
        if name in self._req_dispatcher:
            del self._req_dispatcher[name]

    def _init_api(self):
        def register_api_method(name, api_f):
            if name in self._req_dispatcher:
                self._log.error("Can't register existing API method: '%s'", name)
                PortApiError("Can't register existing API method: '{}'".format(name))
            self._req_dispatcher.add_method(api_f, \
                "{}.{}".format(self._api_method_prefix, name))
        self._build_api(register_api_method)
        self._log.debug("%s API methods registered.", len(self._req_dispatcher))

    async def _handle_request(self, request: Request) -> Response:
        if request.headers['content-type'] != 'application/json':
            return Response('Invalid content type. API only supports application/json.',
                status_code=415, media_type='text/plain')
        return await self._dispatch_request(request)

    async def _dispatch_request(self, request: Request) -> ORJSONResponse:
        try:
            data = orjson.loads(await request.body())
        except (orjson.JSONDecodeError, ValueError):
            return JSONRPC20Response(error=JSONRPCParseError()._data) # pylint: disable=protected-access
        try:
            request = JSONRPC20Request.from_data(data)
        except JSONRPCInvalidRequestException:
            return JSONRPC20Response(error=JSONRPCInvalidRequest()._data) # pylint: disable=protected-access

        response = await run_in_threadpool(
            JSONRPCResponseManager.handle_request, request, self._req_dispatcher
        )
        if response is not None:
            return ORJSONResponse(response.data, media_type='application/json')
        return ORJSONResponse()

    def _raise_api_exception(self, code: int, msg: str, e: Optional[Exception]) -> NoReturn:
        raise JSONRPCDispatchException(code, msg) from e
