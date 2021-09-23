import ctypes
import os
import sys
import time
import uvicorn
import uvicorn.config

from asgiref.typing import ASGIApplication
from port import log
from threading import Thread, get_ident
from typing import Any, Optional

UVICORN_DEFAULT_LOGGING_CONFIG: dict = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(levelprefix)s %(message)s",
            "use_colors": None,
        },
        "access": {
            "()": "uvicorn.logging.AccessFormatter",
            "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
        },
    },
    "loggers": {
        "uvicorn": { "level": "INFO"},
        "uvicorn.error": {"level": "INFO"},
        "uvicorn.access": { "level": "INFO"},
    }
}

class HttpServer(uvicorn.Server):
    """
    Http ASGI server which runs uvicorn server loop on thread.
    """

    app: ASGIApplication
    _run_thread: Thread
    _ptid = None # parent thread ID - the thread ID of thread which created HttpServer instance

    def __init__(self, app: ASGIApplication, **kwargs: Any) -> None:
        """
        Initializes new `HttpServer` instance with ASGI `app`.
        Note: If `kwargs` contains param `log_level`, the uvicorn log level
              will be changed for all `HttpServer` instances.

        :app: The ASGI application to host.
        :kwargs: The config arguments to initialize underlaying `uvicorn` server instance.
                 See `uvicorn.Config` for available options.
        """
        self.app = app
        logLevel = None
        if 'log_level' in kwargs:
            logLevel = kwargs['log_level']
            if isinstance(logLevel, str):
                ll = logLevel.lower() # uvicorn log level
                if ll == 'verbose':
                    ll = 'trace'
                kwargs['log_level'] = ll

        self._log = log.getLogger(
            f'port.{getattr(app, "__name__", type(app).__name__)}.http.server',
            logLevel=logLevel
        )
        self._ptid       = get_ident()
        self._run_thread = Thread(target=self._run, daemon=True)

        if 'log_config' not in kwargs:
            kwargs['log_config'] = UVICORN_DEFAULT_LOGGING_CONFIG

        cfg = uvicorn.Config(self.app, **kwargs)
        if cfg.reload or cfg.workers > 1:
            raise ValueError("Invalid config 'reload' or `workers`")
        super().__init__(config=cfg)

    def install_signal_handlers(self):
        # Remove signal handlers of uvicorn
        pass

    def start(self) -> bool:
        """
        Starts HTTP server.
        :return: True if server has started, otherwise False.
                 Note, False is returned in cases when server was forced to stop.
        """
        self._log.info('Starting server...')
        self.should_exit = False
        self.force_exit  = False
        self._run_thread.start()
        while not self.started:
            time.sleep(1e-3)
            if self.should_exit or self.force_exit:
                return False
        self._log.info('Server has started')
        return True

    def stop(self, timeout: Optional[float] = None):
        """
        Stops HTTP server.
        :param `timeout`: How much time to wait for the run thread to exit before trying to force kill thread.
        """
        if not self.started:
            return
        self._log.info('Stopping server...')
        try:
            self.should_exit = True
            self._run_thread.join(timeout)
            if self._run_thread.is_alive():
                self._log.warning('The run thread has not exit before timeout, trying to force stop...')
                if not self._forceStop() or self._run_thread.is_alive():
                    raise Exception("Failed to force stop run thread")
            if self.config.uds:
                os.remove(self.config.uds)
            self._log.info('Stopping server...SUCCESS')
        except KeyboardInterrupt:
            self._log.warning('Server was forced stopped!')
        except Exception as e:
            self._log.error(str(e))

    def _run(self):
        """
        Server thread main procedure.
        When `SystemExit` is thrown by underlaying uvicorn server (call to `sys.exit`) or
        unhandled exception occurs, function raises `SystemExit` in parent thread (self._ptid).
        If an exception couldn't be risen in parent thread then `os._exit` is called.
        """
        try:
            self.run()
        except SystemExit as e:
            # Can happen when and uvicorn has called sys.exit
            # or _forceStop() was called. In the latter case
            # should_exit must be True here.
            if not self.should_exit:
                self._log.critical("Unexpected exit with code=%s was called within run thread", e.code)
                self._raiseExitInParentOrExit(exitCode=e.code)
        except: # pylint: disable=bare-except
            self._log.critical("Unhandled exception encountered within run thread:")
            self._log.exception(sys.exc_info()[1])
            self._raiseExitInParentOrExit(exitCode=1)

    def _raiseExitInParentOrExit(self, exitCode):
        self.should_exit = True
        self.force_exit  = True
        self._log.critical("Raising SystemExit exception in parent thread=%s", self._ptid)
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(self._ptid,
            ctypes.py_object(SystemExit))
        if res == 0 or res > 1:
            if res > 1:
                ctypes.pythonapi.PyThreadState_SetAsyncExc(self._ptid, 0)
            self._log.critical("Couldn't forward exception to parent thread, exiting program with code=1")
            os._exit(exitCode) # pylint: disable=protected-access

    def _forceStop(self) -> bool:
        tid = self._run_thread.ident
        if tid is None:
            return False
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid,
                ctypes.py_object(SystemExit))
        if res == 0 or res > 1:
            if res > 1:
                ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, 0)
            return False
        self._run_thread.join(0.1)
        return True
