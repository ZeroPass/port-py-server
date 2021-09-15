import time
import os
import uvicorn

from asgiref.typing import ASGIApplication
from port import log
from threading import Thread
from typing import Any, Union

class HttpServer(uvicorn.Server):
    _run_thread: Thread
    def __init__(self, app: Union[ASGIApplication, str], **kwargs: Any) -> None:
        if 'log_level' in kwargs:
            ll = kwargs['log_level'].lower()
            if ll == 'verbose':
                ll = 'trace'
            kwargs['log_level'] = ll

        self._log        = log.getLogger(f'port.{app.__class__.__name__}.http.server')
        self._run_thread = Thread(target=self.run, daemon=True)
        cfg              = uvicorn.Config(app, **kwargs)
        if cfg.reload or cfg.workers > 1:
            raise ValueError("Invalid config 'reload' or `workers`")
        super().__init__(config=cfg)

    def install_signal_handlers(self):
        # Remove signal handlers of uvicorn
        pass

    def start(self):
        self._log.debug('Starting server...')
        self._run_thread.start()
        while not self.started:
            time.sleep(1e-3)
        self._log.debug('Server has started')

    def stop(self, timeout: float = None):
        self._log.debug('Stopping server...')
        try:
            self.should_exit = True
            self._run_thread.join(timeout)
            if self.config.uds:
                os.remove(self.config.uds)
            self._log.debug('Server was stopped successfully.')
        except KeyboardInterrupt:
            self._log.warning('Server was forced stopped by keyboard interrupt!')
