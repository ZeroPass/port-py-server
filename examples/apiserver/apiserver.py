#!/usr/bin/python
import argparse
import coloredlogs
import os
import sys
import yaml

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

_script_path = Path(os.path.dirname(sys.argv[0]))
#sys.path.append(str(_script_path / Path("../../")))

from port import log
from port.config import ServerConfig, defaultArg, LogLevelValidator, ArgumentHelpFormatter
from port.database import (
    AccountStorage,
    CertificateStorage,
    DscStorage,
    SodTrack,
    StorageAPI
)
from port.proto import (
    Challenge,
    CID,
    PeUnauthorized,
    PortProto,
    UserId,
    utils
)

from port.server import PortServer
from pymrtd import ef
from typing import List, Optional, Tuple, Union


class DevProto(PortProto):
    def __init__(self, storage: StorageAPI, cttl: int, fc: bool, no_tcv: bool):
        super().__init__(storage, cttl)
        self._fc = fc
        self._no_tcv = no_tcv
        self._log = log.getLogger("port.dev_proto")

    def createNewChallenge(self, uid: UserId, seed: Optional[bytes] = None) -> Tuple[Challenge, datetime]:
        c, cct = super().createNewChallenge(uid, seed)
        if self._fc:
            fc = Challenge.fromhex("47E4EE7F211F73265DD17658F6E21C1318BD6C81F37598E20A2756299542EFCF")
            if c == fc:
                return (c, cct)
            self._db.deleteChallenge(c.id)
            cet = self._get_challenge_expiration(utils.time_now())
            self._db.addChallenge(uid, fc, cet)
            return (fc, cet)
        return (c, cct)

    def _get_account_expiration(self, uid: UserId, account: Optional[AccountStorage], sod: SodTrack, dsc: DscStorage) -> Optional[datetime]: #pylint: disable=no-self-use,unused-argument
        """Return 1 minute expiration time"""
        if account is not None and account.expires is not None and \
            not utils.has_expired(account.expires, utils.time_now()):
            return account.expires
        return utils.time_now() + timedelta(minutes=1)

    def _verify_cert_trustchain(self, crt: CertificateStorage) -> None:
        if not self._no_tcv:
            super()._verify_cert_trustchain(crt)
        else:
            self._log.warning("Skipping verification of certificate trustchain")

class ExamplePortServer(PortServer):
    def _init_proto(self, db: StorageAPI):
        if self._cfg.dev:
            self._proto = DevProto(db, self._cfg.challenge_ttl,
                self._cfg.dev_fc or False, self._cfg.dev_no_tcv or False)
        else:
            super()._init_proto(db)

        # install proto hooks
        if  self._proto is PortProto:
            self._proto.createNewChallenge.onCall(self.onGetChallenge)
        else:
            super(DevProto, self._proto).createNewChallenge.onCall(self.onGetChallenge)

        self._proto.register.onCall(self.onRegister)
        self._proto.register.onReturn(self.onRegisterFinish)
        self._proto.getAssertion.onReturn(self.onGetAssertionFinish)

    def onGetChallenge(self, proto, uid: UserId, seed: Optional[bytes]): # pylint: disable=unused-argument
        self._log.info("Get challenge called with uid=%s %s", uid, seed)
        if str(uid) == 'Obi Wan Kenobi':
            self._log.error("Ay caramba, Obi Wan Kenobi requested challenge!")
            raise PeUnauthorized("Obi Wan Kenobi is not allowed to call proto.get_challenge")

        # override seed value
        if seed:
            seed += bytes.fromhex("0b16b00b")
        else:
            seed = bytes.fromhex("600df00d")
        return { 'seed': seed }

    def onRegister(self, proto: PortProto, uid: UserId, sod: ef.SOD, dg15: ef.DG15, cid: CID, csigs: List[bytes], dg14: ef.DG14 = None, allowSodOverride: bool = False): # pylint: disable=unused-argument
        self._log.info("Register called with uid=%s %s %s %s %s", uid, sod, dg15, dg14 or '', cid)
        if str(uid) == 'crt.vavros':
            self._log.error("ccc, someone tries to fake ID of Crt Vavros!")
            raise PeUnauthorized("crt.vavros is not allowed to register")

    def onRegisterFinish(self, return_val: dict, proto: PortProto, uid: UserId, sod: ef.SOD, dg15: ef.DG15, cid: CID, csigs: List[bytes], dg14: ef.DG14 = None, allowSodOverride: bool = False): # pylint: disable=unused-argument
        success = {
            "uid": uid.toBase64(),
            "result" : "registered"
         }
        self._log.info("Register returned val=%s, changing to %s", return_val, success)
        return success

    def onGetAssertionFinish(self, *args, **kwargs): # pylint: disable=unused-argument
        from base64 import b64encode # pylint: disable=import-outside-toplevel
        success = {
            "uid": args[2].toBase64(),
            "cookie" : b64encode(os.urandom(32))
         }
        self._log.info("Register returned val=%s, changing to %s", args[0], success)
        return success

def init_log(logLevel: Union[str, int]):
    """
    Initializes global logging system for server.
    Functions installs `coloredlogs` and adds `FileHandler("server.log")`
    to the log.
    :param `logLevel`: Int or string log level.
    :raises `ValueError`: If `logLevel` is invalid value.
    """
    if isinstance(logLevel, str):
        logLevel = LogLevelValidator()(logLevel)
    _log = log.getLogger()
    coloredlogs.install(
        level  = log.getLevelName(logLevel),
        logger = _log,
        fmt    = '[%(asctime)s] %(levelname)-8s %(thread)-8d %(name)s %(message)s',
        field_styles = {
            'asctime': {'color': 'white'},
            'levelname': {'color': 'white', 'bold': True}
        },
        level_styles = {
            'verbose': {'color': 'black', 'bright': True},
            'debug': {},
            'info': {'color': 'cyan', 'bright': True},
            'warning': {'color': 'yellow'},
            'error': {'color': 'red', 'bright': True},
            'critical': {'color': 'red', 'bright': True},
            'notice': {'color': 'magenta'},
            'spam': {'color': 'green', 'faint': True},
            'success': {'color': 'green', 'bright': True, 'bold': True},
        }
    )

    # Log file handler as local static var 'fh'.
    # Initialized only once, but level can be changed
    # with every call to init_log.
    if not hasattr(init_log, 'fh'):
        init_log.fh = log.FileHandler("server.log")
        formatter = log.Formatter(
            '[%(asctime)s] %(levelname)-8s %(thread)-8d %(name)s %(message)s'
        )
        init_log.fh.setFormatter(formatter)
        _log.addHandler(init_log.fh)
    init_log.fh.setLevel(logLevel)

@dataclass
class DevServerConfig(ServerConfig):
    dev: Optional[bool]       = None # enable development mode
    dev_fc: Optional[bool]    = None # fixed proto challenge when dev is enabled
    dev_no_tcv:Optional[bool] = None # no trustchain validation when dev is enabled

    @staticmethod
    def argumentParser(parser: argparse.ArgumentParser, dbDialectRequired=True) -> argparse.ArgumentParser:
        parser = ServerConfig.argumentParser(parser, dbDialectRequired)
        group = parser.add_argument_group('Development', 'development options')
        group.add_argument('--dev', default=defaultArg(False), action='store_true',
            help='Start development version of server')

        group.add_argument('--dev-fc', default=None, action='store_true',
            help='Dev option: use pre-set fixed challenge instead of random generated')

        group.add_argument('--dev-no-tcv', default=None, action='store_true',
            help='Dev option: do not verify eMRTD PKI trust-chain.')
        return parser

def main():
    _log = log.getLogger('port.server')
    try:
        init_log(log.WARNING)

        # Get config from file
        parser = argparse.ArgumentParser(add_help = False)
        parser.add_argument('--config', type=Path, default='config.yaml', help='Config file.')
        args, leftovers = parser.parse_known_args()
        cfg: DevServerConfig = None
        if args.config.exists():
            with open(args.config, mode='r') as cf:
                try:
                    jcfg = yaml.safe_load(cf)
                    cfg = DevServerConfig.fromJson(jcfg)
                except Exception as e:
                    _log.exception(e)
                    return 1

        # Parse cmd arguments and merge with existing config
        parser = argparse.ArgumentParser(
            parents=[parser],
            prog  = Path(sys.argv[0]).stem,
            usage = '%(prog)s [options]',
            formatter_class = ArgumentHelpFormatter,
            description = 'Example Port server.',
        )
        dbDialectRequired = cfg is None
        DevServerConfig.argumentParser(parser, dbDialectRequired=dbDialectRequired)
        args = parser.parse_args(leftovers)
        delattr(args, 'config')
        if cfg is None:
            cfg = DevServerConfig.fromArgs(args)
        else:
            cfg.update(args) # override

        # Re-init log with provided level
        init_log(cfg.log_level)
        srv = ExamplePortServer(cfg)
        ret = srv.run()
        return ret

    except Exception as e:
        _log.exception(e)
        return 1

if __name__ == "__main__":
    sys.exit(main())
