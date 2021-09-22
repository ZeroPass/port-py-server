import signal
import sys

from collections import defaultdict
from datetime import timedelta
from pathlib import Path

from port import config, log
from port.api import PortApi, PortPrivateApi
from port.database import (
    CertificateStorage,
    DatabaseAPI,
    MemoryDB,
    SeEntryAlreadyExists,
    StorageAPI
)
from port.httpserver import HttpServer
from port.proto import (
    CountryCode,
    PortProto,
    ProtoError,
    utils
)

from pymrtd.pki import x509
from pymrtd.pki.crl import CertificateRevocationList

from threading import Event
from typing import Callable

class PortServer:
    apiStopWait: float  = 30 # 30 sec
    papiStopWait: float = 30 # 30 sec
    _cfg: config.ServerConfig
    _proto: PortProto
    _apisrv: HttpServer  = None
    _papisrv: HttpServer = None
    _log: log.logging.Logger
    _name = 'port.server'
    _ev_stop: Event
    _ev_finished: Event
    _exit_code = 0

    def __init__(self, cfg: config.ServerConfig):
        self._cfg         = cfg
        self._log         = log.getLogger(self._name, cfg.log_level)
        self._ev_stop     = Event()
        self._ev_finished = Event()

    def run(self) -> int: # returns exit code
        self._log.info("Starting new server session ...")
        self._log.debug("  with config: %s", self._cfg)
        self._exit_code = 0
        self._ev_stop.clear()
        self._ev_finished.clear()
        self._install_signal_handlers()

        # init DB and proto
        dbcfg = self._cfg.database
        if dbcfg.dialect == 'mdb':
            db  = MemoryDB()
        else:
            db = DatabaseAPI(dbcfg.dialect, dbcfg.url, dbcfg.name, dbcfg.user, dbcfg.password)
        self._init_proto(db)

        if self._cfg.mrtd_pkd is not None:
            self._load_pkd_to_db(self._cfg.mrtd_pkd.path, self._cfg.mrtd_pkd.allow_self_issued_csca)

        # Init API server
        if self._cfg.api:
            apill = self._cfg.api.log_level or self._cfg.log_level
            api = PortApi(self._proto, logLevel=apill, debug=False)
            self._apisrv = HttpServer(
                api,
                host=self._cfg.api.host,
                port=self._cfg.api.port,
                timeout_keep_alive=self._cfg.api.timeout_keep_alive,
                ssl_ciphers='TLSv1.2',
                ssl_keyfile=self._cfg.api.tls_key,
                ssl_certfile=self._cfg.api.tls_cert,
                log_level=apill,
                http='httptools'
            )

        # Init PAPI server
        if self._cfg.papi:
            papill = self._cfg.papi.log_level or self._cfg.log_level
            papi = PortPrivateApi(self._proto, logLevel=papill, debug=False)
            self._papisrv = HttpServer(
                papi,
                host=self._cfg.papi.host,
                port=self._cfg.papi.port,
                timeout_keep_alive=self._cfg.papi.timeout_keep_alive,
                ssl_ciphers='TLSv1.2',
                ssl_keyfile=self._cfg.papi.tls_key,
                ssl_certfile=self._cfg.papi.tls_cert ,
                log_level=papill,
                http='httptools'
            )

        if self._cfg.api is None and self._cfg.papi is None:
            self._log.warning("Configured not to serve any API!")

        # run the server
        return self._start()

    def _start(self) -> int: # returns exit code
        # pylint: disable=multiple-statements
        try:
            if self._apisrv: self._apisrv.start()
            if self._papisrv: self._papisrv.start()
            while not self._ev_stop.is_set():
                self._run_tasks()
                try:
                    self._ev_stop.wait(self._cfg.job_interval)
                except KeyboardInterrupt: pass # pylint: disable=multiple-statements
        except KeyboardInterrupt: pass # pylint: disable=multiple-statements
        except SystemExit as e:
            self._log.debug("Caught SystemExit, setting exit code to: %s", e.code or 1)
            self._exit_code = e.code or 1
        except Exception as e:
            self._log.critical("Unhandled exception was encountered:")
            self._log.exception(e)
            self._exit_code = 1
        finally:
            if self._papisrv: self._papisrv.stop(self.papiStopWait)
            if self._apisrv: self._apisrv.stop(self.apiStopWait)
            self._log.info("Server has stopped!")
            self._ev_finished.set()
            return self._exit_code # pylint: disable=lost-exception

    def _stop(self):
        self._log.info("Stopping server...")
        try:
            self._ev_stop.set()
            if not self._ev_finished.wait(30):
                self._log.error("Server failed to stop in time!")
        except Exception as e:
            self._log.warning("Stopping server...FAILED")
            self._log.error(e)

    def _run_tasks(self):
        self._log.debug('Start maintenance job')
        try:
            self._proto.purgeExpiredChallenges()
        except Exception as e:
            self._log.error("An exception was encountered while doing maintenance job")
            self._log.exception(e)
        self._log.debug('Finished maintenance job, next schedule at: %s',
            utils.time_now() + timedelta(seconds=self._cfg.job_interval))

    def _init_proto(self, db: StorageAPI):
        self._proto = PortProto(db, self._cfg.challenge_ttl)

    def _load_pkd_to_db(self, pkdPath: Path, allowSelfIssuedCSCA: bool):
        # pylint: disable=too-many-locals
        self._log.info("Loading PKI certificates and CRLs into DB, allowSelfIssuedCSCA=%s ...", allowSelfIssuedCSCA)
        def keyid2str(cert):
            return cert.subjectKey.hex() if cert.subjectKey is not None else None

        timeNow = utils.time_now()
        cscas:  dict[str, dict[str, x509.CscaCertificate]] = defaultdict(dict)
        lcscas: dict[str, dict[str, x509.CscaCertificate]] = defaultdict(dict)
        dscs:   dict[str, dict[str, x509.DocumentSignerCertificate]] = defaultdict(dict)
        crls:   dict[str, CertificateRevocationList] = defaultdict()
        for cert in pkdPath.rglob('*.cer'):
            try:
                self._log.verbose("Loading certificate: %s", cert)
                cfd = cert.open('rb')
                cert = x509.Certificate.load(cfd.read())
                if not cert.isValidOn(timeNow):
                    self._log.debug("Skipping expired certificate. C=%s serial=%s key_id=%s",
                        CountryCode(cert.issuerCountry), CertificateStorage.makeSerial(cert.serial_number).hex(), keyid2str(cert))
                    continue

                ku = cert.key_usage_value.native
                if cert.ca:
                    if 'key_cert_sign' not in ku:
                        self._log.warning("CSCA doesn't have key_cert_sign constrain. C=%s serial=%s key_id=%s",
                            CountryCode(cert.issuerCountry), CertificateStorage.makeSerial(cert.serial_number).hex(), keyid2str(cert))
                    cert.__class__ = x509.CscaCertificate
                    if cert.self_signed == 'maybe':
                        cscas[cert.issuerCountry][cert.serial_number] = cert
                    else:
                        lcscas[cert.issuerCountry][cert.serial_number] = cert
                elif 'digital_signature' in ku and 'key_cert_sign' not in ku:
                    cert.__class__ = x509.DocumentSignerCertificate
                    dscs[cert.issuerCountry][cert.serial_number] = cert

                else:
                    self._log.warning("Skipping certificate because it is not CA but has key_cert_sign constrain. C=%s serial=%s key_id=%s",
                        CountryCode(cert.issuerCountry), CertificateStorage.makeSerial(cert.serial_number).hex(), keyid2str(cert))
            except Exception as e:
                self._log.warning("Could not load certificate: %s", cert)
                self._log.exception(e)

        for crl in pkdPath.rglob('*.crl'):
            try:
                self._log.verbose("Loading crl: %s", crl)
                cfd = crl.open('rb')
                crl = CertificateRevocationList.load(cfd.read())
                crls[crl.issuer.human_friendly] = crl
            except Exception as e:
                self._log.warning("Could not load CRL: %s", crl)
                self._log.exception(e)

        def insert_certs(certs, certType: str, insertIntoDB: Callable[[x509.Certificate], None]) -> int:
            assert callable(insertIntoDB)
            cert_count = 0
            for _, cd in certs.items():
                for _, cert in cd.items():
                    try:
                        insertIntoDB(cert)
                        cert_count += 1
                    except SeEntryAlreadyExists:
                        self._log.info("Skipping %s certificate because it already exists. C=%s serial=%s key_id=%s",
                            certType, CountryCode(cert.issuerCountry), CertificateStorage.makeSerial(cert.serial_number).hex(), keyid2str(cert))
                    except Exception as e:
                        self._log.warning("Could not add %s certificate into DB. C=%s serial=%s key_id=%s",
                            certType, CountryCode(cert.issuerCountry), CertificateStorage.makeSerial(cert.serial_number).hex(), keyid2str(cert))
                        if isinstance(e, ProtoError):
                            self._log.warning(" e=%s", e)
            return cert_count

        def insert_crls(crls: dict[str, CertificateRevocationList]) -> int:
            crl_count = 0
            for issuer, crl in crls.items():
                try:
                    self._proto.updateCRL(crl)
                    crl_count += 1
                except SeEntryAlreadyExists:
                    self._log.info("Skipping CRL because it already exists. issuer='%s' crlNumber=%s", issuer, crl.crlNumber)
                except Exception as e:
                    self._log.warning("Could not add CRL into DB. issuer='%s' crlNumber=%s", issuer, crl.crlNumber)
                    if isinstance(e, ProtoError):
                        self._log.warning(" e=%s", e)
            return crl_count

        cert_count  = insert_certs(cscas, 'CSCA', lambda csca: self._proto.addCscaCertificate(csca, allowSelfIssued=allowSelfIssuedCSCA))
        cert_count += insert_certs(lcscas, 'LCSCA', lambda lcsca: self._proto.addCscaCertificate(lcsca, allowSelfIssued=False))
        cert_count += insert_certs(dscs, 'DSC', self._proto.addDscCertificate)
        crl_count   = insert_crls(crls)
        self._log.info("%s certificates loaded into DB.", cert_count)
        self._log.info("%s CRLs loaded into DB.", crl_count)

    def _install_signal_handlers(self):
        """
        Installs program terminate handlers to properly stop the server.
        On unix system the function hooks on signals: SIGHUP, SIGINT, SIGTERM.
        On windows the CTRL+C signals are caught.
        """
        def stop_server(*args): #pylint: disable=unused-argument
            try:
                self._stop()
            except BaseException as e: #pylint: disable=broad-except
                self._log.critical('An exception was encountered while stopping server!')
                self._log.exception(e)

        if sys.platform == "win32":
            import win32api # pylint: disable=import-outside-toplevel
            win32api.SetConsoleCtrlHandler(stop_server, True) # pylint: disable=c-extension-no-member
        else:
            signal.signal(signal.SIGHUP, stop_server) #pylint: disable=no-member
            signal.signal(signal.SIGINT, stop_server)
            signal.signal(signal.SIGTERM, stop_server)
