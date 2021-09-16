import sys

from collections import defaultdict
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
    _cfg: config.ServerConfig
    _proto: PortProto
    _apisrv: HttpServer  = None
    _papisrv: HttpServer = None
    _log: log.logging.Logger
    _name = 'port.server'
    _ev_stop: Event

    def __init__(self, cfg: config.ServerConfig):
        self._cfg     = cfg
        self._log     = log.getLogger(self._name)
        self._ev_stop = Event()

    def run(self) -> int: # returns exit code
        self._log.info("Starting new server session ...")
        self._ev_stop.clear()
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
            api = PortApi(self._proto, debug=False)
            self._apisrv = HttpServer(
                api,
                host=self._cfg.api.host,
                port=self._cfg.api.port,
                timeout_keep_alive=self._cfg.api.timeout_keep_alive,
                ssl_ciphers='TLSv1.2',
                ssl_keyfile=self._cfg.api.tls_key,
                ssl_certfile=self._cfg.api.tls_cert ,
                log_level=self._cfg.log_level,
                http='httptools'
            )

        # Init PAPI server
        if self._cfg.papi:
            papi = PortPrivateApi(self._proto, debug=False)
            self._papisrv = HttpServer(
                papi,
                host=self._cfg.papi.host,
                port=self._cfg.papi.port,
                timeout_keep_alive=self._cfg.papi.timeout_keep_alive,
                ssl_ciphers='TLSv1.2',
                ssl_keyfile=self._cfg.papi.tls_key,
                ssl_certfile=self._cfg.papi.tls_cert ,
                log_level=self._cfg.log_level,
                http='httptools'
            )

        # run the server
        return self._start()

    def _start(self) -> int: # returns exit code
        self._proto.start()
        if self._apisrv: self._apisrv.start()
        if self._papisrv: self._papisrv.start()
        try:
            while not self._ev_stop.is_set():
                self._run_tasks()
                try:
                    self._ev_stop.wait(self._cfg.job_interval)
                except KeyboardInterrupt: pass # pylint: disable=multiple-statements
            return 0
        except Exception as e:
            self._log.error("Unhandled exception was encountered!")
            self._log.exception(e)
            return 1
        finally:
            if self._papisrv: self._papisrv.stop()
            if self._apisrv: self._apisrv.stop()
            self._proto.stop()

    def _stop(self):
        self._log.debug("_stop()")
        try:
            self._ev_stop.set()
        except Exception as e:
            self._log.error(e)

    def _run_tasks(self):
        self._log.debug('_run_tasks')

    def _init_proto(self, db: StorageAPI):
        self._proto = PortProto(db, self._cfg.challenge_ttl, maintenanceInterval=self._cfg.job_interval)

    def _load_pkd_to_db(self, pkdPath: Path, allowSelfIssuedCSCA: bool):
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
        def stop_server(sig): #pylint: disable=unused-argument
            try:
                self._stop()
            except BaseException as e: #pylint: disable=broad-except
                self._log.warning('An exception was encountered while stopping server!')
                self._log.exception(e)

        if sys.platform == "win32":
            import win32api # pylint: disable=import-outside-toplevel
            win32api.SetConsoleCtrlHandler(stop_server, True)
        else:
            import signal # pylint: disable=import-outside-toplevel
            def unix_signal_handler(sig, frame): #pylint: disable=unused-argument
                stop_server(sig)
            signal.signal(signal.SIGHUP, unix_signal_handler) #pylint: disable=no-member
            signal.signal(signal.SIGINT, unix_signal_handler)
            signal.signal(signal.SIGTERM, unix_signal_handler)
