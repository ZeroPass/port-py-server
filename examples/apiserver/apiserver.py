#!/usr/bin/python
import argparse, coloredlogs, os, signal, sys, ssl

from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

_script_path = Path(os.path.dirname(sys.argv[0]))
#sys.path.append(str(_script_path / Path("../../")))

from port import log
from port.api import PortApiServer
from port.database.storage.x509Storage import CertificateStorage
from port.proto import (
    Challenge,
    CountryCode,
    DatabaseAPI,
    MemoryDB,
    PortProto,
    ProtoError,
    SeEntryAlreadyExists,
    StorageAPI,
    UserId,
    utils
)
from port.settings import Config, DbConfig, ServerConfig

from pymrtd import ef
from pymrtd.pki import x509

from typing import Callable, Tuple


class DevProto(PortProto):
    def __init__(self, storage: StorageAPI, cttl: int, fc: bool, no_tcv: bool):
        super().__init__(storage, cttl)
        self._fc = fc
        self._no_tcv = no_tcv

    def createNewChallenge(self, uid: UserId) -> Tuple[Challenge, datetime]:
        if self._fc:
            fc = Challenge.fromhex("47E4EE7F211F73265DD17658F6E21C1318BD6C81F37598E20A2756299542EFCF")
            c, cct = super().createNewChallenge(uid)
            if c == fc:
                return (c,cct)
            self._db.deleteChallenge(c.id)
            cet = self._get_challenge_expiration(datetime.utcnow())
            self._db.addChallenge(uid, fc, cet)
            return (fc, cet)
        return super().createNewChallenge(uid)

    def _get_default_account_expiration(self):
        return utils.time_now() + timedelta(minutes=1)

    def __validate_certificate_path(self, sod: ef.SOD): #pylint: disable=unused-private-member
        if not self._no_tcv:
            super().__validate_certificate_path(sod)
        else:
            self._log.warning("Skipping verification of eMRTD certificate trustchain")

class DevApiServer(PortApiServer):
    def __init__(self, db: StorageAPI, config: Config, fc=False, no_tcv=False):
        super().__init__(db, config)
        self._proto = DevProto(db, config.challenge_ttl, fc, no_tcv)


def parse_args():
    # Set-up cmd parameters
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge-ttl", default=300,
        type=int, help="number of seconds before requested challenge expires")

    ap.add_argument("-c", "--cert", default=str(_script_path / "tls/port_server.cer"),
        type=str, help="server TLS certificate")

    ap.add_argument("--db-dialect",
        type=str, help="database dialect e.g.: postgresql, mysql etc...\nOverrides --mdb")

    ap.add_argument("--db-url", default="localhost:5432",
        type=str, help="database URL")

    ap.add_argument("--db-user",
        type=str, help="database user name")

    ap.add_argument("--db-pwd", default="",
        type=str, help="database password")

    ap.add_argument("--db-name",
        type=str, help="database name")

    ap.add_argument("--mdb", default=False,
        action='store_true', help="use MemoryDB for database. --db-* args will be ignored")

    ap.add_argument("--mrtd-pkd", default=None,
        type=Path, help="path to eMRTD PKD root folder to load PKI certificates into DB, i.e.: CSCA, DSC, CRLs...")

    ap.add_argument("--mrtd-pkd-allow-self-issued-csca", default=True, action=argparse.BooleanOptionalAction,
        type=bool, help="allow self-issued CSCA to be loaded into DB")

    ap.add_argument("--dev", default=False,
        action='store_true', help="start development version of server")

    ap.add_argument("--dev-fc", default=False,
        action='store_true', help="dev option: use pre-set fixed challenge instead of random generated")

    ap.add_argument("--dev-no-tcv", default=False,
        action='store_true', help="dev option: do not verify eMRTD PKI trust-chain.\nOverrides --mrtd-pkd")

    ap.add_argument("-k", "--key", default=str(_script_path / "tls/server_key.pem"),
        type=str, help="server TLS private key")

    ap.add_argument("--log-level", default=0,
        type=int, help="logging level, [0=verbose, 1=debug, 2=info, 3=warn, 4=error]")


    ap.add_argument("--no-tls", default=False,
        action='store_true', help="do not use secure TLS connection")

    ap.add_argument("-p", "--port",
        type=int, help="server listening port")

    ap.add_argument("-u", "--url", default='0.0.0.0',
        type=str, help="server http address")

    args = vars(ap.parse_args())

    if args["log_level"] <= 0:
        args["log_level"] = log.VERBOSE
    elif args["log_level"] == 1:
        args["log_level"] = log.DEBUG
    elif args["log_level"] == 2:
        args["log_level"] = log.INFO
    elif args["log_level"] == 3:
        args["log_level"] = log.WARN
    elif args["log_level"] >= 4:
        args["log_level"] = log.ERROR

    if args['port'] is None:
        args['port'] = 80 if args['no_tls'] else 443

    return args

def init_log(logLevel):
    l = log.getLogger()
    coloredlogs.install(
        level  = log.getLevelName(logLevel),
        logger = l,
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

    log.getLogger('requests').setLevel(log.WARN)
    log.getLogger('urllib3').setLevel(log.WARN)

    fh = log.FileHandler("server.log")
    fh.setLevel(logLevel)
    formatter = log.Formatter(
        '[%(asctime)s] %(levelname)-8s %(thread)-8d %(name)s %(message)s'
    )
    fh.setFormatter(formatter)
    l.addHandler(fh)

def load_pkd_to_db(proto: PortProto, pkdPath: Path, allowSelfIssuedCSCA: bool):
    l = log.getLogger('port.api.server')
    l.info("Loading PKI certificates into DB, allowSelfIssuedCSCA=%s ...", allowSelfIssuedCSCA)
    def keyid2str(cert):
        return cert.subjectKey.hex() if cert.subjectKey is not None else None

    timeNow = utils.time_now()
    cert_count = 0
    cscas:dict[str, dict[str, x509.CscaCertificate]] = defaultdict(dict)
    lcscas:dict[str, dict[str, x509.CscaCertificate]] = defaultdict(dict)
    dscs:dict[str, dict[str, x509.DocumentSignerCertificate]] = defaultdict(dict)
    for cert in pkdPath.rglob('*.cer'):
        try:
            l.verbose("Loading certificate: {}".format(cert))
            cfd = cert.open('rb')
            cert = x509.Certificate.load(cfd.read())
            if not cert.isValidOn(timeNow):
                l.debug("Skipping expired certificate. C=%s serial=%s key_id=%s",
                    CountryCode(cert.issuerCountry), CertificateStorage.makeSerial(cert.serial_number).hex(), keyid2str(cert))
                continue

            ku = cert.key_usage_value.native
            if cert.ca:
                if 'key_cert_sign' not in ku:
                    l.warning("CSCA doesn't have key_cert_sign constrain. C=%s serial=%s key_id=%s",
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
                l.warning("Skipping certificate because it is not CA but has key_cert_sign constrain. C=%s serial=%s key_id=%s",
                    CountryCode(cert.issuerCountry), CertificateStorage.makeSerial(cert.serial_number).hex(), keyid2str(cert))
        except Exception as e:
            l.warning("Could not load certificate: %s", cert)
            l.exception(e)

    def insertCerts(certs, certType: str, insertIntoDB: Callable[[x509.Certificate], None] ):
        assert callable(insertIntoDB)
        nonlocal cert_count
        for _, cd in certs.items():
            for _, cert in cd.items():
                try:
                    insertIntoDB(cert)
                    cert_count += 1
                    l.info("%s certificate was added into DB. C=%s serial=%s key_id=%s",
                        certType, CountryCode(cert.issuerCountry), CertificateStorage.makeSerial(cert.serial_number).hex(), keyid2str(cert))
                except SeEntryAlreadyExists:
                    l.info("Skipping %s certificate because it already exists. C=%s serial=%s key_id=%s",
                        certType, CountryCode(cert.issuerCountry), CertificateStorage.makeSerial(cert.serial_number).hex(), keyid2str(cert))
                except Exception as e:
                    l.warning("Could not add %s certificate into DB. C=%s serial=%s key_id=%s",
                        certType, CountryCode(cert.issuerCountry), CertificateStorage.makeSerial(cert.serial_number).hex(), keyid2str(cert))
                    if isinstance(e, ProtoError):
                        l.warning(" e=%s", e)

    insertCerts(cscas, 'CSCA', lambda csca: proto.addCscaCertificate(csca, allowSelfIssued=allowSelfIssuedCSCA))
    insertCerts(lcscas, 'LCSCA', lambda lcsca: proto.addCscaCertificate(lcsca, allowSelfIssued=False))
    insertCerts(dscs, 'DSC', proto.addDscCertificate)
    l.info("%s certificates loaded into DB.", cert_count)

def main():
    args = parse_args()

    init_log(args['log_level'])
    l = log.getLogger('port.api.server')
    l.info("Starting new server session ...")
    l.debug("run parameters: {}".format(sys.argv[1:]))

    ctx = None
    if not args['no_tls']:
        ctx = ssl.SSLContext( ssl.PROTOCOL_TLS_SERVER)
        ctx.options |= ssl.OP_SINGLE_ECDH_USE | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2
        ctx.load_cert_chain(args['cert'], args['key'])

    config = Config(
        database = DbConfig(
            dialect = args['db_dialect'],
            url     = args['db_url'],
            user    = args['db_user'],
            pwd     = args['db_pwd'],
            db      = args['db_name']
        ),
        api_server = ServerConfig(
            host = args['url'],
            port = args['port'],
            ssl_ctx = ctx
        ),
        web_app=None,
        challenge_ttl = args['challenge_ttl']
    )

    if args['mdb'] and not args['db_dialect']:
        db  = MemoryDB()
    else:
        db = DatabaseAPI(config.database.dialect, config.database.url, config.database.db, config.database.user, config.database.pwd)

    # Setup and run server
    if args["dev"]:
        sapi = DevApiServer(db, config, args['dev_fc'], args['dev_no_tcv'])
    else:
        sapi = PortApiServer(db, config)

    if args['mrtd_pkd'] and not args['dev_no_tcv']:
        allowSelfIssuedCSCA = args['mrtd_pkd_allow_self_issued_csca']
        load_pkd_to_db(sapi._proto, args['mrtd_pkd'], allowSelfIssuedCSCA)

    def signal_handler(sig, frame): #pylint: disable=unused-argument
        print('Stopping server...')
        sapi.stop()
        print('Stopping server... SUCCESS')
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    sapi.start()

if __name__ == "__main__":
    main()
