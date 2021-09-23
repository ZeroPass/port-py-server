# API service
Port API service serves endpoint on JSON-RPC protocol.
Server has 6 API methods defined.
All API methods are defined in [api.py](https://github.com/ZeroPass/port-py-server/blob/18e134e9316bf3888ae5e51ce4cf46468e832f44/src/APIservice/api.py#L56-L172) and their logic is defined in class [PortProto](https://github.com/ZeroPass/port-py-server/blob/66b2ea724ec9a515d07298eed828c6849ec1cbbc/src/APIservice/proto/proto.py#L65-L438).
 To demonstrate the eMRTD PoC, API methods `port.register` and `port.get_assertion` should be called respectively.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Usage](#usage)
  + [Server Parameters](#server-parameters)
- [Public API Methods](#public-api-methods)
- [Private API Methods](#private-api-methods)
- [API Errors](#api-errors)
- [Testing](#testing)

## Prerequisites
* Python 3.9 or higher,
* Installed dependencies by running:
  ```
  python -m pip install -r requirements-dev.txt
  
  ```
  *This will install all dependencies.*

* Configure SQL database:
  * For PostgreSQL database see [here](../../../../../port-py-server#configure-postgresql-database).

## Usage
To see available commands execute `apiserver.py` with `--help` switch.
You can also use `yaml` file to config the server. See [config.yaml](config.yaml)

Example in foreground run:
```
 python apiserver.py --dbi-dialect=<dialect> --db-user <USER> --db-pwd <PWD> --db-name <NAME> --api-host 127.0.0.1
```

Example in background run:
```
example:
sudo nohup python apiserver.py --dbi-dialect=<dialect> --db-user <USER> --db-pwd <PWD> --db-name <NAME> --api-host 127.0.0.1 &
```
*Note: Listening to port 443 requires commands to be run as `sudo`.*

Local run using in memory SQLite:
*Note: Use python tool [pkdext](https://github.com/ZeroPass/PassID-documntation-and-tools/tree/master/tools/pkdext) to extract CSCA and DSC certificates from master list in LDAP (\*.ldif) files*
```
python apiserver.py --db-dialect=sqlite --mrtd-pkd=<path_to_pkd_root>
```

Local run using [MemoryDB](https://github.com/ZeroPass/port-py-server/blob/a6c67e787da400dd5c74218bfdf11302a8f71200/src/port/database/database.py#L1267-L1882) [DEPRECATED]:  
*Note: Use python tool [pkdext](https://github.com/ZeroPass/PassID-documntation-and-tools/tree/master/tools/pkdext) to extract CSCA and DSC certificates from master list in LDAP (\*.ldif) files*
```
python apiserver.py --db-dialect=mdb --mrtd-pkd=<path_to_pkd_root>
```

*Note: Consider running the server with python `-O` or `-OO` option in production, to optimize execution of script (i.e. remove assert statements, doc strings and some debugging context checks)*

### Server Parameters

* --api-host : Public API server bind URL address
```
default: 127.0.0.1
type: str
options:
        -localhost (127.0.0.1)
        -*         (0.0.0.0)
        -<IP>      (<IP>)
```

* --api-port : Public API server bind port
```
default: 8080
type: int
options:
        -<PORT>      (<PORT>)
```

* --api-log-level : Public API server log level
```
default: None - same as --log-level
type: str
options: [verbose, debug, info, warning, error]
```

* --api-tls-cert : Public API server TLS certificate
```
default: None
type: path
```

* --api-tls-key : Public API server TLS key
```
default: None
type: path
```

* --papi-host : Private API server bind URL address  
  **WARNING*: Never expose private API to the internet!
```
default: 127.0.0.1
type: str
options:
        -localhost (127.0.0.1)
        -*         (0.0.0.0)
        -<IP>      (<IP>)
```

* --papi-port : Private API server bind port
```
default: 8080
type: int
options:
        -<PORT>      (<PORT>)
```

* --papi-log-level : Private API server log level
```
default: None - same as --log-level
type: str
options: [verbose, debug, info, warning, error]
```

* --papi-tls-cert : Private API server TLS certificate
```
default: None
type: path
```

* --papi-tls-key : Private API server TLS key
```
default: None
type: path
```

* --db-dialect: Database dialect e.g.: mysql, sqlite, mdb etc..  
  For available dialects see [SQLAlchemy](https://docs.sqlalchemy.org/en/14/dialects/)

* --db-user : database username
```
default: empty string
type: str
```

* --db-pwd : database password
```
default: empty string
type: str
```

* --db-name : database name
```
default: empty string
type: str
```

* --challenge-ttl : number of seconds before requested challenge expires
```
default: 300
type: int
```

* --dev : developer mode. When this flag is set all newly registered accounts will expired after 1 minute.
See also other *--dev-** flags.
```
default: false
type: bool
```

* --dev-fc : use fixed constant challenge with value of [this bytes](https://github.com/ZeroPass/port-py-server/blob/master/examples/apiserver/apiserver.py#L26) instead of random challenge
*To be used for testing server with [test client](https://github.com/ZeroPass/port-py-server/blob/master/examples/apiserver/unittest/test_client.py)*
```
default: false
type: bool
```

* --dev-no-tcv : skip verification of eMRTD trustchain (CSCA=>DSC=>SOD)
```
default: false
type: bool
```

* --log-level : set server logging level.
```
default: verbose
type: str
options: [verbose, debug, info, warn, error]
```

* --job-interval : server job execution interval.
```
default: 3600 (1 hr)
type: int
```

* --mrtd-pkd : path to the root folder of trustchain CSCA/DSC certificates and CRLs to be loaded into database when server starts.
```
default: None
type: str
```

## Public API Methods
* **port.ping**
  Used for testing connection with server.
  **params:** `int32` [*ping*] number
  **return:** `int32` random [*pong*] number

* **port.get_challenge**
  Returns new random 32 bytes challenge to be used for `register` or `get_assertion` APIs.
  **params:**
    * `base64` encoded upt to 20-byte [*uid*] [user id](https://github.com/ZeroPass/port-py-server/blob/a6c67e787da400dd5c74218bfdf11302a8f71200/src/port/proto/types.py#L155-L189)

  **return:** 32-byte [*challenge*] and `int32` [*expires*] - challenge expiration timestamp

* **port.cancel_challenge**
  Cancel requested challenge.
  **params:** `base64` encoded 32-byte [*challenge*]
  **return:** none

* **port.register**
  Register new user using eMRTD credentials. Account will be valid for 10 minutes (1 minute if `--dev` flag was used) after which it will expire and user will have to register again.
  By default EF.SOD is always validated into eMRTD trustchain unless `--dev-no-tcv` flag was used.
  **params:**
    * `base64` encoded up to  20-byte [*uid*] [user id](https://github.com/ZeroPass/port-py-server/blob/a6c67e787da400dd5c74218bfdf11302a8f71200/src/port/proto/types.py#L155-L189)
    * `base64` encoded [[*dg15*]](https://github.com/ZeroPass/port-py-server/blob/a87cb5cc55c160a9ca80583ecb6099d7a6e57660/src/pymrtd/ef/dg.py#L189-L203) file (eMRTD AA Public Key)
    * `base64` encoded [[*SOD*]](https://github.com/ZeroPass/port-py-server/blob/a87cb5cc55c160a9ca80583ecb6099d7a6e57660/src/pymrtd/ef/sod.py#L135-L195) file (eMRTD Data Security Object)
    * `hex` encoded 4-byte [[*cid*]](https://github.com/ZeroPass/port-py-server/blob/master/src/port/proto/challenge.py#L12-L37) (challenge id)
    * ordered list [*csigs*] of 4 `base64` encoded eMRTD signatures (AA) made over 8-byte long challenge chunks ([see verification process](https://github.com/ZeroPass/port-py-server/blob/5800f368b03de6bf8d2ee9d26ba974ff3284b215/src/APIservice/proto/proto.py#L244-L249))
    * (Optional)`base64` encoded [[*dg14*]](https://github.com/ZeroPass/port-py-server/blob/a87cb5cc55c160a9ca80583ecb6099d7a6e57660/src/pymrtd/ef/dg.py#L161-L185) file.
    File is required if elliptic curve cryptography was used to produce signatures. (EF.DG14 contains info about ECC signature algorithm)

  **return:** Implementation specific JSON dictionary

 * **port.get_assertion**
  Get active authentication assertion for existing user using eMRTD AA signature.  
  **params:**
    * `base64` encoded up to 20-byte [*uid*] [user id](https://github.com/ZeroPass/port-py-server/blob/a6c67e787da400dd5c74218bfdf11302a8f71200/src/port/proto/types.py#L155-L189)
    * `hex` encoded 4-byte [[*cid*]](https://github.com/ZeroPass/port-py-server/blob/master/src/port/proto/challenge.py#L12-L37) (challenge id)
    * ordered list [*csigs*] of 4 `base64` encoded eMRTD signatures (AA) made over 8-byte long challenge chunks ([see verification process](https://github.com/ZeroPass/port-py-server/blob/5800f368b03de6bf8d2ee9d26ba974ff3284b215/src/APIservice/proto/proto.py#L244-L249))

   **return:** Implementation specific JSON dictionary

## Private API Methods
 * **port.get_account**
  Get registered account info. See [papi.get_account](https://github.com/ZeroPass/port-py-server/blob/a6c67e787da400dd5c74218bfdf11302a8f71200/src/port/api/papi.py#L26-L93)
  **params:**
    * `base64` encoded up to 20-byte [*uid*] [user id](https://github.com/ZeroPass/port-py-server/blob/a6c67e787da400dd5c74218bfdf11302a8f71200/src/port/proto/types.py#L155-L189)

   **return:** Account info or error if account doesn't exists.

* **port.upload_certificate**
  Upload new CSCA/DSC certificate to server. See [papi.upload_certificate](https://github.com/ZeroPass/port-py-server/blob/a6c67e787da400dd5c74218bfdf11302a8f71200/src/port/api/papi.py#L97-L1143)
  **params:**
    * `base64` encoded up certificate

## API Errors
Server can return these Port errors defined [here](https://github.com/ZeroPass/port-py-server/blob/a6c67e787da400dd5c74218bfdf11302a8f71200/src/port/proto/error.py).

## Testing
See [test client](unittest) in unittest folder.
