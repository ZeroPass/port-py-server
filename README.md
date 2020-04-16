# PassID Server - PoC
This repository contains server source code for PassID PoC. The server consists of two services: 
* [API service](https://github.com/ZeroPass/PassID-Server/tree/master/src/APIservice) which serves JSON-RPC PassID API endpoint
* [web app](https://github.com/ZeroPass/PassID-Server/tree/master/src/WebApp) platform for users to upload eMRTD trustchain certificates (CSCA/DSC) and revocation list (CRL) to server

Part of source code is also [pymrtd](https://github.com/ZeroPass/PassID-Server/tree/master/src/pymrtd) library which is used to parse eMRTD file structure, verify integrity of eMRTD files and validate trustchain.

## Table of Contents  
- [Dependencies](#dependencies)
- [Configure PostgreSQL database](#configure-postgresql-database)
- [Usage](#usage)
  + [Instructions for running server services](#instructions-for-running-server-services)
- [Server module structure](#server-module-structure)
- [PassID client repositories](#passid-client-repositories)
- [License](#license)

## Dependencies
* [Python 3.7 or higher](https://www.python.org/downloads/).<br>
  Check this [website](https://wiki.python.org/moin/BeginnersGuide/Download) for installation guidelines.
* PIP3 (sudo apt-get install python3-pip)

* [asn1crypto](https://github.com/wbond/asn1crypto)
```
 pip3 install asn1crypto
```

* [cryptography](https://github.com/pyca/cryptography)     (*Note: Library has to be patched see [README](https://github.com/ZeroPass/PassID-Server/blob/master/src/pymrtd/pki/README.md) of pki module*)
```
  pip3 install cryptography
```

* [Python LDIF parser](https://ldif3.readthedocs.io/en/latest/)
```
  pip3 install ldif3
```

* [Paramiko](https://pypi.org/project/paramiko/)
```
  pip3 install paramiko
```

* [SQLAlchemy](https://www.sqlalchemy.org/)
```
  pip3 install sqlalchemy
```

* [JSON-RPC](https://github.com/pavlov99/json-rpc)
```
  pip3 install json-rpc
```

* [werkzeug](https://palletsprojects.com/p/werkzeug/)
```
  pip3 install werkzeug
```

* [ColoredLogs](https://coloredlogs.readthedocs.io/en/latest/)
```
  pip3 install coloredlogs
```

* [pycountry](https://github.com/flyingcircusio/pycountry)
```
  pip3 install pycountry
```

* [PostgreSQL adapter - psycopg2](http://initd.org/psycopg/)
```
  pip3 install psycopg2
```

### Configure PostgreSQL database

* Install PostgreSQL

    ```sudo apt update```
    
    ```sudo apt install postgresql postgresql-contrib```

* Login to PostgreSQL

```sudo -i -u postgres```

* Create user

  ```createuser <username>```

* Create database

  ```createdb <dbname>```

* Set user password

  ```psql```

  ```psql=# alter user <username> with encrypted password '<password>';```

* Set user privileges

  ```psql=# grant all privileges on database <dbname> to <username> ;```

## Usage
To extract eMRTD trustchain certificates (CSCA/DSC) from master list files (`*.ml`) and PKD LADAP files (`*.ldif`) use python tool [pkdext](https://github.com/ZeroPass/PassID-documntation-and-tools/tree/master/tools/pkdext).
(Optional) If using SQL database you can use class [Builder](https://github.com/ZeroPass/PassID-Server/blob/a87cb5cc55c160a9ca80583ecb6099d7a6e57660/src/management/builder.py#L54) to load trustchain certificates into database via custom script.

#### Instructions for running server services:
* API service [README](src/APIservice#api-service)
* Web app [README](src/WebApp#webapp-data)

## Server module structure
* [APIService](https://github.com/ZeroPass/PassID-Server/tree/master/src/APIservice)
* [pymrtd](src/pymrtd)
* [WebApp](https://github.com/ZeroPass/PassID-Server/tree/master/src/WebApp)

## PassID client repositories:
* [EOSIO PassID mobile app](https://github.com/ZeroPass/eosio-passid-mobile-app)
* [Android PassID PoC](https://github.com/ZeroPass/PassID-Android-App)
* [iOS PassID PoC](https://github.com/ZeroPass/PassID-iOS-App)

## License
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
