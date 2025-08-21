# Port Python Server SDK
[![tests](https://github.com/ZeroPass/port-py-server/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/ZeroPass/port-py-server/actions/workflows/tests.yml)

This repository contains server source code for the Port python server.

Part of source code is also [pymrtd](https://github.com/ZeroPass/port-py-server/tree/master/src/pymrtd) library which is used to parse eMRTD file structure, verify integrity of eMRTD files.

## Prerequisites
Python >= 3.9  
PIP

**Linux**

* MySQL:
[mysqlclient](https://pypi.org/project/mysqlclient/) requires MySQL development headers and libraries.
  ```
  # Debian/Ubuntu
  apt-get install default-libmysqlclient-dev build-essential
  ```
  ```
  # Red Hat / CentOS
  yum install mysql-devel
  ```

* PostgreSQL:
[psycopg2](https://pypi.org/project/psycopg2/) requires additional tools, libraries and headers to be installed on your system.
See:
https://www.psycopg.org/docs/install.html#prerequisites

* SQLite:
if the installation of [sqlcipher3](https://pypi.org/project/sqlcipher3) fails you might try to install binary package:
  ```
  python -m pip install install sqlcipher3-binary
  ```

## Install
Following command installs `port` and `pymrtd` libraries with all required dependency.

Production with no extra database drivers
```
python -m pip install -r requirements.txt
```

Production with database driver for MySQL:
```
python -m pip install -r requirements-mysql.txt
```

Production with database driver for PostgreSQL:
```
python -m pip install -r requirements-postgresql.txt
```

Production with database driver for SQLite:
```
python -m pip install -r requirements-sqlite.txt
```

Development:
```
python -m pip install -r requirements-dev.txt
```
### Configure PostgreSQL database

* Install PostgreSQL

    ```sudo apt update```

    ```sudo apt install libpq-dev postgresql postgresql-contrib```

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
To extract eMRTD trustchain certificates (CSCA/DSC) from master list files (`*.ml`) and PKD LDAP files (`*.ldif`) use python tool [pkdext](https://github.com/ZeroPass/port-py-server/tree/master/scripts/pkdext).

In **production** python should be run in optimized mode (by passing the `-O` or `-OO` switch to the interpreter, or by setting the `PYTHONOPTIMIZE` environment variable to 1 (or higher) to eliminate any assert type checking code and speed up execution.

#### Instructions for running example server:
* Example API service [README](examples/apiserver/README.md)

## Server modules structure
* [Port](src/port)
* [pymrtd](src/pymrtd)

## License
This project is licensed under the terms of the GNU Lesser General Public License (LGPL) for open-source use and a Commercial License for proprietary use. See the [LICENSE.LGPL](/LICENSE.LGPL) and [LICENSE.COMMERCIAL](/LICENSE.COMMERCIAL) files for details.

