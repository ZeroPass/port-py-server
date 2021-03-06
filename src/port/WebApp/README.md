# WebApp data
Web portal where anyone can upload LDAP (`*.ldif`) files from [ICAO PKD](https://download.pkd.icao.int/) (Master list, DSC & CRL) to server. The uploaded certificates are then used by [API service](https://github.com/ZeroPass/port-py-server/tree/master/src/APIservice).


### Prerequisites
* Python 3.7 or higher,
* Installed requirements from [here](../../../../../port-py-server#prerequisites),
* Configured PostgreSQL user and database (see [here](../../../../../port-py-server#configure-postgresql-database)).

### Parameters

* --url: server URL address
```
default: 127.0.0.1
type: str
options:
        -localhost (127.0.0.1)
        -*         (0.0.0.0)
        -<IP>      (<IP>)
```

* --port : server port number
```
default: 8000
type: int
options:
        -<PORT>      (<PORT>)
```

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

Run in the foreground (in 'src/WebApp'):
```
 python3 server.py --db-user <USER> --db-pwd <PWD> --db-name <NAME> --url localhost
```

Run in the background (in 'src/WebApp'):
```
nohup python3 server.py --db-user <USER> --db-pwd <PWD> --db-name <NAME> --url localhost &
```

### Other documentation
* [ICAO 9303 LDAP-LDIF structure specification](https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf)

