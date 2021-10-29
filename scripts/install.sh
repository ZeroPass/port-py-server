#!/bin/bash

DEVELOPMENT="false"

CONTAINER_NAME="docker_port_py_server"

echo $PWD

for i in "$@"; do
  case $i in
    -d=*|--database=*)
      DATABASE="${i#*=}"
      shift # past argument=value
      ;;
    -d*|--development*)
      DEVELOPMENT="true"
      shift # past argument=value
      ;;
    *)
      # unknown option
      ;;
  esac
done

echo "---------------------------------"
echo "* Instaling server port libraries"
echo "---------------------------------"
echo "* DATABASE    = ${DATABASE}"
echo "* DEVELOPMENT = ${DEVELOPMENT}"
echo "---------------------------------"

echo "Go to correct default position "
cd /app


#install development libraries
if [ "$DEVELOPMENT" = "true" ]
then
    echo "Installing developement dependecies."
    apt-get install libpq-dev -y
    apt-get install python3.9-dev default-libmysqlclient-dev build-essential -y

    python3.9 -m pip install --upgrade setuptools
    python3.9 -m pip install --upgrade pip
    python3.9 -m pip install --upgrade distlib

    python3.9 -m pip install mysqlclient

    python3.9 -m pip install -r requirements-dev.txt
    echo "End of installing developement dependecies."
fi

#install libraries
case "${DATABASE^^}" in
"MYSQL")
    echo "Installing basic library dependencies + MySQL dependencies."
    apt-get install python3.9-dev default-libmysqlclient-dev build-essential -y

    python3.9 -m pip install --upgrade setuptools
    python3.9 -m pip install --upgrade pip
    python3.9 -m pip install --upgrade distlib

    python3.9 -m pip install mysqlclient

    python3.9 -m pip install -r requirements-mysql.txt
    ;;
"POSTGRESQL")
    echo "Installing basic library dependencies + PostgreSQL dependencies."
    apt-get install libpq-dev -y
    python3.9 -m pip install -r requirements-postgresql.txt
    ;;
"SQLITE")
    echo "Installing basic library dependencies + SQLite dependencies."
    python3.9 -m pip install sqlcipher3-binary -y
    python3.9 -m pip install -r requirements-sqlite.txt
    ;;
*)
    echo "Not valid database name. OPTIONS: [mysql, postgresql, sqlite]"
    ;;
esac


#echo "Number files in SEARCH PATH with EXTENSION:" $(ls -1 "${SEARCHPATH}"/*."${EXTENSION}" | wc -l)
#if [[ -n $1 ]]; then
#    echo "Last line of file specified as non-opt/last argument:"
#    tail -1 $1
#fi



#if (( $# == 0 )); then
#    echo "No parameter provided. You need to provide database name [MYSQL, POSTGRESQL, SQLITE]. "
#    exit 1
#else
#    echo "Number of parameters is $#"
#fi