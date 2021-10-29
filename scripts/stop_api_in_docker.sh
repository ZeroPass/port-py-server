#!/bin/bash

PID=$(ps aux | grep "python3.9 ../examples/apiserver/apiserver.py" | awk 'NR==1{ print $2 }')
docker exec -it $(docker ps | grep docker_port_py_server | awk '{print $1}') kill -9 $PID 2> /dev/null
