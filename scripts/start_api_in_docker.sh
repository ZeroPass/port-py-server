#!/bin/bash
sh ./stop_api.sh
docker exec -it $(docker ps | grep docker_port_py_server | awk '{print $1}') nohup python3.9 ../examples/apiserver/apiserver.py &

