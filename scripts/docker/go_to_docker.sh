#!/bin/bash

docker exec -it $(docker ps | grep docker_port_py_server | awk '{print $1}') sh