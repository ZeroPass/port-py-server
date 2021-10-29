#!/bin/bash

docker stop $(docker ps | grep docker_port_py_server | awk '{print $1}')