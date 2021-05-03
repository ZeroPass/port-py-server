#!/bin/bash
openssl req -new -x509 -nodes -days 356 -sha384 -subj "/O=ZeroPass Port/OU=Port Server/CN=Port Server" -key server_key.pem -out "port_server_new.cer"

# der encoding
openssl x509 -outform der -in "port_server_new.cer" -out "port_server_new.der"
