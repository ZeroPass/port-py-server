#!/bin/bash
# Script generates Port certificate ID from x509 certificate using OpenSSL

usage="Calculate Port certificate ID from x509 certificate

$(basename "$0") [-h] <x509_certificate.cer>

where:
    -h  show this help text"

while getopts ':h:' option; do
  case "$option" in
    h) echo "$usage"
       exit
       ;;
   \?) printf "Error: illegal option: -%s\n" "$OPTARG" >&2
       echo "$usage" >&2
       exit 1
       ;;
  esac
done
shift $((OPTIND - 1))

if [ -z "$1" ]; then
  printf "Error: missing positional argument for 'x509_certificate.cer'\n\n"
  echo "$usage" >&2
  exit 1
elif ! [ -f "$1" ]; then
  printf "Error: positional argument is not file\n\n"
  echo "$usage" >&2
  exit 1
fi

TMP_TSC_CRT='.cert.tbs.tmp'
openssl asn1parse -inform der -in "$1" -strparse 4 -noout -out $TMP_TSC_CRT
rc=$?; if [[ $rc != 0 ]]; then exit $rc; fi

RESULT=$(openssl dgst -sha512-256 $TMP_TSC_CRT | awk '{print $2}' | cut -c1-16 2>&1)
rc=$?; if [[ $rc != 0 ]]; then (1>&2 echo "$RESULT"); exit $rc; fi
rm -f $TMP_TSC_CRT
echo "hex_id: ${RESULT^^}"
echo "int_id: $((16#$RESULT))"
