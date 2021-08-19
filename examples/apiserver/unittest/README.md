This is small test client script which calls Port APIs: `port.register`, `port.get_assertion`
on to server with valid passport data (EF.SOD, EF.DG15 and passport signatures).

### Usage
Server should be configured and ran with params `--dev` and `--dev-fc` with no tls `--no-tls` on port 80.
```
python apiserver.py --dev --dev-fc --no-tls -p 80 --mdb --mdb-pkd=<path_to_csca_dsc_folder>
```
