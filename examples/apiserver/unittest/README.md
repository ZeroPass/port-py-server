This is small test client script that calls Port APIs: `port.get_challenge`, `port.register` and `port.get_assertion`  
with valid passport data (EF.SOD, EF.DG15 and passport signatures).

### Usage
To run `test_client.py` the example server should be configured and ran with params `--dev` and `--dev-fc` with no TLS on api port 80.
```
example:
python apiserver.py --dev --dev-fc --api-port 80 --db-dialect=sqlite --mrtd-pkd=<path_to_csca_dsc_folder>
```
