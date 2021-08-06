#!/usr/bin/python
import base64, json, os, requests
from pymrtd.ef.dg import DataGroupNumber

from datetime import datetime
from port.proto import CID, Challenge, UserId, Session, SessionKey
from pymrtd import ef
from typing import List

headers = {'content-type': 'application/json'}

def b64encode(data: bytes):
    return str(base64.b64encode(data), 'ascii')

def bsigs_to_b64sigs(bsigs):
    ssigs = []
    for bsig in bsigs:
        ssigs.append(b64encode(bsig))
    return ssigs

def pingServer(url: str) -> Challenge:
    payload = {
        "method": "port.ping",
        "params": {
            "ping" : int.from_bytes(os.urandom(4), 'big')
        },
        "jsonrpc": "2.0",
        "id": 0,
    }

    response = requests.post(
        url, data=json.dumps(payload), headers=headers).json()
    if "error" in response:
        raise Exception(response['error'])
    return response['result']['pong']

def requestChallenge(url: str, uid: UserId) -> Challenge:
    payload = {
        "method": "port.getChallenge",
        "params": {
            "uid"   : uid.toBase64(),
        },
        "jsonrpc": "2.0",
        "id": 8,
    }

    response = requests.post(
        url, data=json.dumps(payload), headers=headers).json()
    if "error" in response:
        raise Exception(response['error'])
    c   = Challenge.fromBase64(response['result']['challenge'])
    cet = datetime.utcfromtimestamp(response['result']['expires'])
    return (c, cet)

def requestRegister(url: str, uid: UserId, sod: ef.SOD, dg15: ef.DG15, cid: CID, csigs: List[bytes]):
    payload = {
        "method": "port.register",
        "params": {
            "uid"   : uid.toBase64(),
            "sod"   : b64encode(sod.dump()),
            "dg15"  : b64encode(dg15.dump()),
            "cid"   : cid.hex(),
            "csigs" : bsigs_to_b64sigs(csigs),
         },
        "jsonrpc": "2.0",
        "id": 1,
    }

    response = requests.post(
        url, data=json.dumps(payload), headers=headers).json()
    if "error" in response:
        raise Exception(response['error'])

    result = response['result']
    uid = UserId.fromBase64(result['uid'])
    sk  = SessionKey.fromBase64(result['session_key'])
    et  = datetime.utcfromtimestamp(result['expires'])
    return (uid, Session(sk), et)

def requestLogin(url: str, uid: UserId, cid: CID, csigs: List[bytes], dg1 = None):
    payload = {
        "method": "port.login",
        "params": {
            "uid"  : uid.toBase64(),
            "cid"   : cid.hex(),
            "csigs" : bsigs_to_b64sigs(csigs),
            "dg1": b64encode(dg1) if dg1 is not None else None
         },
        "jsonrpc": "2.0",
        "id": 2,
    }

    response = requests.post(
        url, data=json.dumps(payload), headers=headers).json()
    if "error" in response:
        raise Exception(response['error'])

    result = response['result']
    sk  = SessionKey.fromBase64(result['session_key'])
    et  = datetime.utcfromtimestamp(result['expires'])
    return (Session(sk), et)

def requestGreeting(url: str, uid: UserId, s: Session):
    mac = s.getMAC("sayHello".encode('ascii') + uid)
    payload = {
        "method": "port.sayHello",
        "params": {
            "uid"  : uid.toBase64(),
            "mac"  : b64encode(mac),
         },
        "jsonrpc": "2.0",
        "id": 2,
    }

    response = requests.post(
        url, data=json.dumps(payload), headers=headers).json()
    if "error" in response:
        raise Exception(response['error'])

    result = response['result']
    return result['msg']

def alter_sod(sod: ef.SOD):
     # copy doesn't work and set doesn't work so replace raw hash of DG1
    s = ef.SOD.load(sod.dump() \
        .replace(sod.ldsSecurityObject.dgHashes.find(DataGroupNumber(1)).hash,\
             bytes.fromhex('BADEF50D00000000FF6A22FFEF1567FF88079F415C66EAD250AB5F23781AC2CD')))
    assert sod.dump() != s.dump()
    return s

def alter_dg15(dg15: ef.DG15):
    # replace first 16 bytes of rsa public key
    d15 = ef.DG15.load(dg15.dump() \
        .replace(bytes.fromhex('BD8620D45693E1CD8678639F22E9553F'),\
             bytes.fromhex('BADEFD615900BC3EBADEFD615900BC3E')))
    assert dg15.dump() != d15.dump()
    return d15

def main():
    url = "http://localhost:80"

    tvUid = UserId.fromhex("dc8b9f25b383b7552bdd5f5b4945dfce46a790ee")
    raw_sod = bytes.fromhex("778207CF308207CB06092A864886F70D010702A08207BC308207B8020103310F300D060960864801650304020105003081E90606678108010101A081DE0481DB3081D8020100300D060960864801650304020105003081C3302502010104200E5DA521CC643C0269E2C71205E3FE50C43FF9E6980F5BC745898C1A0795CEC130250201020420BA477BCF824157E20B7060956BED9E8C34D9699926000C7F2019120A0F62954A3025020103042062627BD08F74B698FCB2948E27F98FC1EE04EAC21EF1187A284A4F726090BA5F302502010E042072ECEE0A12EFF3464D2A25F20808ED60C1773D45F815C5C371AFD366639BD8D7302502010F042030E44DAB9996890E32B20ED93B91A654618CA18AA330CD9828F2C1B20F2AEDC9A08204DC308204D8308202C0A0030201020204448833B8300D06092A864886F70D01010B05003057310B3009060355040613027369311B3019060355040A0C1273746174652D696E737469747574696F6E7331133011060355040B0C0A652D70617373706F72743116301406035504030C0D435343412D536C6F76656E6961301E170D3134303530383038303134315A170D3234303930353232303030305A3058310B3009060355040613027369311B3019060355040A0C1273746174652D696E737469747574696F6E7331133011060355040B0C0A652D70617373706F72743117301506035504030C0E44532D536C6F76656E69612D303130820122300D06092A864886F70D01010105000382010F003082010A0282010100C88010F9A33A388C6D006A30EBF9731E591DB18EC08D514FC57D731C862DC5F2A974B9465BA447A9F1F294B98A66E66EEBEE9509082CE9C33B05BB0A05B62FC30B0CE5AB33730F2E1B66D9612CAF8CC2231D96B9611384C2B76A53886DDA714C7701E43FE7D290C930895F698F8CC6016B08B3E21882884D18DFE7226794C0F3BF4CD6126A7775F123252427EB0437ABDF8A8D7FD767344B498A6F4FDCDB45B6FCE3355C2C186A95DF230C545B16E1FCBA69CD742CA363D5B2ABC2EF4ABC0663F7A4713ED86BFC2A30D333D12708343D3A90383D043A3E491AAA3AC1B00035FF01857991AA997A777C97FC82B4BE94116E42AD8A560881EB8E7672002FEE9EA50203010001A381AA3081A7300E0603551D0F0101FF040403020780302B0603551D1004243022800F32303134303530383038303134315A810F32303134303830353232303030305A30400603551D2004393037303506092B06810DAF5A0401013028302606082B06010505070201161A687474703A2F2F7777772E637363612D73692E676F762E73692F30130603551D23040C300A800845C02458BE10ADD330110603551D0E040A04084466E17D2DBC5A7F300D06092A864886F70D01010B0500038202010099D3DEE1A4313AC3CF78207483E496BA7AF8D3A3D9E91261615AD51546904D07C3736665B98AA9B95B5AF643CAD7708FD2A2B7649BB880075E6E1CA1ACE169BC1E802CF1998935B6351828C3BCF3BED49525A47D88EF2296551A00D6B05296E3117FD862820C3A1F69CD1CA770560F5E2C3DA51CCE6D2811BBD7B5DB4899E9C01D31150E320BAFBBB9540C473E205B753720EE28B4C866427650F0E9446E4891F196E985CF959DBFC67CE7EB6E9B7E2C5066CFFAAE6C8B137D53F0F7C3B03DEA1F8DB52E6061CBC6CEAF9C035BD88F71B3B874A40C536703C24EA82BBDD6DE155CA974381B8C6DDB8BA2DDC0F39DC17695061D2B4872007BE243DFCF6C7DB561FD2D72D1D4EB0077094DDEFCA7E24E69D3D2F8B6C9939529DC7E6CD324F633BDDE5A170F313EE38B4F42F8E01F29A155F6FDABFCAD16BD426A63E4DD754C07722A7E959D2E2B9A78665D6D6597F07E272680AE8BE02B9B89F2DE207580DE1A6CF55AE07626DA945C4022821AF9319AF96D379787EC6B9D3EAB6B374EAB8965208DC9636E3E5677717049D219DBB3B6C8126683F9D98891D4D89322755FC310A9CED99911148DA96479F853591A48F9A270FBB2A30CCF2E98647D2CED4C6B72029515524316BDBE043837C9B8739D8E219B8E0F02873D47A9226A46E668A64F8044EF15C8DE2DA6C1B0C2146395800B34BEE8E3D99ECAC901618D402054E4493C318201D4308201D0020101305F3057310B3009060355040613027369311B3019060355040A0C1273746174652D696E737469747574696F6E7331133011060355040B0C0A652D70617373706F72743116301406035504030C0D435343412D536C6F76656E69610204448833B8300D06096086480165030402010500A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420A86EFB22772EFC58E6E2F844339AA2FF84EF5A043E90F9E5BF41208E69A7DDE2300D06092A864886F70D01010B050004820100B440C1F5E835E26C24B1014EB61924713E37F7153131442625738BCD291BDF819A9E7536B4503B9C248EEE1E67EEBC3482B9792689763999846063B29C27633EB044389B50BCCF73F96C2E9085603ADF4DCDA550DF71860A6F50A3438A2B95F7B99F276844ABD0D86640F9DAA2CCFC4CAC3F35239248D71E3065E1D801139E5CE3B62F5269749EC3F456FDEEB383B12843B2527CB8948000CFE289636DE59AF56C393BFDE62F8009066F641FC017FDC6F4C209E5BDE0C3BEF90331A4E139CCD311E01DA0652CA6F9B52BD48C66EDC7B24A5DAE902B3BB055B12EFBC572B9F7B0C86F3C7CC88DF9CA372CD5AE10B43A8135FDC3A765F0C30976557D3DE1BD5D07")
    sod = ef.SOD.load(raw_sod)

    rawDg15 = bytes.fromhex("6F81A230819F300D06092A864886F70D010101050003818D0030818902818100BD8620D45693E1CD8678639F22E9553F09E3AFD87BD26000113CE2798B7A02A2E0AB6B7525D09072109D938D6708167E8FAFAF83F17BFBA36CECCE26058C7ED9AE29516755B19F78CE0E73DA02340B117B8AB2ECA007F1390E93E896016335EB5C1E330B961C03E253D17874F7ABEE8D4962C49FFE578D46954FF23B26F5E5550203010001")
    dg15 = ef.DG15.load(rawDg15)

    sigc = Challenge.fromhex("47E4EE7F211F73265DD17658F6E21C1318BD6C81F37598E20A2756299542EFCF")
    csigs = [
        bytes.fromhex("8AECE4E0AB1A6B9E06B31ACBA51AE316D0B7B48E2F5FE13E575060F6B9DC27A2F9D03DCF67A141F466EEC753879106BE0992F46F5EAAD075EB1886D2ACE90D60C2EDA69880780CE4FA36EF27AB01C47527BD23B178EC8F213307281572C219487FC11B2C3D9C144DC98D96D1A79A7478449D692D3D14E8C044F81B3ADF0047E0"),
        bytes.fromhex("97251259E9EB453A8DC2D9CD85D5A49D2E83F31D6465CB1FBD09C5E7800D4F0FB9FF7312343CD3955CA3BE6768AD7938F3D36B0C9E2205923786949B5F48FBF1C94D01B5BC9DA88C8293E118F87E14E4CC409D52AA7ED266E20248AB3C04949838540DEB24588436607EA620B4825D002C5FAB4F07B618D72C0A9EC247653FE7"),
        bytes.fromhex("12C0972DFE9E1DDB42B46130D64339E0845578D85E5F0ED7C9E12036AE0C3D417BBAAA6CA5579E782DDEADA825E432C2AE9593B8DB5806327E22B18CD0AB86353C314925A01390806A1D6E8DDE2CD0D82D9671457139241E93BC308E5573C335D14EF6182A5171A443A82A2568D6B1373A1F227377C584ABA7B1E8B1F47E393F"),
        bytes.fromhex("0854CF7B69FB54286F97FC8B396722E21156DFEEC38CF5C63035B09A59C4EA7FCA79865D5EE166548AAE5AE1F629A57459B46F5D1D1E4EFE9369C0075903D3CA282D6B2CF5843E62CE53BEA33E3D6AA7A48147CC38C9B534437FD0DCD0F0C787BE74061DFA844435253D651E7986BA47F49FA49D7041BD1FE72B5E5D09221FD1"),
    ]


    try:
        print("Pinging server ...")
        pong = pingServer(url)
        print("Pong: {}\n".format(pong))

        print("Requesting challenge from server ...")
        c, cet = requestChallenge(url, tvUid)
        print("Server returned challenge={} expires={}\n".format(c.hex(), cet))
        assert c == sigc

        try:
            print("Trying to register new user with altered EF.SOD file ...")
            uid, s, et = requestRegister(url, tvUid, alter_sod(sod), dg15, sigc.id, csigs)
            raise AssertionError("Registration with altered EF.SOD file succeeded!")
        except Exception as e:
            print("Server returned error: {}\n".format(e))
            assert str(e) == "{'code': 422, 'message': 'Invalid EF.SOD'}"

        try:
            print("Trying to register new user with altered EF.DG15 file ...")
            uid, s, et = requestRegister(url, tvUid, sod, alter_dg15(dg15), sigc.id, csigs)
            raise AssertionError("Registration with altered EF.DG15 file succeeded!")
        except Exception as e:
            print("Server returned error: {}\n".format(e))
            assert str(e) == "{'code': 422, 'message': 'Invalid EF.DG15 file'}"

        print("Registering new user ...")
        uid, s, et = requestRegister(url, tvUid, sod, dg15, sigc.id, csigs)
        assert uid == tvUid
        print("User was successfully registered!\n  uid={}\n  session_key={}\n  session_expires={}\n".format(uid.hex(), s.key.hex(), et))

        print("Requesting greeting from server ...")
        msg = requestGreeting(url, uid, s)
        print("Server says: {}\n".format(msg))


        print("Requesting new challenge from server for login ...")
        c, cet = requestChallenge(url, tvUid)
        print("Server returned challenge={} expires={}\n".format(c.hex(), cet))
        assert c == sigc

        print("Logging in ...")
        s, et = requestLogin(url, uid, c.id, csigs)
        print("Login succeed!\n  uid={}\n  session_key={}\n  session_expires={}\n".format(uid.hex(), s.key.hex(), et))

        print("Requesting greeting from server ...")
        msg = requestGreeting(url, uid, s)
        print("Server says: {}\n".format(msg))

    except AssertionError as e:
        print("Assert failed: {}".format(e))
    except Exception as e:
        print("Error: Server returned error: {}".format(str(e)))


if __name__ == "__main__":
    main()
