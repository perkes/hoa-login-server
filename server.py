from solana.publickey import PublicKey
from flask_socketio import SocketIO
from nacl.signing import VerifyKey
from flask import Response
from flask import request
from flask import Flask

import requests
import random
import string
import base58
import nacl
import json
import time
import zmq

tokens = {}
app = Flask(__name__)
config = json.load(open('./config.json', 'r'))

TOKEN_LENGTH = config["token_length"]
ZMQ_PORT = config["zmq_port"]
UPDATE_AUTHORITY = config["update_authority"]
RPC_URL = config["rpc_url"]
ATTRIB = config["attrib"]

def hash_token_name(text):
  hash=0
  for ch in text:
    hash = ( hash*281  ^ ord(ch)*997) & 0xFFFFFFFF
  return hash

def get_nft_metadata(nft_address):
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
    req = requests.get(url='https://api.solscan.io/account?address='+nft_address, headers=headers)
    req = json.loads(req.text)
    resp = {}

    resp['is_hoa'] = False
    if req['data']['metadata']['updateAuthority'] == UPDATE_AUTHORITY:
        resp['is_hoa'] = True

    token_name = req['data']['tokenInfo']['name']
    nft_number = token_name.split('#')[1]

    req = json.load(open('./metadata/' + str(nft_number) + '.json', 'r'))

    sex, race = None, None
    for attribute in req['attributes']:
        if attribute['trait_type'] in ('Race', 'Sex', 'Class', 'Level', 'Head', 'Body', 'Weapon', 'Helmet', 'Shield'):
            if attribute['trait_type'] == 'Level':
                resp['Level'] = attribute['value']
            else:
                if attribute['trait_type'] == 'Sex':
                    sex = attribute['value'].lower()
                if attribute['trait_type'] == 'Race':
                    race = attribute['value'].lower()
                value = ATTRIB[attribute['trait_type']][attribute['value']]
                resp[attribute['trait_type'].lower()] = value
    # Assigning the PC a name from the name list. The same NFT will always be assigned the same name.
    name_list = config['names'][race][sex]
    resp['name'] = name_list[abs(hash_token_name(token_name))%len(name_list)]
    return resp

def is_token_active(token, nft_address):
    try:
        is_active = tokens[token]['active']
    except:
        is_active=False
    try:
        nft_matches = (nft_address == tokens[token]['nft_address'])
    except:
        nft_matches=False
    # Tokens may only be used once.
    del tokens[token]
    return True if (is_active and nft_matches) else False

def process_message(message):
    try:
        nft_address = message['nft_address']
    except:
        return bytes('{"status": "error: all messages must include the nft_address parameter."}', encoding='utf8')

    if message['id'] == 'is_token_active':
        if is_token_active(message['token'], nft_address):
            return bytes('{"status": "OK"}', encoding='utf8')
        return bytes('{"status": "error: token inactive or nft does not match."}', encoding='utf8')
    elif message['id'] == 'get_nft_metadata':
        metadata = get_nft_metadata(nft_address)
        if metadata:
            resp = {}
            resp['status'] = 'OK'
            resp['ret'] = metadata
            return bytes(json.dumps(resp), encoding='utf8')
        return bytes('{"status": "error: invalid NFT address."}', encoding='utf8')
    else:
        return bytes('{"status": "error: message id not supported."}', encoding='utf8')

def generate_token():
    return ''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.digits, k=TOKEN_LENGTH))

@app.route('/request_token')
def request_token():
    wallet_address = request.args.get('wallet_address', type=str)
    nft_address = request.args.get('nft_address', type=str)
    token = generate_token()

    data = {
      "jsonrpc": "2.0",
      "id": 1,
      "method": "getProgramAccounts",
      "params": [
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        {
          "encoding": "jsonParsed",
          "filters": [
            {
              "dataSize": 165
            },
            {
              "memcmp": {
                "offset": 32,
                "bytes": wallet_address
              }
            }
          ]
        }
      ]
    }

    req = requests.post(url = RPC_URL, json = data)
    resp = json.loads(req.text)

    nfts = [t['account']['data']['parsed']['info']['mint'] for t in resp['result'] if t['account']['data']['parsed']['info']['tokenAmount']['amount'] == '1']

    if nft_address not in nfts:
        response = Response(response=json.dumps({"status": "error: NFT not owned by the provided wallet."}), status=418, mimetype='application/json')
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    
    tokens[token] = {
        'wallet_address': wallet_address,
        'nft_address': nft_address,
        'token': token,
        'active': False
    }
    
    response = Response(response=json.dumps(tokens[token]), status=200, mimetype='application/json')
    response.headers.add('Access-Control-Allow-Origin', '*')

    return response

@app.route('/activate_token')
def activate_token():
    token = request.args.get('token', type=str)
    signature = request.args.get('signature', type=str)

    try:
        pubkey = PublicKey(tokens[token]['wallet_address'])
    except:
        response = Response(response=json.dumps({"status": "error: attempted to activate unregistered token."}), status=419, mimetype='application/json')
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

    verify_key = VerifyKey(bytes(pubkey))
    decoded_signature = base58.b58decode(signature)

    try:
        verify_key.verify(
            bytes(token, "utf8"),
            decoded_signature
        )
        tokens[token]['active'] = True
        response = Response(response=json.dumps({"status": "OK"}), status=200, mimetype='application/json') 
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except:
        response = Response(response=json.dumps({"status": "error: invalid signature"}), status=421, mimetype='application/json')
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

def run_server():
    socketio = SocketIO(app)
    socketio.run(app, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.bind("tcp://*:" + str(ZMQ_PORT))
    
    socketio = SocketIO(app)
    socketio.start_background_task(target=run_server)

    while True:
        message = json.loads(socket.recv())
        socket.send(process_message(message))