from theblockchainapi import TheBlockchainAPIResource, SolanaNetwork
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
KEY_ID = config["key_id"]
SECRET_KEY= config["secret_key"]
UPDATE_AUTHORITY = config["update_authority"]
RPC_URL = config["rpc_url"]
ATTRIB = config["attrib"]

BLOCKCHAIN_API_RESOURCE = TheBlockchainAPIResource(
    api_key_id=KEY_ID,
    api_secret_key=SECRET_KEY
)

def hash_token_name(text:str):
  hash=0
  for ch in text:
    hash = ( hash*281  ^ ord(ch)*997) & 0xFFFFFFFF
  return hash

def get_nft_metadata(nft_address):
    try:
        nft_metadata = BLOCKCHAIN_API_RESOURCE.get_nft_metadata(
            mint_address=nft_address,
            network=SolanaNetwork.MAINNET_BETA
        )

        token_name = nft_metadata['data']['name']
        req = requests.get(url = nft_metadata['data']['uri'])
        req = req.json()
        resp = {}

        resp['is_hoa'] = False
        if nft_metadata['update_authority'] == UPDATE_AUTHORITY:
            resp['is_hoa'] = True

        sex, race = None, None
        for attribute in req['attributes']:
            if attribute['trait_type'] in ('Race', 'Sex', 'Class', 'Level', 'Head'):
                if attribute['trait_type'] == 'Level':
                    resp['Level'] = attribute['value']
                else:
                    if attribute['trait_type'] == 'Sex':
                        sex = attribute['value'].lower()
                    if attribute['trait_type'] == 'Race':
                        race = attribute['value'].lower()
                    resp[attribute['trait_type'].lower()] = ATTRIB[attribute['trait_type']][attribute['value']]
        name_list = config['names'][race][sex]
        resp['name'] = name_list[abs(hash_token_name(token_name))%len(name_list)]
        return resp
    except:
        return None

def is_token_active(token, nft_address):
    try:
        is_active = tokens[token]['active']
    except:
        is_active=False
    try:
        nft_matches = (nft_address == tokens[token]['nft_address'])
    except:
        nft_matches=False
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
            return bytes(str({"status": "OK", "ret": metadata}), encoding='utf8')
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
        return Response(json.dumps({"status": "error: NFT not owned by the provided wallet."}), status=418, mimetype='application/json')
    
    tokens[token] = {
        'wallet_address': wallet_address,
        'nft_address': nft_address,
        'token': token,
        'active': False
    }

    return Response(str(tokens[token]), status=200, mimetype='application/json')

@app.route('/activate_token')
def activate_token():
    token = request.args.get('token', type=str)
    signature = request.args.get('signature', type=str)

    try:
        pubkey = PublicKey(tokens[token]['wallet_address'])
    except:
        return Response(json.dumps({"status": "error: attempted to activate unregistered token."}), status=419, mimetype='application/json')

    verify_key = VerifyKey(bytes(pubkey))
    decoded_signature = base58.b58decode(signature)

    try:
        verify_key.verify(
            bytes(token, "utf8"),
            decoded_signature
        )
        tokens[token]['active'] = True
        return Response(json.dumps({"status": "OK"}), status=200, mimetype='application/json')
    except:
        return Response(json.dumps({"status": "error: invalid signature"}), status=421, mimetype='application/json')

def run_server():
    socketio = SocketIO(app)
    socketio.run(app, port=5000)

if __name__ == '__main__':
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.bind("tcp://*:" + str(ZMQ_PORT))
    
    socketio = SocketIO(app)
    socketio.start_background_task(target=run_server)

    while True:
        message = json.loads(socket.recv())
        socket.send(process_message(message))
