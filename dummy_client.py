import json
import zmq

context = zmq.Context()

socket = context.socket(zmq.REQ)
socket.connect("tcp://localhost:5555")

messages = [
    {
        "id": "is_token_active",
        "token": "sNTtjPyq2IYHXl1JjVDHt4inCVZUctZzlsoFwSpT",
        "nft_address": "97rQic6p1L3CsRiboLC77R463kDm23HfSpELUdytxCRX"
    },
    {
        "id": "get_nft_metadata",
        "nft_address": "97rQic6p1L3CsRiboLC77R463kDm23HfSpELUdytxCRX"
    }
]

for message in messages:
    message_bytes = bytes(json.dumps(message), encoding='utf8')
    socket.send(message_bytes)
    reply = socket.recv()
    print(reply)
