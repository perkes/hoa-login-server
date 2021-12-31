
# Heroes of Argentum - Login Server

This server can communicate with the game server using zero-config sockets (zmq) and with the game client, through HTTP. 

### Prerequisites

- pip
- virtualenv


To get **virutalenv**: 
```
pip install virtualenv
``` 

### Installing

Create a new virtual environment:
```
virtualenv -p python3 venv
```    

Start the virtual environment:
```
source venv/bin/activate
```    
Install requirements with pip:
```
pip install -r requirements.txt
```

### Running

Once the installation phase is complete, you can run the (development) server:
```
python server.py
```

You can try the two socket messages supported by the login server with dummy_client.py. You can try the HTTP messages using any web browser.

The supported HTTP messages are:

Request token returns a token that is associated to the given nft and wallet addresses. It's not active, active token must be called before the token can be used.
* request_token
    * wallet_address
    * nft_address
    * @returns: token

Activate token checks the signature (the wallet address passed to request token must sign the provided token) against the token, if the signature is verified, the token is activated and a status OK message is returned.
* activate_token
    * token
    * signature
    * @returns: activation status

## Built With

* [Flask](https://flask.palletsprojects.com/en/2.0.x/) - Web server.
* [Solana-PY](https://michaelhly.github.io/solana-py/) - Interacting with the Solana blockchain, signature verification.
* [TheBlockchainAPI](https://docs.theblockchainapi.com/) - Interacting with the Solana blockchain.
* [ZeroMQ](https://zeromq.org/) - Zero config sockets.

## Authors

* **Jonathan Perkes** - jonathanperkes@gmail.com
