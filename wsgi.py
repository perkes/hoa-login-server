from app_ import process_message
from threading import Thread
import json
import zmq
import app_

config = json.load(open('./config.json', 'r'))
ZMQ_PORT = config["zmq_port"]

class Worker(Thread):
    def __init__(self, process_message):
        Thread.__init__(self)
        self._context = zmq.Context()
        self._socket = self._context.socket(zmq.REP)
        self._process_message = process_message
        self.active = True

    def run(self):
        self._socket.bind('tcp://*:' + str(ZMQ_PORT))
        while self.active:
            message = json.loads(self._socket.recv())
            self._socket.send(self._process_message(message))


worker = Worker(process_message)
worker.start()
app = app_.app