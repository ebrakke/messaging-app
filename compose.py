import threading
import socket
import struct
import time
import random
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP as OAEP
from utils import split_utf8

MESSAGE = '''
The fountains mingle with the river 
   And the rivers with the ocean, 
The winds of heaven mix for ever 
   With a sweet emotion; 
Nothing in the world is single; 
   All things by a law divine 
In one spirit meet and mingle. 
   Why not I with thine? 
See the mountains kiss high heaven 
   And the waves clasp one another; 
No sister-flower would be forgiven 
   If it disdained its brother; 
And the sunlight clasps the earth 
   And the moonbeams kiss the sea: 
What is all this sweet work worth 
   If thou kiss not me? 
'''.encode('utf-8')

class MessageClient(object):
  def __init__(self, server_pk, client_sk, pks, host, port, identity):
    self.server_pk = server_pk
    self.sk = client_sk
    self.pks = pks
    self.host = host
    self.port = port
    self.id = identity
    self.decryption_cipher = OAEP.new(client_sk)
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  
  def encrypt_message(self, pk, message):
    # first encrypt with the recipients pk
    cipher_reciever = OAEP.new(pk).encrypt(message)
    # encrypt now with the servers pk
    cipher_server = OAEP.new(self.server_pk).encrypt(cipher_reciever)
    return cipher_server
  
  def decrypt_message(self, message):
    if not message:
      return
    try:
      return self.decryption_cipher.decrypt(message)
    except ValueError as e:
      pass
      # print 'Message not for you'
  
  def send_msg(self, sock, msg):
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)
  
  def recv_msg(self, sock):
    raw_msgln = self.recv_all(sock, 4)
    if not raw_msgln:
      return
    msgln = struct.unpack('>I', raw_msgln)[0]
    return self.recv_all(sock, msgln)
  
  def recv_all(self, sock, n):
    data = ''
    while len(data) < n:
      packet = sock.recv(n - len(data))
      if not packet:
        return
      data += packet
    return data
  
  def test(self):
    self.sock.connect((self.host, self.port))
    chunks = split_utf8(MESSAGE, 100)
    while True:
      time.sleep(1)
      sending_to = random.randint(0,19)
      while sending_to == self.id:
        sending_to = random.randint(0,19)
      receiver = self.pks[sending_to]  # whom to send the message to
      try:
        msg_chunk_to_send = chunks.next()
      except StopIteration:
        msg_chunk_to_send = 'END'
      msg = self.encrypt_message(receiver, msg_chunk_to_send)
      self.send_msg(self.sock, msg)
      data = self.recv_msg(self.sock)
      while data:
        message = self.decrypt_message(data)
        if message:
          print('{} recived this message: {}'.format(self.id, message))
        data = self.recv_msg(self.sock)

def generate_test_clients(n):
  clients = []
  pks = []
  server_pk = RSA.importKey(open('server_public_key.pem').read())
  # load in all private keys and public keys
  for i in range(n):
    pk = RSA.importKey(open('public_keys/{}.pem'.format(i)).read())
    pks.append(pk)
    sk = RSA.importKey(open('private_keys/{}.pem'.format(i)).read())
    client = MessageClient(server_pk, sk, pks, 'localhost', 8000, i)
    clients.append(client)
  return clients

if __name__ == '__main__':
  clients = generate_test_clients(20)
  for client in clients:
    threading.Thread(target=client.test).start()