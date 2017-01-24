import threading
import socket
import struct
import time
import random
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP as OAEP
from utils import split_utf8

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