from Crypto.PublicKey import RSA
from Crypto import Random
import random
import os

os.system('rm private_keys/* && rm public_keys/*')
os.system('rm server_public_key.pem && rm server_private_key.pem')
keys = []
for i in range(20):
  random_generator = Random.new().read
  key = RSA.generate(2048, random_generator)
  keys.append(key)

server_key = RSA.generate(4096, Random.new().read)

for index, key in enumerate(keys):
  with open('public_keys/{}.pem'.format(index), 'w') as f:
    public_key = key.publickey()
    f.write(public_key.exportKey())
    f.close()
  with open('private_keys/{}.pem'.format(index), 'w') as f:
    private_key = key.exportKey()
    f.write(private_key)
    f.close()

with open('server_public_key.pem', 'w') as f:
  f.write(server_key.publickey().exportKey('PEM'))
  f.close()
with open('server_private_key.pem', 'w') as f:
  f.write(server_key.exportKey('PEM'))
  f.close()


