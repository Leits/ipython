from DiffieHellman import DiffieHellman
from binascii import hexlify
from Crypto.Cipher import AES
from Crypto import Random
from json import dumps, loads
from uuid import uuid4, UUID
from itertools import combinations
from operator import xor

n = 3
m = 2
bid = {"data": "Secret bid"}
bid_key = DiffieHellman()
key = uuid4()

bid_data = dumps(bid)
bid_data = bid_data + (AES.block_size - len(bid_data) % AES.block_size) * " "

cipher = AES.new(key.hex, AES.MODE_ECB)
ctext = cipher.encrypt(bid_data)

print 'key:', key.hex
print 'encrypted bid:', hexlify(ctext)

oo = [DiffieHellman() for i in range(n)]
oo_pub_keys = [oo[i].publicKey for i in range(n)]

bid_sh_keys = [bid_key.genSecret(bid_key.privateKey, oo_pub_keys[i]) for i in range(n)]

#print bid_sh_keys

blocks = []
for i in combinations(bid_sh_keys, m):
    blocks.append(reduce(xor, i, key.int))

# post to bid
# 1 - ctext
# 2 - blocks
# 3 - bid_key.publicKey

bid_sh_keys2 = [bid_key.genSecret(oo[i].privateKey, bid_key.publicKey) for i in range(n)]

#print bid_sh_keys2

blocks2 = []
for k, i in zip(blocks, combinations(bid_sh_keys2, m)):
    blocks2.append(reduce(xor, i, k))

key2 = UUID(int=blocks2[0])
print 'key2:', key2.hex
cipher2 = AES.new(key2.hex, AES.MODE_ECB)
bid_data2 = cipher2.decrypt(ctext)

print 'bid:', loads(bid_data2.strip())
