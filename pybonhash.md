```python
import string, sys, hashlib, binascii
from Crypto.Cipher import AES
from flag import key
if not len(key) == 42:
    raise AssertionError
else:
    data = open(sys.argv[1], 'rb').read()
    assert len(data) >= 191
FIBOFFSET = 4919
MAXFIBSIZE = len(key) + len(data) + FIBOFFSET

def fibseq(n):
    out = [
     0, 1]
    for i in range(2, n):
        out += [out[(i - 1)] + out[(i - 2)]]

    return out


FIB = fibseq(MAXFIBSIZE)
i = 0
output = ''
while i < len(data):
    data1 = data[(FIB[i] % len(data))]
    key1 = key[((i + FIB[(FIBOFFSET + i)]) % len(key))]
    i += 1
    data2 = data[(FIB[i] % len(data))]
    key2 = key[((i + FIB[(FIBOFFSET + i)]) % len(key))]
    i += 1
    tohash = bytes([data1, data2])
    toencrypt = hashlib.md5(tohash).hexdigest()
    thiskey = bytes([key1, key2]) * 16
    cipher = AES.new(thiskey, AES.MODE_ECB)
    enc = cipher.encrypt(toencrypt)
    output += binascii.hexlify(enc).decode('ascii')

print(output)
```

flag is the key, and is used at encryption.

flag is 42bytes long, and only 2 bytes are used to generating key for encrypting one block

encrypting process is simple. it hashes two bytes of plaintext, and AES encrypts the hash by 32 bytes long key(made by key1, key2)

brute-forcing 2 bytes of plaintext and 2 bytes of key, then we can verify if the key is right

for all hashes and all keys, comparing its output to given text file's block is enough to verify the keys

for optimization, using pre-calculated hash table is more efficient to brute force.

finally, there is key permutation using ((i + FIB[(FIBOFFSET + i)]) % len(key)), so indexing blocks which use n-th index key is important.

solver is below.

```python
import string, sys, hashlib, binascii
from Crypto.Cipher import AES

key = [0 for _ in range(42)] # flag!

printable = [ord(i) for i in string.printable] # for optimization

FIBOFFSET = 4919 # data from problem sourcecode

l_data = 0
hash_txt = ""

with open("hash.txt","r") as f: # get problem's output
	hash_txt = f.read()
	l_data = len(hash_txt) // 32

print(l_data)

data = "x" * l_data

MAXFIBSIZE = len(key) + len(data) + FIBOFFSET

def fibseq(n):
    out = [
     0, 1]
    for i in range(2, n):
        out += [out[(i - 1)] + out[(i - 2)]]

    return out

FIB = fibseq(MAXFIBSIZE) # get FIB
i = 0

hashtable = [] # hashtable for optimization

def gethash(): # generate hashes for all 2 byte sized input
	hashtbl = []
	for i in printable:
		for j in printable:
			tmp = bytes([i, j])
			hashtbl.append(hashlib.md5(tmp).hexdigest().encode())
	return hashtbl

def checkhash(hsh): # verify hash is correct or not
	global hashtable
	for i in hashtable:
		assert type(hsh) == type(i) and len(hsh) == len(i)
		if hsh == i:
			return True
	return False

def checkblock(block): # find right key for the block
	print(block)
	block = bytes.fromhex(block)
	for i in printable:
		print("CHK : " + str(i))
		for j in printable:
			thiskey = bytes([i, j]) * 16
			cipher = AES.new(thiskey, AES.MODE_ECB)
			dec = cipher.decrypt(block)
			if checkhash(dec):
				return i, j
	assert 1 != 1

hashtable = gethash() # make hashtable

table = [] # index table, table[n] : n-th key is used when i == table[n] in problem sourcecode

for i in range(len(key)): # get table
	j = 0
	while True:
		if i == ((j + FIB[(FIBOFFSET + j)]) % len(key)):
			break
		j += 1
	table.append(j)

print(table)

for i in range(len(table)):
	j = (table[i] // 2) * 64 # 2 keys are used in one block, so [table[n] over 2]-th block is right block
    
	k1, k2 = checkblock(hash_txt[j:j+64]) # get keys used in that block
    
	key[i] = k1 if table[i] % 2 == 0 else k2 # check first key or second key is used
    
	print([chr(i) for i in key]) # print progress

print("".join([chr(i) for i in key])) # print flag

```
