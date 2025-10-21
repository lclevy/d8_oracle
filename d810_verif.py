'''
d810_verif.py

https://github.com/lclevy

- extract signatures data from Canon FIR files
- check their validity

valid for Digic8 and Digic10 cameras except: M50, SX70, 4000D, 2000D, SX740, M6 m2, G5X m2 which use old keys from 2010.
also valid for c70, c300 m3 and c500 m2
not supported : R1 and next models

secp256r1 algorithm was identified by Ponguin from Magic Lantern forum, but never proved.

New fields for FIRv5 (2018) and FIRv6 (2020):

offset, content
...
0x44 regions count
0x48 count times (region_offset, region_size)
...
0x68 r1_length (often 0x20)
0x6c r1
0x8c s1_length 
0x90 s1
0xb0 r2_length
0xb4 r2
0xd4 s2_length
0xd8 s2
0xf8 end

(r1, s1) is the signature based on sha256 the 3 first regions (header and updaters)
(r2, s2) is the signature based on sha256 of the firmware
'''

import sys
from binascii import unhexlify

from struct import Struct
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

from json import dumps

S_SIGNATURES = Struct('<'+'L32s')
SIGNATURES_OFFSET = 0x68
def get_sign(fir):
  #s = dict()
  p = SIGNATURES_OFFSET  
  for i in range(4):
    l, v = S_SIGNATURES.unpack_from(fir, p)
    d['l%d'%(i+1)] = l
    if l<32: #for 250d update v101, which has r1 with 31 bytes only !
      fill = b'\x00'*(32-l)
      v = fill+fir[p+4:p+4+l]
    j = (i//2)+1  
    if i%2:
      prefix = 's'
    else:
      prefix = 'r'
    d[prefix+'%d'%j] = v  
    p = p + S_SIGNATURES.size  
  return d

def check_ecc( key, h, signature):
  verifier = DSS.new(key, 'fips-186-3')
  try:
      verifier.verify(h, signature)
      return True
  except ValueError:
      return False

REGIONS_TABLE=0x44
def compute_hashes(fir):
  c = Struct('<L').unpack_from(fir, REGIONS_TABLE)[0]
  h1 = SHA256.new()
  for i in range(REGIONS_TABLE+4, REGIONS_TABLE+4+(c-1)*8, 8):
    o, s = Struct('<LL').unpack_from(fir, i)
    h1.update( fir[o:o+s] )

  o, s = Struct('<LL').unpack_from(fir, REGIONS_TABLE+4+(c-1)*8)  
  h2 = SHA256.new( fir[ o:o+s ] )
    
  return h1, h2

try:
  with open(sys.argv[1], 'rb') as f:
    fir = f.read()

    d = dict()
    d['model_id'] = Struct('<L').unpack_from(fir, 0)[0]

    if d['model_id'] in [ 0x80000436, 0x80000424, 0x80000433, 0x00000808, 0x80000437, 0x80000498, 0x80000467 ]:
      pk = ECC.import_key( encoded = unhexlify(b'04'+b'DBB4D364EE83CDF72C3A595A09BE2C2D8170847D8C4F566FC7FE099D43EE71EFE548A0C26FCC8AE424B918C2E08171DC78C83920AD8697E82EC0BBF8EDAEF1CF'), curve_name = 'secp256r1' )
      d['digic'] = 8
    elif d['model_id'] in [ 0x80000421, 0x80000453, 0x80000428, 0x40000213, 0x40010206, 0x40000206, 0x80000481, 0x80000450, 0x80000480, 0x80000491, 0x40000218, 0x80000464, 0x80000487, 0x40000214, 0x80000465 ]:
      pk = ECC.import_key( encoded = unhexlify(b'04'+b'5e3b144079d39dc0ef01e72cb8d5eba8c4bec6f95b00bd0393d914f146c16330de731d6c646d5b648c1e4db8c1f36752ef41aefa71173c8deabb395a38521220'), curve_name = 'secp256r1' )
      d['digic'] = 10
    else:
      print('model not supported : 0x%x' % d['model_id'])
      sys.exit()  

    d['version'] = Struct('<5s').unpack_from(fir, 0x10)[0].decode()
    d['checksum'] = Struct('<L').unpack_from(fir, 0x20)[0]

    signatures = get_sign(fir)
    h1, h2 = compute_hashes(fir)

    v1 = check_ecc( pk, h1, signatures['r1']+signatures['s1'] )  
    v2 = check_ecc( pk, h2, signatures['r2']+signatures['s2'] )  

    d['h1'] = h1.digest().hex()
    d['h2'] = h2.digest().hex()
    d['r1'] = int.from_bytes(signatures['r1'], byteorder='big')
    d['s1'] = int.from_bytes(signatures['s1'], byteorder='big')
    d['r2'] = int.from_bytes(signatures['r2'], byteorder='big')
    d['s2'] = int.from_bytes(signatures['s2'], byteorder='big')
    d['v1'] = v1
    d['v2'] = v2
    print(dumps(d, indent=4))
except FileNotFoundError as e:
  print(e)    