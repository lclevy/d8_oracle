#!/usr/bin/env python
'''
>python d8_oracle.py fir\EOSRP160.FIR

Input is update file fir\EOSRP160.FIR
  allocating 0x20c6400 bytes at 0x800000 for FIR file
Oracle is rom file eosr_110/ROM0.BIN loaded at 0xe0000000
Emulating cipher.bin at 0x200000. Code copied from 0xe0039000
  Updater decrypted ? True
  dumping verified and decrypted updater1 (0x800120-0xae5030) to file 80000433_1.6.0_updater1.bin
  found decryption function called around 0x81fef4-0x81ff00
Emulating AES decryption at 0x81fef4 within updater1
  dumping 80000433_1.6.0_firmware.bin (0xae5060-0x28c63a0)
  decryption successful ? True

'''
from unicorn import *
from unicorn.arm_const import *

from capstone import *

import sys
from binascii import unhexlify, hexlify
from hashlib import sha1, sha256
from struct import Struct
import argparse
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util import Counter 
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

import time

def malloc( size ):
  pass

def print_registers():
  regs = [ 
    ('R0', UC_ARM_REG_R0), ('R1', UC_ARM_REG_R1), ('R2', UC_ARM_REG_R2), ('R3', UC_ARM_REG_R3),  ('LR', UC_ARM_REG_LR), ('SP', UC_ARM_REG_SP), ('PC', UC_ARM_REG_PC) 
    ]

  for n, r in regs:
    print(">>> %s = 0x%x" % (n, mu.reg_read(r) ) )

'''symbols = { 0x204B58 : 'verify_signature',  0x204D74 : 'decrypt', 0x204AB4 : 'init',  0x204AD0 : 'update', 0x204AE0:'final', 0x204936 : 'sha256_final',
  0x2042DC : 'aes_key_expansion', 0x204AFC : 'secp256r1_verif', 0x200180 : 'verif' } #0x204b34 : 'malloc',

def hook_code(uc, pc, size, user_data):
  print(">>> pc = 0x%x" % (mu.reg_read(UC_ARM_REG_PC) ) )'''

new_block = []

def hook_block(uc, pc, size, user_data):
  if pc not in new_block:
    #print('pc = %x' % (pc)) 
    new_block.append( pc )

    '''if pc in symbols:
      print( '%x > ' % pc, symbols[pc] )'''

  if pc == 0x0204b34:
    r0 = int(mu.reg_read(UC_ARM_REG_R0))
    #print( 'malloc r0=%d' % r0 )
    #addr = malloc( r0 )
  elif pc == 0x0204D74:
    print('  %x: decrypt  R1=%x R2=%x R0=%x R3=%x' % (pc, int(mu.reg_read(UC_ARM_REG_R1)),  int(mu.reg_read(UC_ARM_REG_R2)), int(mu.reg_read(UC_ARM_REG_R0)),
      int(mu.reg_read(UC_ARM_REG_R3)) ) )
  elif pc == 0x0204AD0:
    print('  %x: sha256_update  R1/data=%x R2/size=%x R0/ctx=%x' % (pc, int(mu.reg_read(UC_ARM_REG_R1)),  int(mu.reg_read(UC_ARM_REG_R2)), int(mu.reg_read(UC_ARM_REG_R0))  ) )
  elif pc == 0x0204AE0: 
    r1 = int(mu.reg_read(UC_ARM_REG_R1))
    r0 = int(mu.reg_read(UC_ARM_REG_R0))
    #print('%x: sha256_final  R1=%x R2=%x R0=%x' % (pc, r1,  int(mu.reg_read(UC_ARM_REG_R2)), int(mu.reg_read(UC_ARM_REG_R0))  ) )
    #print( hexlify(mu.mem_read(r1,4)) )
  elif pc == 0x02042DC:
    r1 = int(mu.reg_read(UC_ARM_REG_R1))
    print('  %x: aes_key_expansion  R1=%x R2=%x R0=%x' % (pc, int(mu.reg_read(UC_ARM_REG_R1)),  int(mu.reg_read(UC_ARM_REG_R2)), int(mu.reg_read(UC_ARM_REG_R0))  ) )


#to disassemble around pc in case of exception
md = Cs(CS_ARCH_ARM, UC_MODE_THUMB|CS_MODE_LITTLE_ENDIAN) #CS_MODE_THUMB
md.detail = True 


STACK_ADDRESS_BASE = 0x100000
STACK_SIZE = 0x1000

EMU_START_ADDRESS = 0x0200000 
#EMU_STOP_ADRESS  = 0x02042DE #key_exp + 2
EMU_STOP_ADDRESS  = 0x020002c

FIR_ADDRESS = 0x800000
FIR_SIZE = 0x210_0000

CIPHER_ADDRESS = 0x200000
CIPHER_SIZE = 0x10000

ROM0_ADDR = 0xe000_0000
ROM0_SIZE = 0x200_0000

CIPHER_ROM_ADDR = 0xe003_9000
CIPHER_ROM_SIZE = 0xaf00

BFE00100_data = unhexlify('18F09FE518F09FE518F09FE518F09FE518F09FE518F09FE518F09FE518F09FE5000000E0040000E0080000E00C0000E0100000E0140000E0180000E01C0000E0'+'10101010101010101111111111111111121212121212121213131313131313131414141414141414151515151515151516161616161616161717171717171717'+
                     '181818181818181819191919191919191A1A1A1A1A1A1A1A1B1B1B1B1B1B1B1B1C1C1C1C1C1C1C1C1D1D1D1D1D1D1D1D1E1E1E1E1E1E1E1E1F1F1F1F1F1F1F1F'+'20202020202020202121212121212121222222222222222223232323232323232424242424242424252525252525252526262626262626262727272727272727')             
SEED1_DATA = 0xBFE00100
SEED2_RAM = 0x2057C4
SEED2_SIZE = 0x10

DEBUG = False

PAGE_SIZE = 0x400

'''EOS R 180 updater
                        s_V&D_Firmware_V5_0081fed4           XREF[1]:     FUN_0081fbfa:0081fd26(*)  
  0081fed4 56 26 44 20 46 69         ds         "V&D Firmware V5"
            72 6d 77 61 72 65 
            20 56 35 00
                        s_%d=_Third_0081fee4                 XREF[1]:     FUN_0081fbfa:0081fd46(*)  
  0081fee4 25 64 3d 5f 54 68         ds         "%d=_Third"
            69 72 64 00

                        LAB_0081fef0                         XREF[1]:     0081fd58(j)  
  0081fef0 10 20                     movs       r0,#0x10
  0081fef2 4c 4b                     ldr        r3,[PTR_DAT_00820024]                            = 00002070

  0081fef4 02 01                     lsls       r2,r0,#0x4
  0081fef6 4c 49                     ldr        r1,[PTR_DAT_00820028]                            = bfe00100
  0081fef8 00 90                     str        r0,[sp,#0x0]=>local_b0
  0081fefa 38 46                     mov        r0,r7
  0081fefc 42 f0 f3 fe               bl         decrypt                                          undefined decrypt(undefined para
'''
code_pattern = unhexlify('10204c4b02014c4900903846') #to find EMU_START_ADDRESS2 in updater

parser = argparse.ArgumentParser()
parser.add_argument("firfile", help="fir filename")
parser.add_argument("-r", "--rom", help="rom dump", action="store", default=Path('roms') / Path('eosr_110.BIN') )
parser.add_argument("-p", "--patch", help="patch 1 byte of Updater signature to break ECDSA verification", action="store_true", default=False)
parser.add_argument("-t", "--time", help="display emulations time", action="store_true", default=False)
parser.add_argument("-v", "--verbose", help="verbose", action="store_true", default=False)
parser.add_argument("-u", "--updater", help="decrypt updater only", action="store_true", default=False)
parser.add_argument("-s", "--sign", help="signature verification only", action="store_true", default=False)
parser.add_argument("-H", "--hash", help="display sha1 values", action="store_true", default=False)

args = parser.parse_args()

try:
  with open(args.rom, 'rb') as rom_file:
    rom0 = rom_file.read()
except FileNotFoundError:
  print('default ROM is missing')
  sys.exit()

base_addr = ROM0_ADDR

cipher_offset = CIPHER_ROM_ADDR - base_addr
cipher_bin = rom0[cipher_offset:cipher_offset+CIPHER_ROM_SIZE]

with open(args.firfile, 'rb') as fir_file:
  fir = fir_file.read()

try:
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    mu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
  
    print('Input is update file %s' % args.firfile)
    model, _, version = Struct('<L12s5s').unpack_from(fir, 0)
    id = '%x_%s' % (model, version.decode())

    mem_size = ((len(fir)//PAGE_SIZE)+1)*PAGE_SIZE
    print('  allocating 0x%x bytes at 0x%x for FIR file' % (mem_size, FIR_ADDRESS) )
    
    mu.mem_map(FIR_ADDRESS, mem_size) #for FIR file
    mu.mem_write(FIR_ADDRESS, fir)

    print('Oracle is rom file %s' % args.rom, 'loaded at 0x%x' % base_addr)
    if args.hash:
      print('  sha1=', sha1(rom0).hexdigest() )

    mu.mem_map(ROM0_ADDR, ROM0_SIZE) 
    mu.mem_write(base_addr, rom0)

    mu.mem_map(CIPHER_ADDRESS, CIPHER_SIZE) 
    mu.mem_write(CIPHER_ADDRESS, cipher_bin ) #copied to 0x4020_0000 by ROM code, which is a alias to 0x20_0000. Some sha256 functions are fixed as 0x20xxxx
  
    mu.mem_map(SEED1_DATA-0x100, 0x1000) 
    mu.mem_write(SEED1_DATA, BFE00100_data) #decrypt_seed1

    mu.mem_map( 0xf000000, 0x200000 ) #for malloc 

    mu.mem_map(STACK_ADDRESS_BASE, STACK_SIZE)
    mu.reg_write(UC_ARM_REG_SP, STACK_ADDRESS_BASE+STACK_SIZE-256 )

    if args.verbose:
      mu.hook_add(UC_HOOK_BLOCK, hook_block, begin=CIPHER_ADDRESS,end=CIPHER_ADDRESS+CIPHER_ROM_SIZE)

    header, offset = Struct('<LL').unpack_from(fir, 0x24)
    _len, _, iv = Struct('<LL16s').unpack_from(fir, header) 
    #ciphertext_updater = fir[offset:offset+_len] #keep ciphertext version
    updater1_address = FIR_ADDRESS+offset

    #https://neuromancer.sk/std/secg/secp256r1
    PUBKEY = 0x205784
    PARAM_N = 0x20522c
    PARAM_A = 0X2051a8
    PARAM_B = 0x2051c8
    PARAM_G = 0x2051e8

    if args.patch: #signature experiments
      #modify last byte of Updater signature
      mu.mem_write(FIR_ADDRESS+0x68+4+31, b'\x01')
 
    start_time = time.time()
    print( 'Emulating cipher.bin at 0x200000. Code copied from 0x%x' % CIPHER_ROM_ADDR )
    mu.emu_start(EMU_START_ADDRESS|1, 0x200016)
    if args.time:
      print( '  Updater decryption took: %.2fs' % (time.time() - start_time) )

    verify_result = mu.reg_read(UC_ARM_REG_R0)
    if verify_result!=0:
      print('  Updater signature is invalid, aborting')
      sys.exit()

    if args.sign:
      print('  Updater signature is valid')
      sys.exit()

    mu.emu_start(0x200016|1, EMU_STOP_ADDRESS)
    
    decrypted = mu.mem_read( updater1_address, _len )
    updater_verified = decrypted.find(b'V&D Firmware V5')>0
    print('  Updater decrypted ?', updater_verified )

    filename = '%08x_%s_updater1.bin' % ( model, version.decode() )
    if updater_verified:
      with open( filename, 'wb' ) as upd:

        print('  dumping verified and decrypted updater1 (0x%x-0x%x) to file %s' % ( updater1_address, updater1_address+_len, filename ) )

        _hash = sha1(decrypted).digest() #hash of emulated decryption
        if args.hash:
          print( '  sha1=', hexlify(_hash) ) #rp160 = 45f28541c1ad8b385a974d9ae0c718aa940697b7
        upd.write( decrypted ) 

    decrypt_offset = decrypted.find(code_pattern)
    if decrypt_offset < 0:
      print('  decryption function call not found. Exit')
      sys.exit()
      
    EMU_START_ADDRESS2 = updater1_address+decrypt_offset+4 #lsls       r2,r0,#0x4
    EMU_STOP_ADDRESS2 = updater1_address+decrypt_offset+16 #after bl         decrypt
    print('  found decryption function called around 0x%x-0x%x' % (EMU_START_ADDRESS2, EMU_STOP_ADDRESS2))

    if args.updater:
      sys.exit()

    #parses encryption header
    firmware_offset = Struct('<L').unpack_from(fir, 0x30)[0]
    header, ciphertext, header_len = Struct('<LLL').unpack_from(fir, firmware_offset)
    _len, _, iv = Struct('<LL16s').unpack_from(fir, firmware_offset+header)

    mu.reg_write(UC_ARM_REG_R0, 0x10 ) #seed2 len, first param on stack
    mu.reg_write(UC_ARM_REG_R7, FIR_ADDRESS ) #will be R0, first paramater
    mu.reg_write(UC_ARM_REG_R3, 0x2057C4 ) #decryption seed2 stored in updater context at 0x2070

    mu.mem_map( 0x7000, 0x10000 ) #for malloc at 95809c/RP160 (uses 0x897c) and 9626f8/R180 (uses 0x776c)

    ciphertext_offset = FIR_ADDRESS+firmware_offset+ciphertext
    ciphertext_firmware = fir[firmware_offset+ciphertext:firmware_offset+ciphertext+_len] #keep ciphertext version
    print('Emulating AES decryption at 0x%x within updater1' % (EMU_START_ADDRESS2) )

    start_time = time.time()
    mu.emu_start(EMU_START_ADDRESS2|1, EMU_STOP_ADDRESS2)
    if args.time:
      print( '  Firmware decryption took: %.2fs' % (time.time() - start_time) )

    filename = '%08x_%s_firmware.bin' % ( model, version.decode() )
    with open(filename, 'wb') as firm:
      print('  dumping %s (0x%x-0x%x)' % (filename, ciphertext_offset, ciphertext_offset+_len) )
      decrypted = mu.mem_read( ciphertext_offset, _len )
      print( '  decryption successful ?', decrypted.find(b'akashimorino')>=0 ) #dryshell password
      if args.hash:
        print( '  sha1=', sha1(decrypted).hexdigest() ) 
      firm.write( decrypted ) 

except UcError as e:
    print_registers()
    print("Error: ",e)
    pc = mu.reg_read(UC_ARM_REG_PC)
    dis = md.disasm(mu.mem_read(pc,4), pc, count=5)
    for i in dis:
      print(i)
