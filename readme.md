# d8_oracle.py readme

This repository contains tools to experiment cryptography of digic8 FIR updates from Canon, using a camera dump and Unicorn emulation.

No camera dump is provided.

Digic and Canon are trademarks of Canon company.

Bonus: a tool to verify ECDSA signatures from Digic8 and Digic10 FIR files (EOS R and later, not working starting R1 model).

## Slides

- hacklu2025_slides/ directory contains presentation at Hack.lu 2025 conference (https://2025.hack.lu/)

## Python scripts

- **d8_oracle.py** the main script which does Unicorn emulation
- d810_verif.py, which verifies and extracts ECDSA signatures from FIRv5 / Digic 8 and FIRv6 / Digic 10 updates (.FIR files)
- ml_scripts/ directory contains updates of Magic Lantern legacy scripts (https://github.com/reticulatedpines/magiclantern_simplified/tree/dev/tools/indy)
  - fir_tool2.py to display structure of FIR files, from 2007 to 2023. EOS R1 and later are not supported.
  - dump_fir.py to display firmware records (output of d8_oracle.py : *_firmware.bin files)

### Setup

#### ROM dump

YOU NEED AN EOS R ou RP ROM DUMP:
- using CBasic : https://github.com/lclevy/cbasic_examples
- or ask a friend. 

*DO NOT REDISTRIBUTE ROM dumps, it contains copyrighted code from Canon !!!*

#### FIR files

- here : https://eoscard.pel.hu/
- or using these links:
  - https://gdlp01.c-wss.com/gds/8/0400006288/02/eosr-v180-win.zip
  - https://gdlp01.c-wss.com/gds/2/0400006292/01/eosrp-v160-win.zip
  - https://gdlp01.c-wss.com/gds/6/0400006776/01/v103-sl3-250d-200d2-x10-win.zip 
  - https://gdlp01.c-wss.com/gds/9/0400009889/01/eosr6-v190-win.zip 


### d8_oracle.py

This is **the main tool**, an Unicorn script which emulates:
1. digic8 camera code (cipher.bin part) to decrypt updater code inside .FIR files, for Digic8 / FIRv5 updates.
2. updater code to decrypt the main FIR payload

Does not work with old Digic8 cameras : M50, SX70, 4000D, 2000D, SX740, M6 m2, G5X m2. Older crypto is used.

#### Requirements

- Camera rom dump (EOS R, EOS RP). By default uses 'roms\eosr_110.BIN'
- Unicorn emulation engine (https://www.unicorn-engine.org/)
    - pip install unicorn
- Capstone
    - pip install capstone
- pycryptodome (https://pypi.org/project/pycryptodome/)
    - pip install pycryptodome 
- Python 3.10 or later
- Tested with Windows 10 and Python 3.11.7, Ubuntu 22.04 and Python 3.12.8


#### First test

ROM0.bin must be put in roms/ as eosr_110.BIN, or use -r argument

Decrypting EOS RP update using default dump, from EOS R 1.1.0, (time command is optionnal).
```
$ time python3 d8_oracle.py fir/EOSRP160.FIR 
Input is update file fir/EOSRP160.FIR
  allocating 0x20c6400 bytes at 0x800000 for FIR file
Oracle is rom file roms/eosr_110.BIN loaded at 0xe0000000
Emulating cipher.bin at 0x200000. Code copied from 0xe0039000
  Updater decrypted ? True
  dumping verified and decrypted updater1 (0x800120-0xae5030) to file 80000433_1.6.0_updater1.bin
  found decryption function called around 0x81fef4-0x81ff00
Emulating AES decryption at 0x81fef4 within updater1
  dumping 80000433_1.6.0_firmware.bin (0xae5060-0x28c63a0)
  decryption successful ? True

real	1m36,076s
user	1m34,516s
sys	0m0,914s
```

The script can last 1 or 2 minutes.

2 files are created :
- 80000433_1.6.0_updater1.bin, the decrypted Updater
- 80000433_1.6.0_firmware.bin, the decrypted Firmware payload (update records)

updates records can be displayed and extracted using *fir_dump.py* tool:
```
>python dump_fir.py 80000424_1.8.0_firmware.bin

fileLen = 0x1d80b40
0x000: checksum = 0x5384a6ba
0x004: 0x00000000
0x008: 0x00000002
0x00c: 0x00000000
0x010: nb_record = 0xb
0x014: table_offset = 0x20
0x018: record_size = 0x18
0x01c: size_after = 0x1d80a18
0x020: ---patches table---
      + tag  + foffset  +   size   + moffset  +    ?
 --------------------------------------------------------
 0x01: 0x0100 0x00000128 0x01382824 0xe0040000 0x000228f6
 0x02: 0x0100 0x01382950 0x0015f308 0xe1c60000 0x00002b02
 0x03: 0x0100 0x014e1c58 0x00006173 0xe1ef0000 0x00000189
 0x04: 0x0100 0x014e7dd0 0x00052344 0xe1f50000 0x00000f5c
 0x05: 0x0100 0x0153a118 0x00000014 0xf0000000 0x00000019
 0x06: 0x0100 0x0153a130 0x0078afb0 0xf0b40000 0x0000c49c
 0x07: 0x0105 0x01cc50e0 0x0001d508 0x00000000 0x00000189
 0x08: 0x0200 0x01ce25e8 0x000000e6 0x00000000 0x00000066
 0x09: 0x0200 0x01ce26d0 0x00025728 0x00000000 0x00033333
 0x0a: 0x0200 0x01d07df8 0x00004456 0x00000000 0x00000333
 0x0b: 0x0200 0x01d0c250 0x000748f0 0x00000000 0x0001999a
```
#### Usage 

```
usage: d8_oracle.py [-h] [-r ROM] [-p] [-t] [-v] [-u] [-s] [-H] firfile

positional arguments:
  firfile            fir filename

options:
  -h, --help         show this help message and exit
  -r ROM, --rom ROM  rom dump
  -p, --patch        patch 1 byte of Updater signature to break ECDSA verification
  -t, --time         display emulations time
  -v, --verbose      verbose
  -u, --updater      decrypt updater only
  -s, --sign         signature verification only
  -H, --hash         display sha1 values
```

Decrypt EOS R update using EOS R ROM (by default as roms\eosr_110.BIN):
```
>python d8_oracle.py fir\EOSR0180.FIR
Input is update file fir\EOSR0180.FIR
  allocating 0x2071c00 bytes at 0x800000 for FIR file
Oracle is rom file roms\eosr_110.BIN loaded at 0xe0000000
Emulating cipher.bin at 0x200000. Code copied from 0xe0039000
  Updater decrypted ? True
  dumping verified and decrypted updater1 (0x800120-0xaf1050) to file 80000424_1.8.0_updater1.bin
  found decryption function called around 0x82b2ac-0x82b2b8
Emulating AES decryption at 0x82b2ac within updater1
  dumping 80000424_1.8.0_firmware.bin (0xaf1080-0x2871bc0)
  decryption successful ? True
```
Decrypt EOS R update using EOS RP ROM (-r option):
```
>python d8_oracle.py -r roms\eosrp_160.BIN fir\EOSR0180.FIR
b'c6735fd4e79aa90f22f2a8fb79bb56da5b6d4c29'
Input is update file fir\EOSR0180.FIR
  allocating 0x2071c00 bytes at 0x800000 for FIR file
Oracle is rom file roms\eosrp_160.BIN loaded at 0xe0000000
Emulating cipher.bin at 0x200000. Code copied from 0xe0039000
  Updater decrypted ? True
  dumping verified and decrypted updater1 (0x800120-0xaf1050) to file 80000424_1.8.0_updater1.bin
  found decryption function called around 0x82b2ac-0x82b2b8
Emulating AES decryption at 0x82b2ac within updater1
  dumping 80000424_1.8.0_firmware.bin (0xaf1080-0x2871bc0)
  decryption successful ? True
```
Modifies updater signature (-p option), signature is invalid:
```
>python d8_oracle.py -p -r roms\eosrp_160.BIN fir\EOSR0180.FIR
Input is update file fir\EOSR0180.FIR
  allocating 0x2071c00 bytes at 0x800000 for FIR file
Oracle is rom file roms\eosrp_160.BIN loaded at 0xe0000000
Emulating cipher.bin at 0x200000. Code copied from 0xe0039000
  Updater signature is invalid, aborting
```
Time measurements (-t):
```
>python d8_oracle.py -t -r roms\eosrp_160.BIN fir2\250d_CCF20101.FIR
Input is update file fir2\250d_CCF20101.FIR
  allocating 0x2257400 bytes at 0x800000 for FIR file
Oracle is rom file roms\eosrp_160.BIN loaded at 0xe0000000
Emulating cipher.bin at 0x200000. Code copied from 0xe0039000
  Updater decryption took: 0.65s
  Updater decrypted ? True
  dumping verified and decrypted updater1 (0x800120-0xaf0df0) to file 80000436_1.0.1_updater1.bin
  found decryption function called around 0x82c200-0x82c20c
Emulating AES decryption at 0x82c200 within updater1
  Firmware decryption took: 70.13s
  dumping 80000436_1.0.1_firmware.bin (0xaf0e20-0x2a57160)
  decryption successful ? True
```
Compute sha1 hashes (-H):
```
>python d8_oracle.py -H fir2\250d_CCF20101.FIR
Input is update file fir2\250d_CCF20101.FIR
  allocating 0x2257400 bytes at 0x800000 for FIR file
Oracle is rom file roms\eosr_110.BIN loaded at 0xe0000000
  sha1= c370d62be47f3dfe8eb4fc92a06418e97bdb35e3
Emulating cipher.bin at 0x200000. Code copied from 0xe0039000
  Updater decrypted ? True
  dumping verified and decrypted updater1 (0x800120-0xaf0df0) to file 80000436_1.0.1_updater1.bin
  sha1= b'6d5ea5cd07cd5441f6f0e785baad8629dcc78551'
  found decryption function called around 0x82c200-0x82c20c
Emulating AES decryption at 0x82c200 within updater1
  dumping 80000436_1.0.1_firmware.bin (0xaf0e20-0x2a57160)
  decryption successful ? True
  sha1= ed5164ed80f4b6bda1492089048f81cee9bb7b88
```

Verbose mode (-v) to trace interesting functions and their arguments:
```
>python d8_oracle.py -t -v fir2\250d_CCF20101.FIR
Input is update file fir2\250d_CCF20101.FIR
  allocating 0x2257400 bytes at 0x800000 for FIR file
Oracle is rom file roms\eosr_110.BIN loaded at 0xe0000000
Emulating cipher.bin at 0x200000. Code copied from 0xe0039000
  204ad0: sha256_update  R1/data=800000 R2/size=20 R0/ctx=f000000
  204ad0: sha256_update  R1/data=800024 R2/size=44 R0/ctx=f000000
  204ad0: sha256_update  R1/data=800100 R2/size=2f0cf0 R0/ctx=f000000
  Updater decryption took: 34.50s
  204d74: decrypt  R1=bfe00100 R2=100 R0=800000 R3=2057c4
  204ad0: sha256_update  R1/data=bfe00100 R2/size=100 R0/ctx=f13f70c
  204ad0: sha256_update  R1/data=2057c4 R2/size=10 R0/ctx=f13f70c
  2042dc: aes_key_expansion  R1=100e64 R2=10 R0=2057d4
  Updater decrypted ? True
  dumping verified and decrypted updater1 (0x800120-0xaf0df0) to file 80000436_1.0.1_updater1.bin
  found decryption function called around 0x82c200-0x82c20c
Emulating AES decryption at 0x82c200 within updater1
  Firmware decryption took: 69.31s
  dumping 80000436_1.0.1_firmware.bin (0xaf0e20-0x2a57160)
  decryption successful ? True
```

### d810_verif.py

A python script to verify secp256r1 signature of FIR files. sha256 and signatures are also extracted for experiments.

json output has been used to be loaded later in Python / Sage scripts.

#### Requirements

- FIR updates from Digic8 / Digic 10 cameras, except: M50, SX70, 4000D, 2000D, SX740, M6 m2, G5X m2. See https://eoscard.pel.hu/
- pycryptodome


#### Examples

the following json outputs, v1 and v2 are results of secp256r1 verifications respectively done for header+updater1 and firmware records.

```
>python d810_verif.py fir\EOSR0110.FIR
{
    "model_id": 2147484708,
    "digic": 8,
    "version": "1.1.0",
    "checksum": 4268450544,
    "l1": 32,
    "r1": 31323756063238374392508491582805776373437566423162572565846722368935386736017,
    "l2": 32,
    "s1": 74788522049821623814981105735963242052012423163522866445150358619063389558252,
    "l3": 32,
    "r2": 37338074232135136951525356287077330019241069257782543128061947696470943237382,
    "l4": 32,
    "s2": 87425640174130597392166027084233914813080538292068612777650224181962773338735,
    "h1": "2782fa56e08aa30d6d796800f5a533e33b1ac729526e8a7c17dba868a07f6cdf",
    "h2": "071c5cf3f87ef17c6ad0d47fb7d7be050f55ea33f6089fd7f10007c1c269a01d",
    "v1": true,
    "v2": true
}
```

```
>python d810_verif.py fir\EOSR6120.FIR
{
    "model_id": 2147484755,
    "digic": 10,
    "version": "1.2.0",
    "checksum": 2616006900,
    "l1": 32,
    "r1": 47792633328137182841597573660849596701047492904304937443793298288611044409372,
    "l2": 32,
    "s1": 42667954688985036105556263335159907808619858313438828049114817024814805705529,
    "l3": 32,
    "r2": 37498477888346825957785337362870872913532388735764960821251675480355619508103,
    "l4": 32,
    "s2": 57760211935964340613755306752130085042128545048977959178103793819193124656744,
    "h1": "67749f5cb22f937ab9b1a329f4df631f5f1701e4ac7c72a153b57e526f2eb262",
    "h2": "56a0b625912f793968671f025ca61f428ca61b8ccd094488cc4bb55f64531dc1",
    "v1": true,
    "v2": true
}
```

