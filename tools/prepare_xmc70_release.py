"""Prepare a merged ESP32-S3 release for the verified XMC 20:7018 board.
The expected download SHA256 must come from the upstream release checksums.
Unknown bootloaders are rejected by the existing audited correction.
"""
import argparse
import hashlib
from pathlib import Path
import struct
from xmc70_bootloader import correct_image

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('source',type=Path)
parser.add_argument('destination',type=Path)
parser.add_argument('--expected-sha256',required=True)
args=parser.parse_args()
if args.source.resolve()==args.destination.resolve():
    parser.error('Preserve the original release by choosing a separate destination')
image=args.source.read_bytes()
if hashlib.sha256(image).hexdigest()!=args.expected_sha256.lower():
    parser.error('Release SHA256 mismatch')
if len(image)<0x10000 or image[0]!=0xe9 or struct.unpack_from('<H',image,12)[0]!=9:
    parser.error('Expected a merged ESP32-S3 image starting at address zero')
pos=24
for _ in range(image[1]):
    _,length=struct.unpack_from('<II',image,pos)
    pos+=8+length
end=((pos+16)//16)*16+32
if end>0x8000:
    parser.error('Bootloader overlaps partition table')
patched=correct_image(image[:end])+image[end:]
with args.destination.open('xb') as output:
    output.write(patched)
print('Prepared',args.destination)
print('SHA256',hashlib.sha256(patched).hexdigest())
print('Application unchanged. Flash this board-specific merged image at offset 0x0.')
