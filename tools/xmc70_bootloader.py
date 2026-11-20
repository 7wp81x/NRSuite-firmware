"""Audited XMC 20:7018 workaround for this ESP32-S3's pinned bootloader.

This substitutes family 0x70 for 0x41 in the strict XMC identification check.
Other boards should use the unchanged esp32-s3 environment.
"""
import hashlib
from pathlib import Path
import struct

ORIGINAL_SHA256 = 'f65462cc7cfbe2382ccd4827a612a0081b03e4f6107aa7ea49e903df298558b8'
PATCHED_SHA256 = '694ab548c7891f7aeaa16fa017b496159f6d33605f13981f471cf624f90bbb8a'
PATCH_OFFSET = 9816

def correct_image(image):
    digest = hashlib.sha256(image).hexdigest()
    if digest == PATCHED_SHA256:
        return image
    if digest != ORIGINAL_SHA256:
        raise ValueError('Unknown bootloader SHA256 '+digest+'. Re-audit before using the XMC workaround.')
    patched = bytearray(image)
    assert patched[PATCH_OFFSET:PATCH_OFFSET+5] == bytes.fromhex('4c1aa79907')
    patched[PATCH_OFFSET:PATCH_OFFSET+5] = bytes.fromhex('a2c990cc6a')
    position, checksum = 24, 0xef
    for _ in range(patched[1]):
        _, length = struct.unpack_from('<II',patched,position)
        position += 8
        for value in patched[position:position+length]:
            checksum ^= value
        position += length
    offset = ((position+16)//16)*16-1
    patched[offset] = checksum
    patched[offset+1:] = hashlib.sha256(patched[:offset+1]).digest()
    result = bytes(patched)
    if hashlib.sha256(result).hexdigest() != PATCHED_SHA256:
        raise ValueError('Correction failed to reproduce the audited bootloader')
    return result

def prepare_bootloader(source,target,env):
    path = Path(env.subst('$BUILD_DIR/bootloader.bin'))
    try:
        original = path.read_bytes()
        corrected = correct_image(original)
        if original != corrected:
            temporary = path.with_suffix('.xmc70.tmp')
            temporary.write_bytes(corrected)
            temporary.replace(path)
        print('[XMC70] Verified bootloader '+PATCHED_SHA256)
    except (OSError,ValueError) as error:
        print('[XMC70] Upload/build stopped: '+str(error))
        return 1
    return 0

if 'Import' in globals():
    Import('env')
    if env.subst('$PIOENV') != 'esp32-s3-xmc70':
        raise ValueError('XMC70 hook is only for esp32-s3-xmc70')
    env.AddPostAction('$BUILD_DIR/bootloader.bin',prepare_bootloader)
    env.AddPreAction('upload',prepare_bootloader)
