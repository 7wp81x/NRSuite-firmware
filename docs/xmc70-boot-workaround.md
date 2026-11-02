# ESP32-S3 XMC 20:7018 boot failure and release workaround

## Problem and observed cause

An ESP32-S3 v0.2 board with 16 MB XMC flash, manufacturer 0x20 and
device 0x7018, rebooted with `bootloader_flash: XMC flash startup fail`
when the stock beta.3 merged image was installed. Correcting only the
bootloader restored boot and USB STATUS replies.

The official v1.0.0-beta.3.1.2 S3 merged image contains the exact same
18,976-byte bootloader, SHA256
`f65462cc7cfbe2382ccd4827a612a0081b03e4f6107aa7ea49e903df298558b8`.
The download was checked against the release's published checksum.
The stock 3.1.2 image was not deliberately flashed to reproduce another loop.
Its identical bootloader and this board's prior result motivated applying
the same verified correction before installation.

The existing audited binary correction changes the strict XMC family check
from 0x41 to 0x70, preserving manufacturer/capacity and the other 0x40/0x50
family checks. At offset 9816 it replaces `4c1aa79907` with `a2c990cc6a`,
then repairs the ESP image checksum and appended SHA256. The corrected
bootloader hash must be
`694ab548c7891f7aeaa16fa017b496159f6d33605f13981f471cf624f90bbb8a`.

This is a narrowly scoped workaround for the tested XMC board. Because it
substitutes the strict 0x41 check, it must not silently replace the generic
S3 bootloader for all flash families. A long-term source-level bootloader
fix should add this flash support while preserving existing supported chips.
No universal source-level fix is claimed by this contribution.

## What is included

- `tools/xmc70_bootloader.py`: exact-hash guarded binary correction. It accepts
  only the audited original and corrected bootloader; corrected input is
  idempotent and unknown inputs fail closed. Its existing optional SCons
  hook is restricted to an explicitly configured `esp32-s3-xmc70` environment.
  This contribution does not enable that environment or alter standard builds.
- `tools/prepare_xmc70_release.py`: checks the caller-supplied upstream release
  SHA256 and merged ESP32-S3 header, extracts and corrects the bootloader,
  and creates a separate output. All bytes after the bootloader stay unchanged.
  Existing outputs are not overwritten. It does not communicate with a board.
- `test/test_xmc70_release.py`: offline golden-image and refusal checks using
  a separately downloaded official release as the fixture.
- `docs/xmc70-boot-evidence.json`: minimized verification evidence without
  device identifiers, flash contents, credentials, or host-specific paths.

## Reproduce the prepared image

Download the S3 image and `checksums.txt` from
[release v1.0.0-beta.3.1.2](https://github.com/7wp81x/NRSuite-firmware/releases/tag/v1.0.0-beta.3.1.2).
Use the published checksum for the exact release being prepared.

```sh
python tools/prepare_xmc70_release.py \
  beta-nrsuite-esp32s3-v1.0.0-beta.3.1.2.bin \
  beta-nrsuite-esp32s3-v1.0.0-beta.3.1.2-xmc70.bin \
  --expected-sha256 b8447c5ca535ee2f288097ccb52de548beb8d8f2412b35024a85913844a60b8e
```

Expected corrected merged-image SHA256:
`e76ca44658249e45568c6546533199f05ad2221b12d48a588b839bfe46d0f528`.
Flash at offset `0x0` only on the intended XMC 20:7018 S3 board, after saving
a recovery backup and confirming the board identity.

Each future release needs its own published download checksum. A changed
bootloader will be rejected until separately reviewed. Flashing a stock
merged image again replaces the corrected bootloader, which explains why
an application update can bring back this startup failure.

## Verification and limits

On 2026-11-02 a full private 16 MB recovery backup was saved, then esptool
5.1.0 wrote 1,676,048 bytes at 0x0 and reported `Hash of data verified.`
The prepared image's app segment checksum and appended SHA256 were valid;
its application and partition bytes matched the official release unchanged.
The bootloader also passed esptool image-info checksum/hash validation.

After upload the board initially stayed in ROM download mode, showing
`boot:0x0 (DOWNLOAD(USB/UART0))` and `waiting for download`. A physical reset
with BOOT released resolved this separate boot-mode state. This capture
was not an application crash.

Three USB STATUS replies reported `v1.0.0-beta.3.1.2` and `ESP32-S3`.
Uptime advanced 20842 -> 36052 -> 51268 ms, with free heap 147372 bytes in
each reply. These are saved observations, not a claim of exhaustive testing.
No cold power cycle, Android UI, or radio feature acceptance was performed.
The repository source was not rebuilt for this release-image installation.

Run the offline checks with Python 3.9+:

```sh
python test/test_xmc70_release.py --release /path/to/beta-nrsuite-esp32s3-v1.0.0-beta.3.1.2.bin
```

## Suggested upstream resolution

Review XMC startup handling in the pinned bootloader/library build and add
support for 20:7018 without removing support for other flash families. Until
that is available, an explicitly named XMC-specific release asset could use
this guarded preparation step. The generic S3 release should retain its
existing behavior. Revalidate on the affected hardware whenever the
bootloader dependency changes.
