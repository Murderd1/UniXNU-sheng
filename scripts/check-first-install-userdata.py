#!/usr/bin/env python3
"""Host checks for signed table restoration and explicit sparse zeroing."""
import hashlib
import importlib.util
import io
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import uuid

spec = importlib.util.spec_from_file_location('first_install', Path(__file__).with_name('build-first-install-userdata.py'))
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class FirstInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.out = Path(cls.temporary.name)
        cls.private = cls.out / 'test-private.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072',
                        '-out', str(cls.private)], check=True, capture_output=True)
        modulus = subprocess.check_output(['openssl', 'rsa', '-in', str(cls.private), '-modulus', '-noout'], text=True)
        cls.anchor = b'VROOTKEY' + bytes.fromhex(modulus.strip().split('=')[1]) + b'\x01\x00\x01'
        # Cross the streaming boundary and exercise a final partial block.
        cls.image = b'\x7e' * (build.CHUNK + 19)
        cls.image_hash = hashlib.sha256(cls.image).digest()
        cls.hashes = b''.join(hashlib.sha256(cls.image[i:i + 4096]).digest() for i in range(0, len(cls.image), 4096))
        cls.volume = uuid.uuid4()
        cls.window = dict(offset=37, size=len(cls.image), sha256=cls.image_hash.hex())
        cls.envelope = cls.sign(hashlib.sha256(cls.hashes).digest())

    @classmethod
    def sign(cls, table_hash):
        header = build.HEADER.pack(b'VROOT01\0', 1, 160, 4096, 0, len(cls.image), len(cls.hashes) // 32,
                                   cls.volume.bytes, cls.image_hash, table_hash, hashlib.sha256(cls.anchor).digest(), 1)
        (cls.out / 'header').write_bytes(header)
        signature = subprocess.check_output(['openssl', 'dgst', '-sha256', '-sign', str(cls.private), str(cls.out / 'header')])
        return header + signature

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def restore(self, image=None, envelope=None, volume=None):
        destination = self.out / 'restored.vroot'
        destination.unlink(missing_ok=True)
        build.restore_manifest(io.BytesIO(bytes(37) + (self.image if image is None else image)), self.window,
                               self.envelope if envelope is None else envelope, self.anchor, destination,
                               self.image_hash.hex(), str(self.volume if volume is None else volume))
        return destination.read_bytes()

    def test_restored_envelope_preserves_signature_and_exact_table(self):
        self.assertEqual(self.restore(), self.envelope + self.hashes)

    def test_corrupted_image_and_short_read_rejected(self):
        for data in (b'X' + self.image[1:], self.image[:-1]):
            with self.assertRaises(ValueError):
                self.restore(image=data)
            self.assertFalse((self.out / 'restored.partial').exists())

    def test_modified_signature_rejected(self):
        with self.assertRaisesRegex(ValueError, 'signature'):
            self.restore(envelope=self.envelope[:-1] + bytes([self.envelope[-1] ^ 1]))

    def test_valid_signature_with_wrong_table_hash_rejected(self):
        with self.assertRaisesRegex(ValueError, 'table hash'):
            self.restore(envelope=self.sign(bytes(32)))

    def test_wrong_volume_and_key_rejected(self):
        with self.assertRaisesRegex(ValueError, 'UUID'):
            self.restore(volume=uuid.uuid4())
        with self.assertRaisesRegex(ValueError, 'key hash'):
            build.verify_policy(self.envelope, self.anchor[:10] + bytes([self.anchor[10] ^ 1]) + self.anchor[11:])

    def test_shipped_policy_signatures(self):
        for name in ('OS', 'SystemOS'):
            policy = build.DEVICE / 'scripts/policies/ipados-27.0.1-24A446' / name
            build.verify_policy((policy / 'manifest.header.bin').read_bytes(), (policy / 'trusted-key.bin').read_bytes())

    def test_sparse_expands_to_root_followed_by_explicit_zeros(self):
        raw, sparse = self.out / 'root', self.out / 'sparse'
        content = b'R' * 4096 + bytes(8192) + b'T' * 4096
        raw.write_bytes(content)
        build.sparse_image(raw, sparse, 65536)
        stream = io.BytesIO(sparse.read_bytes())
        magic, major, minor, header_size, chunk_header, block, blocks, chunks, checksum = struct.unpack('<IHHHHIIII', stream.read(28))
        self.assertEqual((magic, major, minor, header_size, chunk_header, block, blocks), (0xed26ff3a, 1, 0, 28, 12, 4096, 16))
        expanded = bytearray()
        for _ in range(chunks):
            kind, _, count, total = struct.unpack('<HHII', stream.read(12))
            body = stream.read(total - 12)
            if kind == 0xcac1:
                self.assertEqual(len(body), count * block)
                expanded.extend(body)
            else:
                self.assertEqual((kind, body), (0xcac2, bytes(4)))
                expanded.extend(body * (count * block // 4))
        self.assertEqual(expanded, content + bytes(65536 - len(content)))
        self.assertEqual(stream.read(), b'')


if __name__ == '__main__':
    unittest.main(verbosity=2)
