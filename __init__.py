import hashlib
import io
import struct
import sys
import base64

import nacl.signing

if len(sys.argv) != 3:
    print("Usage: ssh-verify [file] [signature file]")
    sys.exit(2)

with open(sys.argv[2], "r") as sig_file:
    sig_armored = sig_file.read()

header = "-----BEGIN SSH SIGNATURE-----\n"
footer = "\n-----END SSH SIGNATURE-----\n"

assert sig_armored.startswith(header)
assert sig_armored.endswith(footer)

sig_bin = base64.b64decode(sig_armored[len(header):-len(footer)])
with io.BytesIO(sig_bin) as sig_stream:
    def check_eof(stream: io.IOBase):
        assert len(stream.read(1)) == 0

    def read_int(stream: io.RawIOBase, size: int = 4) -> int:
        return int.from_bytes(stream.read(size), "big")

    def read_string(stream: io.RawIOBase) -> bytes:
        size = read_int(stream)
        return stream.read(size)

    magic = sig_stream.read(6)
    assert magic == b"SSHSIG"

    version = read_int(sig_stream)
    assert version == 1

    with io.BytesIO(read_string(sig_stream)) as pk_ser:
        pk_type = read_string(pk_ser)

        if pk_type == b"ssh-ed25519":
            pk = nacl.signing.VerifyKey(read_string(pk_ser))
            check_eof(pk_ser)

        elif pk_type == b"sk-ssh-ed25519@openssh.com":
            pk = nacl.signing.VerifyKey(read_string(pk_ser))
            application = read_string(pk_ser)
            print(f"Application: {application.decode()}")
            check_eof(pk_ser)

        else:
            print(f"Unsupported key type: {pk_type}")
            sys.exit(1)

    namespace = read_string(sig_stream)
    assert read_string(sig_stream) == b""  # reserved
    hash_alg = read_string(sig_stream)

    with io.BytesIO(read_string(sig_stream)) as sig_ser:
        sig_type = read_string(sig_ser)
        assert sig_type == pk_type

        if pk_type == b"ssh-ed25519":
            signature = read_string(sig_ser)
            check_eof(sig_ser)

        elif pk_type == b"sk-ssh-ed25519@openssh.com":
            signature = read_string(sig_ser)
            flags = sig_ser.read(1)[0]
            counter = read_int(sig_ser)
            check_eof(sig_ser)

        else:
            print(f"Unsupported signature type: {pk_type}")
            sys.exit(1)

    check_eof(sig_stream)

    hasher = hashlib.new(hash_alg.decode())
    data = bytearray(1 << 16)
    view = memoryview(data)
    with open(sys.argv[1], "rb", buffering=0) as file:
        while True:
            block_len = file.readinto(data)
            if not block_len:
                break
            hasher.update(view[:block_len])
    digest = hasher.digest()

    with io.BytesIO() as signed_data_stream:
        def write_string(stream: io.RawIOBase, string: bytes):
            stream.write(len(string).to_bytes(4, "big"))
            stream.write(string)

        signed_data_stream.write(b"SSHSIG")
        write_string(signed_data_stream, namespace)
        write_string(signed_data_stream, b"")  # reserved
        write_string(signed_data_stream, hash_alg)
        write_string(signed_data_stream, digest)

        signed_data = bytes(signed_data_stream.getbuffer())

    if sig_type.startswith(b"sk-"):
        pre_signed_data = signed_data
        auth_data = hashlib.sha256(application).digest() + struct.pack("!BI", flags, counter)
        client_data_hash = hashlib.sha256(pre_signed_data).digest()
        signed_data = auth_data + client_data_hash

    pk.verify(signed_data, signature)
    print(f"{sig_type} signature with key {bytes(pk)} and namespace '{namespace.decode()}' verified successfully")
