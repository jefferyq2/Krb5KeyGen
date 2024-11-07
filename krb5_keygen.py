"""
Krb5KeyGen
Copyright (C) 2024 Javier Álvarez

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.
 
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import hashlib
import binascii
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

import argparse


def generate_ntlm_hash(password: str) -> bytes:
    password_unicode = password.encode("utf-16le")
    ntlm_hash = hashlib.new("md4", password_unicode).digest()
    return binascii.hexlify(ntlm_hash).decode()


def generate_kerberos_aes_key(password, salt, iterations=4096, key_size=128):
    password_bytes = password.encode("utf-8")
    salt_bytes = salt.encode("utf-8")

    AES256_CONSTANT = bytes([0x6B, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6F, 0x73, 0x7B, 0x9B, 0x5B, 0x2B, 0x93, 0x13, 0x2B, 0x93, 0x5C, 0x9B, 0xDC, 0xDA, 0xD9, 0x5C, 0x98, 0x99, 0xC4, 0xCA, 0xE4, 0xDE, 0xE6, 0xD6, 0xCA, 0xE4])
    AES128_CONSTANT = AES256_CONSTANT[:16]
    IV = bytes([0x00] * 16)

    derived_key = PBKDF2(password_bytes, salt_bytes, dkLen=32, count=iterations)

    if key_size == 128:
        aes_key = derived_key[:16]
        constant = AES128_CONSTANT
    elif key_size == 256:
        aes_key = derived_key
        constant = AES256_CONSTANT
    else:
        raise ValueError("key_size must be 128 or 256")

    cipher = AES.new(aes_key, AES.MODE_CBC, IV)
    aes_key_part_1 = cipher.encrypt(constant)

    cipher = AES.new(aes_key, AES.MODE_CBC, IV)
    aes_key_part_2 = cipher.encrypt(aes_key_part_1)

    final_key = aes_key_part_1[:16] + aes_key_part_2[:16]
    final_key = binascii.hexlify(final_key).decode("utf-8")
    return final_key if key_size == 256 else final_key[:32]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Krb5KeyGen is a tool designed to generate NTLM and Kerberos AES encryption keys based on user-provided credentials, domain information, and optional iteration counts.")
    parser.add_argument("username", type=str, help="Username, case-sensitive (e.g., 'Administrator' is different from 'administrator').")
    parser.add_argument("password", type=str, help="User's password.")
    parser.add_argument("domain", type=str, help="Complete domain, can be in uppercase or lowercase (e.g., CONTOSO.LOCAL or contoso.local).")
    parser.add_argument("--iterations", type=int, default=4096, help="Number of iterations (default is 4096, commonly used in Kerberos and Active Directory).")
    args = parser.parse_args()

    salt = f"{args.domain.upper()}{args.username}"

    ntlm_key = generate_ntlm_hash(args.password)
    print("Key NTLM (RC4-HMAC):", ntlm_key)

    aes128_key_size = 128
    aes128_key = generate_kerberos_aes_key(args.password, salt, args.iterations, aes128_key_size)
    print("Key AES128:", aes128_key)

    aes256_key_size = 256
    aes256_key = generate_kerberos_aes_key(args.password, salt, args.iterations, aes256_key_size)
    print("Key AES256:", aes256_key)
