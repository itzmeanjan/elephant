#!/usr/bin/python3

import elephant
import numpy as np
from random import Random, randint

u8 = np.uint8


def test_dumbo_kat():
    """
    Tests functional correctness of Dumbo AEAD implementation, using
    Known Answer Tests submitted along with final round submission of Elephant
    in NIST LWC

    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """
    with open("dumbo.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            # 128 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(len(key) >> 1, "big")
            # 96 -bit public message nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(len(nonce) >> 1, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # cipher text + authentication tag ( expected )
            ct = bytes(
                [
                    int(f"0x{ct[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ct) >> 1)
                ]
            )

            cipher, tag = elephant.dumbo_encrypt(key, nonce, ad, pt)
            flag, text = elephant.dumbo_decrypt(key, nonce, tag, ad, cipher)

            assert (
                cipher + tag == ct
            ), f"[Dumbo KAT {cnt}] expected cipher to be 0x{ct.hex()}, found 0x{(cipher + tag).hex()} !"
            assert (
                pt == text and flag
            ), f"[Dumbo KAT {cnt}] expected plain text 0x{pt.hex()}, found 0x{text.hex()} !"

            # don't need this line, so discard
            fd.readline()


def test_jumbo_kat():
    """
    Tests functional correctness of Jumbo AEAD implementation, using
    Known Answer Tests submitted along with final round submission of Elephant
    in NIST LWC

    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """
    with open("jumbo.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            # 128 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(len(key) >> 1, "big")
            # 96 -bit public message nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(len(nonce) >> 1, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # cipher text + authentication tag ( expected )
            ct = bytes(
                [
                    int(f"0x{ct[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ct) >> 1)
                ]
            )

            cipher, tag = elephant.jumbo_encrypt(key, nonce, ad, pt)
            flag, text = elephant.jumbo_decrypt(key, nonce, tag, ad, cipher)

            assert (
                cipher + tag == ct
            ), f"[Jumbo KAT {cnt}] expected cipher to be 0x{ct.hex()}, found 0x{(cipher + tag).hex()} !"
            assert (
                pt == text and flag
            ), f"[Jumbo KAT {cnt}] expected plain text 0x{pt.hex()}, found 0x{text.hex()} !"

            # don't need this line, so discard
            fd.readline()


def test_delirium_kat():
    """
    Tests functional correctness of Delirium AEAD implementation, using
    Known Answer Tests submitted along with final round submission of Elephant
    in NIST LWC

    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """
    with open("delirium.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            # 128 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(len(key) >> 1, "big")
            # 96 -bit public message nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(len(nonce) >> 1, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # cipher text + authentication tag ( expected )
            ct = bytes(
                [
                    int(f"0x{ct[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ct) >> 1)
                ]
            )

            cipher, tag = elephant.delirium_encrypt(key, nonce, ad, pt)
            flag, text = elephant.delirium_decrypt(key, nonce, tag, ad, cipher)

            assert (
                cipher + tag == ct
            ), f"[Delirium KAT {cnt}] expected cipher to be 0x{ct.hex()}, found 0x{(cipher + tag).hex()} !"
            assert (
                pt == text and flag
            ), f"[Delirium KAT {cnt}] expected plain text 0x{pt.hex()}, found 0x{text.hex()} !"

            # don't need this line, so discard
            fd.readline()


def flip_bit(inp: bytes) -> bytes:
    """
    Randomly selects a byte offset of a given byte array ( inp ), whose single random bit
    will be flipped. Input is **not** mutated & single bit flipped byte array is returned back.
    """
    arr = bytearray(inp)
    ilen = len(arr)

    idx = randint(0, ilen - 1)
    bidx = randint(0, 7)

    mask0 = (0xFF << (bidx + 1)) & 0xFF
    mask1 = (0xFF >> (8 - bidx)) & 0xFF
    mask2 = 1 << bidx

    msb = arr[idx] & mask0
    lsb = arr[idx] & mask1
    bit = (arr[idx] & mask2) >> bidx

    arr[idx] = msb | ((1 - bit) << bidx) | lsb
    return bytes(arr)


def test_dumbo_authentication():
    """
    Test that Dumbo authentication failure happens when random bit of associated data
    and/ or encrypted text are flipped. Also it's ensured that in case of authentication
    failure unverified plain text is never released, instead memory allocation for
    decrypted plain text is zeroed.
    """
    rng = Random()

    key = rng.randbytes(16)
    nonce = rng.randbytes(12)
    data = rng.randbytes(32)
    txt = rng.randbytes(32)

    enc, tag = elephant.dumbo_encrypt(key, nonce, data, txt)

    # case 0
    data_ = flip_bit(data)
    flg, dec = elephant.dumbo_decrypt(key, nonce, tag, data_, enc)

    assert not flg, "Dumbo authentication must fail !"
    for i in range(32):
        assert dec[i] == 0, "Unverified plain text must not be released !"

    # case 1
    enc_ = flip_bit(enc)
    flg, dec = elephant.dumbo_decrypt(key, nonce, tag, data, enc_)

    assert not flg, "Dumbo authentication must fail !"
    for i in range(32):
        assert dec[i] == 0, "Unverified plain text must not be released !"

    # case 2
    flg, dec = elephant.dumbo_decrypt(key, nonce, tag, data_, enc_)

    assert not flg, "Dumbo authentication must fail !"
    for i in range(32):
        assert dec[i] == 0, "Unverified plain text must not be released !"


def test_jumbo_authentication():
    """
    Test that Jumbo authentication failure happens when random bit of associated data
    and/ or encrypted text are flipped. Also it's ensured that in case of authentication
    failure unverified plain text is never released, instead memory allocation for
    decrypted plain text is zeroed.
    """
    rng = Random()

    key = rng.randbytes(16)
    nonce = rng.randbytes(12)
    data = rng.randbytes(32)
    txt = rng.randbytes(32)

    enc, tag = elephant.jumbo_encrypt(key, nonce, data, txt)

    # case 0
    data_ = flip_bit(data)
    flg, dec = elephant.jumbo_decrypt(key, nonce, tag, data_, enc)

    assert not flg, "Jumbo authentication must fail !"
    for i in range(32):
        assert dec[i] == 0, "Unverified plain text must not be released !"

    # case 1
    enc_ = flip_bit(enc)
    flg, dec = elephant.jumbo_decrypt(key, nonce, tag, data, enc_)

    assert not flg, "Jumbo authentication must fail !"
    for i in range(32):
        assert dec[i] == 0, "Unverified plain text must not be released !"

    # case 2
    flg, dec = elephant.jumbo_decrypt(key, nonce, tag, data_, enc_)

    assert not flg, "Jumbo authentication must fail !"
    for i in range(32):
        assert dec[i] == 0, "Unverified plain text must not be released !"


def test_delirium_authentication():
    """
    Test that Delirium authentication failure happens when random bit of associated data
    and/ or encrypted text are flipped. Also it's ensured that in case of authentication
    failure unverified plain text is never released, instead memory allocation for
    decrypted plain text is zeroed.
    """
    rng = Random()

    key = rng.randbytes(16)
    nonce = rng.randbytes(12)
    data = rng.randbytes(32)
    txt = rng.randbytes(32)

    enc, tag = elephant.delirium_encrypt(key, nonce, data, txt)

    # case 0
    data_ = flip_bit(data)
    flg, dec = elephant.delirium_decrypt(key, nonce, tag, data_, enc)

    assert not flg, "Delirium authentication must fail !"
    for i in range(32):
        assert dec[i] == 0, "Unverified plain text must not be released !"

    # case 1
    enc_ = flip_bit(enc)
    flg, dec = elephant.delirium_decrypt(key, nonce, tag, data, enc_)

    assert not flg, "Delirium authentication must fail !"
    for i in range(32):
        assert dec[i] == 0, "Unverified plain text must not be released !"

    # case 2
    flg, dec = elephant.delirium_decrypt(key, nonce, tag, data_, enc_)

    assert not flg, "Delirium authentication must fail !"
    for i in range(32):
        assert dec[i] == 0, "Unverified plain text must not be released !"


if __name__ == "__main__":
    print("Execute test cases using `pytest`")
