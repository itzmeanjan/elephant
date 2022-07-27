# elephant
Elephant - Fast, Parallelizable, Lightweight Authenticated Encryption Scheme

## Motivation

Elephant is a fast, parallelizable, lightweight authenticated encryption scheme ( with support for also authenticating associated data ), which is competing in final round of NIST Light Weight Cryptography ( LWC ) standardization effort.

> Find NIST LWC finalists [here](https://csrc.nist.gov/Projects/lightweight-cryptography/finalists)

Elephant is the 9th light weight AEAD scheme that I've decided to implement as a zero-dependency, header-only C++ library, which is easy to use

- Import header files & start using namespaced routines.
- During compilation, let your compiler know where it can find these header files.

> Learn more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

Elephant cipher suite offers three authenticated encryption/ verified decryption algorithms

- Dumbo ( **primary candidate** )
- Jumbo
- Delirium

**Dumbo** uses 80 -rounds of `Spongent-π[160]` permutation as its underlying construction. Dumbo encryption algorithm takes 16 -bytes secret key, 12 -bytes public message nonce, N -bytes associated data & M -bytes plain text, while computing M -bytes cipher text & 8 -bytes authentication tag. On the other hand Dumbo verified decryption algorithm takes 16 -bytes secret key, 12 -bytes nonce, 8 -bytes authentication tag, N -bytes associated data & M -bytes cipher text, producing M -bytes decrypted text & boolean verification flag.

**Jumbo** is built on top of 90 -rounds of `Spongent-π[176]` permutation. Encrypt/ decrypt interfaces look same as Dumbo.

**Delirium** is powered by 18 -rounds of `Keccak-f[200]` permutation, which works with 16 -bytes secret key, 12 -bytes public message nonce & 16 -bytes authentication tag.

> Note, in all of the above cases N, M >= 0 ( bytes ).

> Asssociated data is never encrypted. AEAD schemes provide secrecy only for plain text, while they provide integrity check for associated data & cipher text.

> Boolean verification flag must hold truth value ( i.e. authentication check must pass ) for decryption algorithm to release plain text.

> If boolean verification flag is false, decrypted plain text is zeroed.

During encryption using any of the above schemes, don't use same nonce twice, under same secret key.

While implementing Elephant, I followed the specification submitted to NIST LWC final round call, which can be retrieved from [here](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf). I suggest you go through this document to better understand the scheme.

Previous eight AEAD schemes, that I've worked on, can be found

- [Ascon](https://github.com/itzmeanjan/ascon)
- [TinyJambu](https://github.com/itzmeanjan/tinyjambu)
- [Xoodyak](https://github.com/itzmeanjan/xoodyak)
- [Sparkle](https://github.com/itzmeanjan/sparkle)
- [Photon-Beetle](https://github.com/itzmeanjan/photon-beetle)
- [ISAP](https://github.com/itzmeanjan/isap)
- [Romulus](https://github.com/itzmeanjan/romulus)
- [GIFT-COFB](https://github.com/itzmeanjan/gift-cofb)

> Track progress of NIST LWC standardization effort [here](https://csrc.nist.gov/Projects/lightweight-cryptography)

## Prerequisites

- C++ compiler such as `g++`/ `clang++`, with support for C++20 standard library

```bash
$ g++ --version
g++ (Ubuntu 11.2.0-19ubuntu1) 11.2.0

$ clang++ --version
Ubuntu clang version 14.0.0-1ubuntu1
Target: aarch64-unknown-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
```

- System development utilities such as `make`, `cmake`, `git`.

```bash
$ make --version
GNU Make 3.81

$ cmake --version
cmake version 3.23.2
```

- For testing functional correctness of Elephant AEAD schemes, you'll need to install `python3`, `wget` & `unzip`.

```bash
$ python3 --version
Python 3.10.4

$ wget --version
GNU Wget 1.21.3 built on darwin21.3.0.

$ unzip -v
UnZip 6.00 of 20 April 2009
```

- There are some python dependencies, which can be installed by issuing

```bash
python3 -m pip install --user -r wrapper/python/requirements.txt
```

- For benchmark Elephant AEAD schemes & underlying permutations, you need to globally install `google-benchmark`; see [this](https://github.com/google/benchmark/tree/60b16f1#installation) guide.

## Testing

For ensuring functional correctness and compatibility with Elephantv2 specification ( as submitted to NIST LWC final round call ), I make use of Known Answer Tests ( KAT ) in NIST submission package.

Given 16 -bytes secret key, 12 -bytes public message nonce, plain text and associated data, I use Dumbo, Jumbo `encrypt` routine for computing cipher text and 8 -bytes authentication tag, which is byte-by-byte compared against KATs. Finally an attempt to decrypt back to plain text, using Dumbo, Jumbo verified decryption algorithm, is also made, while ensuring presence of truth value in boolean verification flag.

> Note, if authentication verification fails ( during decryption phase ), decrypted plain text is not released ( i.e. zeroed ).

For executing test cases, issue

```bash
make
```
