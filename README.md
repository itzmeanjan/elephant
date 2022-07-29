# elephant
Elephant - Fast, Parallelizable, Lightweight Authenticated Encryption Scheme

## Motivation

Elephant is a fast, parallelizable, lightweight authenticated encryption scheme ( with support for also authenticating associated data ), which is competing in final round of NIST Light Weight Cryptography ( LWC ) standardization effort.

> Find NIST LWC finalists [here](https://csrc.nist.gov/Projects/lightweight-cryptography/finalists)

Elephant is the 9th light weight AEAD scheme that I've decided to implement as a zero-dependency, header-only C++ library, which is fairly easy to use

- Import header files & start using namespaced routines.
- During compilation, let your compiler know where it can find these header files.

> Learn more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

Elephant cipher suite offers three authenticated encryption/ verified decryption algorithms

Scheme | Nature | Based on Permutation | Secret Key Size | Nonce Size | Authentication Tag Size
--- | --: | :-: | --: | --: | --:
Dumbo ( **primary candidate** ) | H/W friendly | Spongent-π[160] | 16 -bytes | 12 -bytes | 8 -bytes
Jumbo | H/W friendly | Spongent-π[176] | 16 -bytes | 12 -bytes | 8 -bytes
Delirium | S/W friendly | Keccak-f[200] | 16 -bytes | 12 -bytes | 16 -bytes

**Dumbo** uses 80 -rounds of `Spongent-π[160]` permutation as its underlying construction. Dumbo encryption algorithm takes 16 -bytes secret key, 12 -bytes public message nonce, N -bytes associated data & M -bytes plain text, while computing M -bytes cipher text & 8 -bytes authentication tag. On the other hand Dumbo verified decryption algorithm takes 16 -bytes secret key, 12 -bytes nonce, 8 -bytes authentication tag, N -bytes associated data & M -bytes cipher text, producing M -bytes decrypted text & boolean verification flag.

**Jumbo** is built on top of 90 -rounds of `Spongent-π[176]` permutation. Encrypt/ decrypt interfaces look same as Dumbo.

**Delirium** is powered by 18 -rounds of `Keccak-f[200]` permutation, which works with 16 -bytes secret key, 12 -bytes public message nonce & 16 -bytes authentication tag.

> Note, in all of the above cases N, M >= 0 ( bytes ).

> Asssociated data is never encrypted. AEAD schemes provide secrecy only for plain text, while they provide integrity check for associated data & cipher text.

> Boolean verification flag must hold truth value ( i.e. authentication check must pass ) for decryption algorithm to release plain text.

> If boolean verification flag is false, decrypted plain text is zeroed.

During encryption using any of the above schemes, don't reuse same nonce, under same secret key.

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

Similarly Delirium AEAD implementation is tested against KATs, only difference is that it uses 16 -bytes authentication tag.

> Note, if authentication verification fails ( during decryption phase ), decrypted plain text is not released ( i.e. zeroed ).

For executing test cases, issue

```bash
make
```

## Benchmarking

Benchmarking following listed routines, can be done by issuing

```bash
make benchmark
```

> For disabling CPU scaling, when benchmarking, see [this](https://github.com/google/benchmark/blob/60b16f1/docs/user_guide.md#disabling-cpu-frequency-scaling)

- Spongent-π[160], Spongent-π[176] permutation
- Keccak-f[200] permutation
- Dumbo encrypt/ decrypt
- Jumbo encrypt/ decrypt
- Delirium encrypt/ decrypt

> Note, benchmarking of encrypt/ decrypt routines are done with constant sized ( 32 -bytes ) associated data & varied length ( power of 2 values from 64 to 4096 -bytes ) plain/ cipher text. Both associated data & plain texts are randomly generated.

> Also note, neither Dumbo nor Jumbo is software platform friendly, but Keccak-f[200] based Delirium is; see section 1 of Elephant [specification](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf)

> You'll be able to notice that Delirium AEAD performs much better compared to Dumbo & Jumbo, in following benchmark results.

> Elephant is an encrypt-then-mac style construction, which makes it possible to parallelly {en, de}crypt different plain/ cipher text blocks, though parallelization is not yet implemented here.

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-07-29T10:50:25+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.55, 2.30, 2.46
--------------------------------------------------------------------------------------------------------
Benchmark                                              Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------------
bench_elephant::spongent_permutation<160, 1>         321 ns          320 ns      2245079 bytes_per_second=59.6076M/s
bench_elephant::spongent_permutation<160, 80>      25128 ns        25111 ns        26192 bytes_per_second=777.795k/s
bench_elephant::spongent_permutation<176, 1>         360 ns          360 ns      1949839 bytes_per_second=58.2627M/s
bench_elephant::spongent_permutation<176, 90>      32259 ns        32233 ns        21536 bytes_per_second=666.524k/s
bench_elephant::keccak_permutation<1>               33.0 ns         33.0 ns     21486959 bytes_per_second=723.122M/s
bench_elephant::keccak_permutation<18>               587 ns          587 ns      1182532 bytes_per_second=40.6443M/s
bench_elephant::dumbo_encrypt/32/64               374786 ns       374613 ns         1860 bytes_per_second=250.258k/s
bench_elephant::dumbo_decrypt/32/64               374672 ns       374325 ns         1855 bytes_per_second=250.451k/s
bench_elephant::dumbo_encrypt/32/128              525021 ns       524773 ns         1317 bytes_per_second=297.748k/s
bench_elephant::dumbo_decrypt/32/128              524771 ns       524514 ns         1319 bytes_per_second=297.895k/s
bench_elephant::dumbo_encrypt/32/256              827981 ns       827412 ns          839 bytes_per_second=339.915k/s
bench_elephant::dumbo_decrypt/32/256              822066 ns       821595 ns          838 bytes_per_second=342.322k/s
bench_elephant::dumbo_encrypt/32/512             1498709 ns      1484817 ns          469 bytes_per_second=357.788k/s
bench_elephant::dumbo_decrypt/32/512             1475760 ns      1474851 ns          476 bytes_per_second=360.206k/s
bench_elephant::dumbo_encrypt/32/1024            2778663 ns      2776486 ns          253 bytes_per_second=371.423k/s
bench_elephant::dumbo_decrypt/32/1024            2798333 ns      2795474 ns          253 bytes_per_second=368.9k/s
bench_elephant::dumbo_encrypt/32/2048            5319518 ns      5317122 ns          131 bytes_per_second=382.021k/s
bench_elephant::dumbo_decrypt/32/2048            5344753 ns      5341140 ns          129 bytes_per_second=380.303k/s
bench_elephant::dumbo_encrypt/32/4096           10429979 ns     10423667 ns           66 bytes_per_second=386.74k/s
bench_elephant::dumbo_decrypt/32/4096           10396952 ns     10393299 ns           67 bytes_per_second=387.87k/s
bench_elephant::jumbo_encrypt/32/64               418585 ns       418348 ns         1660 bytes_per_second=224.096k/s
bench_elephant::jumbo_decrypt/32/64               417875 ns       417763 ns         1672 bytes_per_second=224.41k/s
bench_elephant::jumbo_encrypt/32/128              615919 ns       615390 ns         1124 bytes_per_second=253.904k/s
bench_elephant::jumbo_decrypt/32/128              612780 ns       612581 ns         1044 bytes_per_second=255.068k/s
bench_elephant::jumbo_encrypt/32/256             1002065 ns      1001263 ns          691 bytes_per_second=280.895k/s
bench_elephant::jumbo_decrypt/32/256             1001474 ns      1001072 ns          696 bytes_per_second=280.949k/s
bench_elephant::jumbo_encrypt/32/512             1783778 ns      1781651 ns          395 bytes_per_second=298.179k/s
bench_elephant::jumbo_decrypt/32/512             1773050 ns      1772175 ns          394 bytes_per_second=299.773k/s
bench_elephant::jumbo_encrypt/32/1024            3248714 ns      3247397 ns          214 bytes_per_second=317.562k/s
bench_elephant::jumbo_decrypt/32/1024            3269078 ns      3267090 ns          200 bytes_per_second=315.648k/s
bench_elephant::jumbo_encrypt/32/2048            6564727 ns      6530101 ns          109 bytes_per_second=311.06k/s
bench_elephant::jumbo_decrypt/32/2048            6869725 ns      6788796 ns           93 bytes_per_second=299.206k/s
bench_elephant::jumbo_encrypt/32/4096           12411939 ns     12372536 ns           56 bytes_per_second=325.822k/s
bench_elephant::jumbo_decrypt/32/4096           12581601 ns     12511566 ns           53 bytes_per_second=322.202k/s
bench_elephant::delirium_encrypt/32/64              7372 ns         7366 ns        92195 bytes_per_second=12.4295M/s
bench_elephant::delirium_decrypt/32/64              7999 ns         7850 ns        86856 bytes_per_second=11.6628M/s
bench_elephant::delirium_encrypt/32/128            12077 ns        11862 ns        59221 bytes_per_second=12.8633M/s
bench_elephant::delirium_decrypt/32/128            11187 ns        11167 ns        58189 bytes_per_second=13.6643M/s
bench_elephant::delirium_encrypt/32/256            17422 ns        17406 ns        40019 bytes_per_second=15.7797M/s
bench_elephant::delirium_decrypt/32/256            17511 ns        17491 ns        38418 bytes_per_second=15.703M/s
bench_elephant::delirium_encrypt/32/512            29989 ns        29967 ns        23113 bytes_per_second=17.3123M/s
bench_elephant::delirium_decrypt/32/512            30111 ns        30084 ns        23126 bytes_per_second=17.245M/s
bench_elephant::delirium_encrypt/32/1024           55462 ns        55321 ns        12292 bytes_per_second=18.2043M/s
bench_elephant::delirium_decrypt/32/1024           55125 ns        55073 ns        12068 bytes_per_second=18.2864M/s
bench_elephant::delirium_encrypt/32/2048          106736 ns       106697 ns         6470 bytes_per_second=18.5914M/s
bench_elephant::delirium_decrypt/32/2048          108815 ns       108366 ns         6091 bytes_per_second=18.305M/s
bench_elephant::delirium_encrypt/32/4096          216919 ns       215549 ns         3119 bytes_per_second=18.2639M/s
bench_elephant::delirium_decrypt/32/4096          218069 ns       216541 ns         3213 bytes_per_second=18.1802M/s
```

### On AWS Graviton2

```bash
2022-07-29T06:52:15+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.15, 0.03, 0.01
--------------------------------------------------------------------------------------------------------
Benchmark                                              Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------------
bench_elephant::spongent_permutation<160, 1>         675 ns          675 ns      1036164 bytes_per_second=28.2462M/s
bench_elephant::spongent_permutation<160, 80>      54064 ns        54063 ns        12944 bytes_per_second=361.265k/s
bench_elephant::spongent_permutation<176, 1>         639 ns          639 ns      1095754 bytes_per_second=32.8431M/s
bench_elephant::spongent_permutation<176, 90>      56916 ns        56915 ns        12297 bytes_per_second=377.48k/s
bench_elephant::keccak_permutation<1>               64.4 ns         64.4 ns     10870294 bytes_per_second=370.269M/s
bench_elephant::keccak_permutation<18>              1012 ns         1012 ns       691370 bytes_per_second=23.5483M/s
bench_elephant::dumbo_encrypt/32/64               810610 ns       810605 ns          864 bytes_per_second=115.654k/s
bench_elephant::dumbo_decrypt/32/64               810542 ns       810538 ns          864 bytes_per_second=115.664k/s
bench_elephant::dumbo_encrypt/32/128             1134860 ns      1134833 ns          617 bytes_per_second=137.685k/s
bench_elephant::dumbo_decrypt/32/128             1134771 ns      1134763 ns          617 bytes_per_second=137.694k/s
bench_elephant::dumbo_encrypt/32/256             1783373 ns      1783331 ns          393 bytes_per_second=157.71k/s
bench_elephant::dumbo_decrypt/32/256             1783303 ns      1783277 ns          393 bytes_per_second=157.715k/s
bench_elephant::dumbo_encrypt/32/512             3188341 ns      3188320 ns          220 bytes_per_second=166.624k/s
bench_elephant::dumbo_decrypt/32/512             3188489 ns      3188416 ns          220 bytes_per_second=166.619k/s
bench_elephant::dumbo_encrypt/32/1024            5998457 ns      5998376 ns          117 bytes_per_second=171.922k/s
bench_elephant::dumbo_decrypt/32/1024            5998382 ns      5998342 ns          117 bytes_per_second=171.923k/s
bench_elephant::dumbo_encrypt/32/2048           11509963 ns     11509888 ns           61 bytes_per_second=176.479k/s
bench_elephant::dumbo_decrypt/32/2048           11510028 ns     11509950 ns           61 bytes_per_second=176.478k/s
bench_elephant::dumbo_encrypt/32/4096           22533223 ns     22533082 ns           31 bytes_per_second=178.904k/s
bench_elephant::dumbo_decrypt/32/4096           22535620 ns     22534223 ns           31 bytes_per_second=178.895k/s
bench_elephant::jumbo_encrypt/32/64               746437 ns       746411 ns          938 bytes_per_second=125.601k/s
bench_elephant::jumbo_decrypt/32/64               747161 ns       747156 ns          937 bytes_per_second=125.476k/s
bench_elephant::jumbo_encrypt/32/128             1090978 ns      1090970 ns          642 bytes_per_second=143.221k/s
bench_elephant::jumbo_decrypt/32/128             1091762 ns      1091738 ns          641 bytes_per_second=143.12k/s
bench_elephant::jumbo_encrypt/32/256             1780147 ns      1780136 ns          393 bytes_per_second=157.994k/s
bench_elephant::jumbo_decrypt/32/256             1780949 ns      1780918 ns          393 bytes_per_second=157.924k/s
bench_elephant::jumbo_encrypt/32/512             3158472 ns      3158452 ns          222 bytes_per_second=168.199k/s
bench_elephant::jumbo_decrypt/32/512             3159294 ns      3159275 ns          222 bytes_per_second=168.156k/s
bench_elephant::jumbo_encrypt/32/1024            5800189 ns      5800151 ns          121 bytes_per_second=177.797k/s
bench_elephant::jumbo_decrypt/32/1024            5801250 ns      5801213 ns          121 bytes_per_second=177.765k/s
bench_elephant::jumbo_encrypt/32/2048           11198258 ns     11198077 ns           63 bytes_per_second=181.393k/s
bench_elephant::jumbo_decrypt/32/2048           11199316 ns     11199241 ns           63 bytes_per_second=181.374k/s
bench_elephant::jumbo_encrypt/32/4096           21879577 ns     21879278 ns           32 bytes_per_second=184.25k/s
bench_elephant::jumbo_decrypt/32/4096           21880699 ns     21880551 ns           32 bytes_per_second=184.239k/s
bench_elephant::delirium_encrypt/32/64             13094 ns        13094 ns        53458 bytes_per_second=6.99216M/s
bench_elephant::delirium_decrypt/32/64             12744 ns        12743 ns        54900 bytes_per_second=7.18428M/s
bench_elephant::delirium_encrypt/32/128            19910 ns        19910 ns        35157 bytes_per_second=7.66388M/s
bench_elephant::delirium_decrypt/32/128            19100 ns        19100 ns        36646 bytes_per_second=7.98878M/s
bench_elephant::delirium_encrypt/32/256            31313 ns        31312 ns        22361 bytes_per_second=8.77156M/s
bench_elephant::delirium_decrypt/32/256            29666 ns        29665 ns        23596 bytes_per_second=9.25853M/s
bench_elephant::delirium_encrypt/32/512            54065 ns        54064 ns        12944 bytes_per_second=9.59593M/s
bench_elephant::delirium_decrypt/32/512            50740 ns        50737 ns        13804 bytes_per_second=10.2252M/s
bench_elephant::delirium_encrypt/32/1024           99556 ns        99556 ns         7031 bytes_per_second=10.1157M/s
bench_elephant::delirium_decrypt/32/1024           92935 ns        92932 ns         7532 bytes_per_second=10.8367M/s
bench_elephant::delirium_encrypt/32/2048          192850 ns       192849 ns         3630 bytes_per_second=10.286M/s
bench_elephant::delirium_decrypt/32/2048          179465 ns       179462 ns         3900 bytes_per_second=11.0533M/s
bench_elephant::delirium_encrypt/32/4096          379266 ns       379263 ns         1845 bytes_per_second=10.38M/s
bench_elephant::delirium_decrypt/32/4096          352195 ns       352193 ns         1988 bytes_per_second=11.1779M/s
```

### On AWS Graviton3

```bash
2022-07-29T06:54:03+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.08, 0.02, 0.01
--------------------------------------------------------------------------------------------------------
Benchmark                                              Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------------
bench_elephant::spongent_permutation<160, 1>         361 ns          361 ns      1941443 bytes_per_second=52.8981M/s
bench_elephant::spongent_permutation<160, 80>      27873 ns        27873 ns        25115 bytes_per_second=700.731k/s
bench_elephant::spongent_permutation<176, 1>         316 ns          316 ns      2213373 bytes_per_second=66.3474M/s
bench_elephant::spongent_permutation<176, 90>      28464 ns        28464 ns        24597 bytes_per_second=754.802k/s
bench_elephant::keccak_permutation<1>               41.1 ns         41.1 ns     17020969 bytes_per_second=579.426M/s
bench_elephant::keccak_permutation<18>               520 ns          520 ns      1346944 bytes_per_second=45.8723M/s
bench_elephant::dumbo_encrypt/32/64               422299 ns       422290 ns         1658 bytes_per_second=222.004k/s
bench_elephant::dumbo_decrypt/32/64               418785 ns       418774 ns         1672 bytes_per_second=223.868k/s
bench_elephant::dumbo_encrypt/32/128              592426 ns       592413 ns         1181 bytes_per_second=263.752k/s
bench_elephant::dumbo_decrypt/32/128              586248 ns       586235 ns         1194 bytes_per_second=266.531k/s
bench_elephant::dumbo_encrypt/32/256              932741 ns       932721 ns          751 bytes_per_second=301.537k/s
bench_elephant::dumbo_decrypt/32/256              921221 ns       921183 ns          760 bytes_per_second=305.314k/s
bench_elephant::dumbo_encrypt/32/512             1670313 ns      1670234 ns          419 bytes_per_second=318.069k/s
bench_elephant::dumbo_decrypt/32/512             1646950 ns      1646914 ns          418 bytes_per_second=322.573k/s
bench_elephant::dumbo_encrypt/32/1024            3143817 ns      3143749 ns          223 bytes_per_second=328.032k/s
bench_elephant::dumbo_decrypt/32/1024            3097916 ns      3097848 ns          226 bytes_per_second=332.892k/s
bench_elephant::dumbo_encrypt/32/2048            6035157 ns      6035025 ns          116 bytes_per_second=336.577k/s
bench_elephant::dumbo_decrypt/32/2048            5944662 ns      5944533 ns          118 bytes_per_second=341.701k/s
bench_elephant::dumbo_encrypt/32/4096           11818049 ns     11817791 ns           59 bytes_per_second=341.117k/s
bench_elephant::dumbo_decrypt/32/4096           11636729 ns     11636475 ns           60 bytes_per_second=346.432k/s
bench_elephant::jumbo_encrypt/32/64               369705 ns       369697 ns         1891 bytes_per_second=253.586k/s
bench_elephant::jumbo_decrypt/32/64               370411 ns       370401 ns         1894 bytes_per_second=253.104k/s
bench_elephant::jumbo_encrypt/32/128              541387 ns       541365 ns         1289 bytes_per_second=288.622k/s
bench_elephant::jumbo_decrypt/32/128              543241 ns       543220 ns         1294 bytes_per_second=287.637k/s
bench_elephant::jumbo_encrypt/32/256              882570 ns       882551 ns          793 bytes_per_second=318.678k/s
bench_elephant::jumbo_decrypt/32/256              885685 ns       885666 ns          792 bytes_per_second=317.558k/s
bench_elephant::jumbo_encrypt/32/512             1566715 ns      1566675 ns          447 bytes_per_second=339.094k/s
bench_elephant::jumbo_decrypt/32/512             1567668 ns      1567620 ns          447 bytes_per_second=338.89k/s
bench_elephant::jumbo_encrypt/32/1024            2877745 ns      2877659 ns          243 bytes_per_second=358.364k/s
bench_elephant::jumbo_decrypt/32/1024            2878913 ns      2878850 ns          243 bytes_per_second=358.216k/s
bench_elephant::jumbo_encrypt/32/2048            5557484 ns      5557337 ns          126 bytes_per_second=365.508k/s
bench_elephant::jumbo_decrypt/32/2048            5558373 ns      5558252 ns          126 bytes_per_second=365.448k/s
bench_elephant::jumbo_encrypt/32/4096           10867850 ns     10867613 ns           64 bytes_per_second=370.942k/s
bench_elephant::jumbo_decrypt/32/4096           10858323 ns     10858086 ns           64 bytes_per_second=371.267k/s
bench_elephant::delirium_encrypt/32/64              8771 ns         8771 ns        79922 bytes_per_second=10.4385M/s
bench_elephant::delirium_decrypt/32/64              8909 ns         8909 ns        78592 bytes_per_second=10.2769M/s
bench_elephant::delirium_encrypt/32/128            13450 ns        13450 ns        52055 bytes_per_second=11.3449M/s
bench_elephant::delirium_decrypt/32/128            13641 ns        13640 ns        51361 bytes_per_second=11.1866M/s
bench_elephant::delirium_encrypt/32/256            21275 ns        21274 ns        32901 bytes_per_second=12.9105M/s
bench_elephant::delirium_decrypt/32/256            21470 ns        21470 ns        32617 bytes_per_second=12.7929M/s
bench_elephant::delirium_encrypt/32/512            36902 ns        36901 ns        18969 bytes_per_second=14.059M/s
bench_elephant::delirium_decrypt/32/512            37090 ns        37090 ns        18870 bytes_per_second=13.9877M/s
bench_elephant::delirium_encrypt/32/1024           68152 ns        68150 ns        10276 bytes_per_second=14.7774M/s
bench_elephant::delirium_decrypt/32/1024           68361 ns        68359 ns        10241 bytes_per_second=14.7322M/s
bench_elephant::delirium_encrypt/32/2048          132156 ns       132153 ns         5298 bytes_per_second=15.0102M/s
bench_elephant::delirium_decrypt/32/2048          132476 ns       132471 ns         5284 bytes_per_second=14.9741M/s
bench_elephant::delirium_encrypt/32/4096          260077 ns       260071 ns         2692 bytes_per_second=15.1373M/s
bench_elephant::delirium_decrypt/32/4096          260673 ns       260668 ns         2686 bytes_per_second=15.1026M/s
```

### On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

```bash
2022-07-29T06:55:46+00:00
Running ./bench/a.out
Run on (4 X 2300 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.08, 0.02, 0.01
--------------------------------------------------------------------------------------------------------
Benchmark                                              Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------------
bench_elephant::spongent_permutation<160, 1>         406 ns          406 ns      1724557 bytes_per_second=46.9871M/s
bench_elephant::spongent_permutation<160, 80>      32410 ns        32410 ns        21594 bytes_per_second=602.634k/s
bench_elephant::spongent_permutation<176, 1>         438 ns          438 ns      1596130 bytes_per_second=47.8561M/s
bench_elephant::spongent_permutation<176, 90>      40568 ns        40566 ns        17252 bytes_per_second=529.611k/s
bench_elephant::keccak_permutation<1>               86.7 ns         86.7 ns      8086390 bytes_per_second=274.973M/s
bench_elephant::keccak_permutation<18>              1468 ns         1468 ns       476544 bytes_per_second=16.2379M/s
bench_elephant::dumbo_encrypt/32/64               482460 ns       482443 ns         1451 bytes_per_second=194.323k/s
bench_elephant::dumbo_decrypt/32/64               488780 ns       488737 ns         1433 bytes_per_second=191.821k/s
bench_elephant::dumbo_encrypt/32/128              675070 ns       675062 ns         1036 bytes_per_second=231.46k/s
bench_elephant::dumbo_decrypt/32/128              683127 ns       683118 ns         1024 bytes_per_second=228.731k/s
bench_elephant::dumbo_encrypt/32/256             1060730 ns      1060660 ns          660 bytes_per_second=265.165k/s
bench_elephant::dumbo_decrypt/32/256             1071774 ns      1071708 ns          653 bytes_per_second=262.432k/s
bench_elephant::dumbo_encrypt/32/512             1895863 ns      1895742 ns          369 bytes_per_second=280.233k/s
bench_elephant::dumbo_decrypt/32/512             1913229 ns      1913143 ns          366 bytes_per_second=277.684k/s
bench_elephant::dumbo_encrypt/32/1024            3566629 ns      3566373 ns          196 bytes_per_second=289.159k/s
bench_elephant::dumbo_decrypt/32/1024            3596799 ns      3596427 ns          195 bytes_per_second=286.743k/s
bench_elephant::dumbo_encrypt/32/2048            6844614 ns      6843861 ns          102 bytes_per_second=296.799k/s
bench_elephant::dumbo_decrypt/32/2048            6897452 ns      6897017 ns          101 bytes_per_second=294.511k/s
bench_elephant::dumbo_encrypt/32/4096           13405258 ns     13404917 ns           52 bytes_per_second=300.729k/s
bench_elephant::dumbo_decrypt/32/4096           13494411 ns     13494493 ns           52 bytes_per_second=298.733k/s
bench_elephant::jumbo_encrypt/32/64               520698 ns       520676 ns         1345 bytes_per_second=180.054k/s
bench_elephant::jumbo_decrypt/32/64               519027 ns       519000 ns         1349 bytes_per_second=180.636k/s
bench_elephant::jumbo_encrypt/32/128              760177 ns       760161 ns          921 bytes_per_second=205.549k/s
bench_elephant::jumbo_decrypt/32/128              757816 ns       757821 ns          924 bytes_per_second=206.183k/s
bench_elephant::jumbo_encrypt/32/256             1239241 ns      1239249 ns          564 bytes_per_second=226.952k/s
bench_elephant::jumbo_decrypt/32/256             1236019 ns      1235975 ns          567 bytes_per_second=227.553k/s
bench_elephant::jumbo_encrypt/32/512             2198475 ns      2198465 ns          319 bytes_per_second=241.646k/s
bench_elephant::jumbo_decrypt/32/512             2192996 ns      2192930 ns          319 bytes_per_second=242.256k/s
bench_elephant::jumbo_encrypt/32/1024            4036555 ns      4036586 ns          173 bytes_per_second=255.476k/s
bench_elephant::jumbo_decrypt/32/1024            4025258 ns      4025103 ns          174 bytes_per_second=256.205k/s
bench_elephant::jumbo_encrypt/32/2048            7791302 ns      7790816 ns           90 bytes_per_second=260.724k/s
bench_elephant::jumbo_decrypt/32/2048            7773041 ns      7772543 ns           90 bytes_per_second=261.337k/s
bench_elephant::jumbo_encrypt/32/4096           15226107 ns     15224531 ns           46 bytes_per_second=264.786k/s
bench_elephant::jumbo_decrypt/32/4096           15185116 ns     15184138 ns           46 bytes_per_second=265.491k/s
bench_elephant::delirium_encrypt/32/64             18888 ns        18887 ns        37064 bytes_per_second=4.84736M/s
bench_elephant::delirium_decrypt/32/64             18976 ns        18975 ns        36959 bytes_per_second=4.8249M/s
bench_elephant::delirium_encrypt/32/128            28135 ns        28133 ns        24871 bytes_per_second=5.42383M/s
bench_elephant::delirium_decrypt/32/128            28174 ns        28172 ns        24862 bytes_per_second=5.41629M/s
bench_elephant::delirium_encrypt/32/256            43560 ns        43556 ns        16072 bytes_per_second=6.3058M/s
bench_elephant::delirium_decrypt/32/256            43471 ns        43469 ns        16100 bytes_per_second=6.31853M/s
bench_elephant::delirium_encrypt/32/512            74289 ns        74284 ns         9426 bytes_per_second=6.98401M/s
bench_elephant::delirium_decrypt/32/512            74207 ns        74203 ns         9432 bytes_per_second=6.99158M/s
bench_elephant::delirium_encrypt/32/1024          135961 ns       135958 ns         5156 bytes_per_second=7.40732M/s
bench_elephant::delirium_decrypt/32/1024          135209 ns       135208 ns         5173 bytes_per_second=7.4484M/s
bench_elephant::delirium_encrypt/32/2048          261226 ns       261223 ns         2679 bytes_per_second=7.59367M/s
bench_elephant::delirium_decrypt/32/2048          260364 ns       260362 ns         2688 bytes_per_second=7.61879M/s
bench_elephant::delirium_encrypt/32/4096          512829 ns       512786 ns         1365 bytes_per_second=7.67722M/s
bench_elephant::delirium_decrypt/32/4096          512671 ns       512642 ns         1366 bytes_per_second=7.67937M/s
```
