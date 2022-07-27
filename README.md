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
- Delirium ( **not yet implemented** )

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

> Note, if authentication verification fails ( during decryption phase ), decrypted plain text is not released ( i.e. zeroed ).

For executing test cases, issue

```bash
make
```

## Benchmarking

Benchmarking following listed routines, can easily be done by issuing

```bash
make benchmark
```

> For disabling CPU scaling, when benchmarking, see [this](https://github.com/google/benchmark/blob/60b16f1/docs/user_guide.md#disabling-cpu-frequency-scaling)

- Spongent-π[160], Spongent-π[176] permutation
- Dumbo encrypt/ decrypt
- Jumbo encrypt/ decrypt

> Note, benchmarking of encrypt/ decrypt routines are done with constant sized ( 32 -bytes ) associated data & varied length ( power of 2 values from 64 to 4096 -bytes ) plain/ cipher text

> Also note, neither Dumbo nor Jumbo is software platform friendly, but Keccak-f[200] based Delirium is; see section 1 of Elephant [specification](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf)

> Elephant is an encrypt-then-mac style construction, which makes it possible to parallelly {en, de}crypt different plain/ cipher text blocks, though parallelization is not yet implemented here.

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-07-27T10:20:17+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.59, 1.55, 1.50
--------------------------------------------------------------------------------------------------------
Benchmark                                              Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------------
bench_elephant::spongent_permutation<160, 1>         313 ns          313 ns      2249907 bytes_per_second=61.0048M/s
bench_elephant::spongent_permutation<160, 80>      25146 ns        25117 ns        27457 bytes_per_second=777.608k/s
bench_elephant::spongent_permutation<176, 1>         337 ns          337 ns      2034523 bytes_per_second=62.2527M/s
bench_elephant::spongent_permutation<176, 90>      30252 ns        30235 ns        22942 bytes_per_second=710.587k/s
bench_elephant::dumbo_encrypt/32/64               375530 ns       375294 ns         1873 bytes_per_second=249.804k/s
bench_elephant::dumbo_decrypt/32/64               372643 ns       372473 ns         1868 bytes_per_second=251.696k/s
bench_elephant::dumbo_encrypt/32/128              521702 ns       521363 ns         1289 bytes_per_second=299.695k/s
bench_elephant::dumbo_decrypt/32/128              521043 ns       520748 ns         1309 bytes_per_second=300.049k/s
bench_elephant::dumbo_encrypt/32/256              821919 ns       821180 ns          835 bytes_per_second=342.495k/s
bench_elephant::dumbo_decrypt/32/256              822393 ns       821656 ns          838 bytes_per_second=342.296k/s
bench_elephant::dumbo_encrypt/32/512             1462046 ns      1461041 ns          458 bytes_per_second=363.61k/s
bench_elephant::dumbo_decrypt/32/512             1549466 ns      1530883 ns          472 bytes_per_second=347.022k/s
bench_elephant::dumbo_encrypt/32/1024            2751141 ns      2750056 ns          252 bytes_per_second=374.992k/s
bench_elephant::dumbo_decrypt/32/1024            2761128 ns      2759933 ns          252 bytes_per_second=373.65k/s
bench_elephant::dumbo_encrypt/32/2048            5315088 ns      5311764 ns          127 bytes_per_second=382.406k/s
bench_elephant::dumbo_decrypt/32/2048            5324620 ns      5314154 ns          130 bytes_per_second=382.234k/s
bench_elephant::dumbo_encrypt/32/4096           10522337 ns     10492379 ns           66 bytes_per_second=384.207k/s
bench_elephant::dumbo_decrypt/32/4096           10526103 ns     10501303 ns           66 bytes_per_second=383.881k/s
bench_elephant::jumbo_encrypt/32/64               410664 ns       407483 ns         1716 bytes_per_second=230.071k/s
bench_elephant::jumbo_decrypt/32/64               402392 ns       400753 ns         1748 bytes_per_second=233.935k/s
bench_elephant::jumbo_encrypt/32/128              596600 ns       593831 ns         1185 bytes_per_second=263.122k/s
bench_elephant::jumbo_decrypt/32/128              611675 ns       605712 ns         1121 bytes_per_second=257.961k/s
bench_elephant::jumbo_encrypt/32/256              938721 ns       937865 ns          727 bytes_per_second=299.883k/s
bench_elephant::jumbo_decrypt/32/256              939970 ns       939577 ns          735 bytes_per_second=299.337k/s
bench_elephant::jumbo_encrypt/32/512             1759896 ns      1738674 ns          414 bytes_per_second=305.549k/s
bench_elephant::jumbo_decrypt/32/512             1727456 ns      1712650 ns          397 bytes_per_second=310.192k/s
bench_elephant::jumbo_encrypt/32/1024            3079661 ns      3078237 ns          228 bytes_per_second=335.013k/s
bench_elephant::jumbo_decrypt/32/1024            3057424 ns      3056115 ns          227 bytes_per_second=337.438k/s
bench_elephant::jumbo_encrypt/32/2048            5897604 ns      5894730 ns          115 bytes_per_second=344.587k/s
bench_elephant::jumbo_decrypt/32/2048            6138066 ns      6093544 ns          114 bytes_per_second=333.345k/s
bench_elephant::jumbo_encrypt/32/4096           11982112 ns     11884950 ns           60 bytes_per_second=339.189k/s
bench_elephant::jumbo_decrypt/32/4096           11553181 ns     11544950 ns           60 bytes_per_second=349.179k/s
```

### On AWS Graviton2

```bash
2022-07-27T06:22:28+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.08, 0.02, 0.01
--------------------------------------------------------------------------------------------------------
Benchmark                                              Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------------
bench_elephant::spongent_permutation<160, 1>         675 ns          675 ns      1035935 bytes_per_second=28.2452M/s
bench_elephant::spongent_permutation<160, 80>      54063 ns        54063 ns        12947 bytes_per_second=361.268k/s
bench_elephant::spongent_permutation<176, 1>         639 ns          639 ns      1095732 bytes_per_second=32.8422M/s
bench_elephant::spongent_permutation<176, 90>      56917 ns        56916 ns        12298 bytes_per_second=377.478k/s
bench_elephant::dumbo_encrypt/32/64               810703 ns       810665 ns          863 bytes_per_second=115.646k/s
bench_elephant::dumbo_decrypt/32/64               810515 ns       810510 ns          864 bytes_per_second=115.668k/s
bench_elephant::dumbo_encrypt/32/128             1135010 ns      1134963 ns          617 bytes_per_second=137.67k/s
bench_elephant::dumbo_decrypt/32/128             1134782 ns      1134761 ns          617 bytes_per_second=137.694k/s
bench_elephant::dumbo_encrypt/32/256             1783472 ns      1783415 ns          393 bytes_per_second=157.703k/s
bench_elephant::dumbo_decrypt/32/256             1783347 ns      1783287 ns          393 bytes_per_second=157.714k/s
bench_elephant::dumbo_encrypt/32/512             3188544 ns      3188491 ns          220 bytes_per_second=166.615k/s
bench_elephant::dumbo_decrypt/32/512             3188349 ns      3188293 ns          220 bytes_per_second=166.625k/s
bench_elephant::dumbo_encrypt/32/1024            5998642 ns      5998606 ns          117 bytes_per_second=171.915k/s
bench_elephant::dumbo_decrypt/32/1024            5998765 ns      5998597 ns          117 bytes_per_second=171.915k/s
bench_elephant::dumbo_encrypt/32/2048           11510538 ns     11510461 ns           61 bytes_per_second=176.47k/s
bench_elephant::dumbo_decrypt/32/2048           11510892 ns     11510487 ns           61 bytes_per_second=176.47k/s
bench_elephant::dumbo_encrypt/32/4096           22534361 ns     22534215 ns           31 bytes_per_second=178.895k/s
bench_elephant::dumbo_decrypt/32/4096           22534963 ns     22534433 ns           31 bytes_per_second=178.893k/s
bench_elephant::jumbo_encrypt/32/64               746432 ns       746412 ns          938 bytes_per_second=125.601k/s
bench_elephant::jumbo_decrypt/32/64               747156 ns       747152 ns          937 bytes_per_second=125.476k/s
bench_elephant::jumbo_encrypt/32/128             1090972 ns      1090952 ns          642 bytes_per_second=143.224k/s
bench_elephant::jumbo_decrypt/32/128             1091808 ns      1091802 ns          641 bytes_per_second=143.112k/s
bench_elephant::jumbo_encrypt/32/256             1780237 ns      1780155 ns          393 bytes_per_second=157.992k/s
bench_elephant::jumbo_decrypt/32/256             1780978 ns      1780967 ns          393 bytes_per_second=157.92k/s
bench_elephant::jumbo_encrypt/32/512             3158415 ns      3158395 ns          222 bytes_per_second=168.203k/s
bench_elephant::jumbo_decrypt/32/512             3159243 ns      3159223 ns          222 bytes_per_second=168.158k/s
bench_elephant::jumbo_encrypt/32/1024            5800209 ns      5800068 ns          121 bytes_per_second=177.8k/s
bench_elephant::jumbo_decrypt/32/1024            5800989 ns      5800884 ns          121 bytes_per_second=177.775k/s
bench_elephant::jumbo_encrypt/32/2048           11198365 ns     11198180 ns           63 bytes_per_second=181.391k/s
bench_elephant::jumbo_decrypt/32/2048           11199990 ns     11199790 ns           62 bytes_per_second=181.365k/s
bench_elephant::jumbo_encrypt/32/4096           21879261 ns     21879125 ns           32 bytes_per_second=184.251k/s
bench_elephant::jumbo_decrypt/32/4096           21880806 ns     21880268 ns           32 bytes_per_second=184.241k/s
```

### On AWS Graviton3

```bash
2022-07-27T06:23:52+00:00
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
bench_elephant::spongent_permutation<160, 1>         359 ns          359 ns      1950251 bytes_per_second=53.1412M/s
bench_elephant::spongent_permutation<160, 80>      27872 ns        27871 ns        25117 bytes_per_second=700.771k/s
bench_elephant::spongent_permutation<176, 1>         317 ns          317 ns      2211504 bytes_per_second=66.2635M/s
bench_elephant::spongent_permutation<176, 90>      28472 ns        28471 ns        24569 bytes_per_second=754.612k/s
bench_elephant::dumbo_encrypt/32/64               421381 ns       421372 ns         1661 bytes_per_second=222.487k/s
bench_elephant::dumbo_decrypt/32/64               418750 ns       418741 ns         1671 bytes_per_second=223.885k/s
bench_elephant::dumbo_encrypt/32/128              591661 ns       591645 ns         1183 bytes_per_second=264.094k/s
bench_elephant::dumbo_decrypt/32/128              586169 ns       586156 ns         1194 bytes_per_second=266.567k/s
bench_elephant::dumbo_encrypt/32/256              931719 ns       931699 ns          751 bytes_per_second=301.868k/s
bench_elephant::dumbo_decrypt/32/256              920966 ns       920946 ns          760 bytes_per_second=305.392k/s
bench_elephant::dumbo_encrypt/32/512             1668328 ns      1668273 ns          420 bytes_per_second=318.443k/s
bench_elephant::dumbo_decrypt/32/512             1646523 ns      1646480 ns          425 bytes_per_second=322.658k/s
bench_elephant::dumbo_encrypt/32/1024            3141793 ns      3141604 ns          223 bytes_per_second=328.256k/s
bench_elephant::dumbo_decrypt/32/1024            3097316 ns      3097216 ns          226 bytes_per_second=332.96k/s
bench_elephant::dumbo_encrypt/32/2048            6032175 ns      6032045 ns          116 bytes_per_second=336.743k/s
bench_elephant::dumbo_decrypt/32/2048            5942672 ns      5942464 ns          118 bytes_per_second=341.82k/s
bench_elephant::dumbo_encrypt/32/4096           11812083 ns     11811829 ns           59 bytes_per_second=341.289k/s
bench_elephant::dumbo_decrypt/32/4096           11633437 ns     11633090 ns           60 bytes_per_second=346.533k/s
bench_elephant::jumbo_encrypt/32/64               369764 ns       369756 ns         1895 bytes_per_second=253.545k/s
bench_elephant::jumbo_decrypt/32/64               369386 ns       369376 ns         1895 bytes_per_second=253.806k/s
bench_elephant::jumbo_encrypt/32/128              540493 ns       540481 ns         1295 bytes_per_second=289.094k/s
bench_elephant::jumbo_decrypt/32/128              540477 ns       540466 ns         1295 bytes_per_second=289.103k/s
bench_elephant::jumbo_encrypt/32/256              882684 ns       882665 ns          793 bytes_per_second=318.637k/s
bench_elephant::jumbo_decrypt/32/256              883672 ns       883626 ns          793 bytes_per_second=318.291k/s
bench_elephant::jumbo_encrypt/32/512             1567723 ns      1567682 ns          446 bytes_per_second=338.876k/s
bench_elephant::jumbo_decrypt/32/512             1567208 ns      1567174 ns          447 bytes_per_second=338.986k/s
bench_elephant::jumbo_encrypt/32/1024            2878903 ns      2878841 ns          243 bytes_per_second=358.217k/s
bench_elephant::jumbo_decrypt/32/1024            2878564 ns      2878502 ns          243 bytes_per_second=358.259k/s
bench_elephant::jumbo_encrypt/32/2048            5559794 ns      5559675 ns          126 bytes_per_second=365.354k/s
bench_elephant::jumbo_decrypt/32/2048            5558188 ns      5558068 ns          126 bytes_per_second=365.46k/s
bench_elephant::jumbo_encrypt/32/4096           10864093 ns     10863858 ns           64 bytes_per_second=371.07k/s
bench_elephant::jumbo_decrypt/32/4096           10860059 ns     10859824 ns           64 bytes_per_second=371.208k/s
```

### On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

```bash
2022-07-27T06:25:21+00:00
Running ./bench/a.out
Run on (4 X 2300 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.15, 0.03, 0.01
--------------------------------------------------------------------------------------------------------
Benchmark                                              Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------------
bench_elephant::spongent_permutation<160, 1>         410 ns          410 ns      1706987 bytes_per_second=46.557M/s
bench_elephant::spongent_permutation<160, 80>      32854 ns        32852 ns        21284 bytes_per_second=594.517k/s
bench_elephant::spongent_permutation<176, 1>         451 ns          451 ns      1553989 bytes_per_second=46.525M/s
bench_elephant::spongent_permutation<176, 90>      39771 ns        39770 ns        17584 bytes_per_second=540.217k/s
bench_elephant::dumbo_encrypt/32/64               489734 ns       489705 ns         1429 bytes_per_second=191.442k/s
bench_elephant::dumbo_decrypt/32/64               482515 ns       482519 ns         1451 bytes_per_second=194.293k/s
bench_elephant::dumbo_encrypt/32/128              684228 ns       684233 ns         1023 bytes_per_second=228.358k/s
bench_elephant::dumbo_decrypt/32/128              675428 ns       675421 ns         1036 bytes_per_second=231.337k/s
bench_elephant::dumbo_encrypt/32/256             1074236 ns      1074143 ns          652 bytes_per_second=261.837k/s
bench_elephant::dumbo_decrypt/32/256             1061743 ns      1061700 ns          660 bytes_per_second=264.905k/s
bench_elephant::dumbo_encrypt/32/512             1918281 ns      1918188 ns          365 bytes_per_second=276.954k/s
bench_elephant::dumbo_decrypt/32/512             1900568 ns      1900530 ns          369 bytes_per_second=279.527k/s
bench_elephant::dumbo_encrypt/32/1024            3606325 ns      3606089 ns          194 bytes_per_second=285.975k/s
bench_elephant::dumbo_decrypt/32/1024            3573929 ns      3573724 ns          196 bytes_per_second=288.565k/s
bench_elephant::dumbo_encrypt/32/2048            6917926 ns      6917513 ns          101 bytes_per_second=293.639k/s
bench_elephant::dumbo_decrypt/32/2048            6860043 ns      6859572 ns          102 bytes_per_second=296.119k/s
bench_elephant::dumbo_encrypt/32/4096           13529290 ns     13529030 ns           52 bytes_per_second=297.97k/s
bench_elephant::dumbo_decrypt/32/4096           13421516 ns     13420351 ns           52 bytes_per_second=300.383k/s
bench_elephant::jumbo_encrypt/32/64               522149 ns       522124 ns         1339 bytes_per_second=179.555k/s
bench_elephant::jumbo_decrypt/32/64               522740 ns       522713 ns         1340 bytes_per_second=179.353k/s
bench_elephant::jumbo_encrypt/32/128              764027 ns       763980 ns          917 bytes_per_second=204.521k/s
bench_elephant::jumbo_decrypt/32/128              765668 ns       765638 ns          915 bytes_per_second=204.078k/s
bench_elephant::jumbo_encrypt/32/256             1247589 ns      1247489 ns          561 bytes_per_second=225.453k/s
bench_elephant::jumbo_decrypt/32/256             1250891 ns      1250826 ns          560 bytes_per_second=224.852k/s
bench_elephant::jumbo_encrypt/32/512             2215333 ns      2215152 ns          316 bytes_per_second=239.825k/s
bench_elephant::jumbo_decrypt/32/512             2221815 ns      2221708 ns          314 bytes_per_second=239.118k/s
bench_elephant::jumbo_encrypt/32/1024            4065996 ns      4065554 ns          172 bytes_per_second=253.655k/s
bench_elephant::jumbo_decrypt/32/1024            4084765 ns      4084644 ns          171 bytes_per_second=252.47k/s
bench_elephant::jumbo_encrypt/32/2048            7854125 ns      7854056 ns           89 bytes_per_second=258.624k/s
bench_elephant::jumbo_decrypt/32/2048            7887482 ns      7887411 ns           89 bytes_per_second=257.531k/s
bench_elephant::jumbo_encrypt/32/4096           15347465 ns     15347333 ns           46 bytes_per_second=262.668k/s
bench_elephant::jumbo_decrypt/32/4096           15420630 ns     15420471 ns           45 bytes_per_second=261.422k/s
```
