#!/bin/bash

# Script for ease of execution of Known Answer Tests against 
# Elephant ( i.e. Dumbo, Jumbo & Delirium ) implementation

make lib

# ---

mkdir -p tmp
pushd tmp

wget -O elephant.zip https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/elephant.zip
unzip elephant.zip

cp elephant/Implementations/crypto_aead/elephant160v2/ref/LWC_AEAD_KAT_128_96.txt ../dumbo.txt
cp elephant/Implementations/crypto_aead/elephant176v2/ref/LWC_AEAD_KAT_128_96.txt ../jumbo.txt
cp elephant/Implementations/crypto_aead/elephant200v2/ref/LWC_AEAD_KAT_128_96.txt ../delirium.txt

popd

# ---

rm -rf tmp
mv dumbo.txt wrapper/python/
mv jumbo.txt wrapper/python/
mv delirium.txt wrapper/python/

# ---

pushd wrapper/python

python3 -m pytest -v -k dumbo
rm dumbo.txt

python3 -m pytest -v -k jumbo
rm jumbo.txt

python3 -m pytest -v -k delirium
rm delirium.txt

popd

# ---
