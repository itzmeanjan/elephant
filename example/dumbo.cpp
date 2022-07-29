#include "dumbo.hpp"
#include "utils.hpp"
#include <cassert>
#include <iostream>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include example/dumbo.cpp
int
main()
{
  // Dumbo Key, Nonce, Tag, Associated Data, Message ( Cipher Text )
  // length in bytes
  constexpr size_t klen = 16;
  constexpr size_t nlen = 12;
  constexpr size_t tlen = 8;
  constexpr size_t dlen = 32;
  constexpr size_t mlen = 32;

  // allocate memory resources
  uint8_t* key = static_cast<uint8_t*>(std::malloc(klen));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(nlen));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(tlen));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dlen));
  uint8_t* txt = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(mlen));

  std::memset(tag, 0, tlen);
  std::memset(enc, 0, mlen);
  std::memset(dec, 0, mlen);

  // generate random key, nonce, associated data & plain text
  random_data(key, klen);
  random_data(nonce, nlen);
  random_data(data, dlen);
  random_data(txt, mlen);

  // Dumbo authenticated encryption/ verified decryption
  dumbo::encrypt(key, nonce, data, dlen, txt, enc, mlen, tag);
  const bool f = dumbo::decrypt(key, nonce, tag, data, dlen, enc, dec, mlen);

  assert(f);

  bool chk = false;
  for (size_t i = 0; i < mlen; i++) {
    chk |= txt[i] ^ dec[i];
  }

  assert(!chk);

  std::cout << "Dumbo AEAD" << std::endl << std::endl;
  std::cout << "Key       : " << to_hex(key, klen) << std::endl;
  std::cout << "Nonce     : " << to_hex(nonce, nlen) << std::endl;
  std::cout << "Data      : " << to_hex(data, dlen) << std::endl;
  std::cout << "Text      : " << to_hex(txt, mlen) << std::endl;
  std::cout << "Encrypted : " << to_hex(enc, mlen) << std::endl;
  std::cout << "Decrypted : " << to_hex(dec, mlen) << std::endl;
  std::cout << "Tag       : " << to_hex(tag, tlen) << std::endl;

  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(data);
  std::free(txt);
  std::free(enc);
  std::free(dec);

  return EXIT_SUCCESS;
}
