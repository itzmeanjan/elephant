#pragma once
#include "aead.hpp"

// Dumbo Authenticated Encryption with Associated Data
namespace dumbo {

// No. of rounds Spongent-π[160] permutation is applied on state
constexpr size_t ROUNDS = 80;

// Spongent-π[160] permutation state is 160 -bit wide
constexpr size_t SLEN = 160;

// Dumbo AEAD's authentication tag is 64 -bit wide
constexpr size_t TLEN = 64;

// Given 16 -bytes secret key, 12 -bytes public message nonce, N -bytes
// associated data & M -bytes plain text, this routine computes M -bytes
// encrypted text & 8 -bytes authentication tag, using Dumbo AEAD scheme
// | M, N >= 0
//
// Note, associated data is never encrypted, but only authenticated.
// Also avoid reusing same nonce under same key.
//
// See algorithm 1 of Elephant specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
static void
encrypt(const uint8_t* const __restrict key,   // 128 -bit secret key
        const uint8_t* const __restrict nonce, // 96 -bit nonce
        const uint8_t* const __restrict data,  // N -bytes associated data
        const size_t dlen,                     // len(data) = N | >= 0
        const uint8_t* const __restrict txt,   // M -bytes plain text
        uint8_t* const __restrict enc,         // M -bytes encrypted text
        const size_t ctlen,                    // len(txt) = len(enc) = M | >= 0
        uint8_t* const __restrict tag          // 64 -bit authentication tag
)
{
  constexpr size_t a = SLEN;
  constexpr size_t b = ROUNDS;
  constexpr size_t c = TLEN;

  elephant::encrypt<a, b, c>(key, nonce, data, dlen, txt, enc, ctlen, tag);
}

// Given 16 -bytes secret key, 12 -bytes public message nonce, 8 -bytes
// authentication tag, N -bytes associated data & M -bytes encrypted text, this
// routine computes M -bytes plain text & boolean verification flag, using Dumbo
// AEAD scheme | M, N >= 0
//
// Note, M -bytes plain text is released only when authentication passes i.e.
// boolean verification flag holds truth value. Otherwise one should find zero
// values in decrypted plain text.
//
// See algorithm 2 of Elephant specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
static bool
decrypt(const uint8_t* const __restrict key,   // 128 -bit secret key
        const uint8_t* const __restrict nonce, // 96 -bit nonce
        const uint8_t* const __restrict tag,   // 64 -bit authentication tag
        const uint8_t* const __restrict data,  // N -bytes associated data
        const size_t dlen,                     // len(data) = N | >= 0
        const uint8_t* const __restrict enc,   // M -bytes encrypted text
        uint8_t* const __restrict txt,         // M -bytes plain text
        const size_t ctlen                     // len(enc) = len(txt) = M | >= 0
)
{
  constexpr size_t a = SLEN;
  constexpr size_t b = ROUNDS;
  constexpr size_t c = TLEN;

  bool f = false;
  f = elephant::decrypt<a, b, c>(key, nonce, tag, data, dlen, enc, txt, ctlen);
  return f;
}

}
