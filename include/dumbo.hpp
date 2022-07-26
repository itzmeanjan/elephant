#pragma once
#include "aead.hpp"

// Dumbo Authenticated Encryption with Associated Data
namespace dumbo {

// No. of rounds Spongent-π[160] permutation is applied on state
constexpr size_t ROUNDS = 80;

// Given 16 -bytes secret key, 12 -bytes public message nonce, N -bytes
// associated data & M -bytes plain text, this routine computes M -bytes
// encrypted text & 8 -bytes authentication tag, using Dumbo AEAD scheme.
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
  uint8_t ekey[20]{};
  uint8_t hmask[20]{};
  uint8_t fmask[20]{};

  // begin encryption

  std::memset(ekey, 0, sizeof(ekey));
  std::memcpy(ekey, key, 16);

  spongent::permute<160, ROUNDS>(ekey);

  uint8_t enonce[20]{};

  size_t off = 0;
  while (off < ctlen) {
    const size_t elen = std::min(20ul, ctlen - off);

    std::memcpy(enonce, nonce, 12);
    std::memset(enonce + 12, 0, sizeof(enonce) - 12);

    elephant::next_mask<160, 1>(ekey, hmask, fmask);
    std::memcpy(ekey, hmask, sizeof(hmask));

    for (size_t i = 0; i < 20; i++) {
      enonce[i] ^= fmask[i];
    }

    spongent::permute<160, ROUNDS>(enonce);

    for (size_t i = 0; i < 20; i++) {
      enonce[i] ^= fmask[i];
    }

    for (size_t i = 0; i < elen; i++) {
      enc[off + i] = txt[off + i] ^ enonce[i];
    }

    off += elen;
  }

  // end encryption

  // begin authentication of associated data

  constexpr size_t br[]{ 0, 1 };

  uint8_t tag_[20]{};
  uint8_t msg_blk[20]{};

  const size_t padded_data_len = 12 + dlen + 1;
  const size_t full_blk_cnt0 = padded_data_len / 20;
  const size_t rm_bytes0 = padded_data_len % 20;
  const size_t tot_blk_cnt0 = full_blk_cnt0 + br[rm_bytes0 > 0];

  elephant::get_ith_data_block<160>(data, dlen, nonce, 0, tag_);

  std::memset(ekey, 0, sizeof(ekey));
  std::memcpy(ekey, key, 16);

  spongent::permute<160, ROUNDS>(ekey);

  for (size_t i = 1; i < tot_blk_cnt0; i++) {
    elephant::get_ith_data_block<160>(data, dlen, nonce, i, msg_blk);

    elephant::next_mask<160, 0>(ekey, hmask, fmask);
    std::memcpy(ekey, hmask, sizeof(hmask));

    for (size_t j = 0; j < 20; j++) {
      msg_blk[j] ^= fmask[j];
    }

    spongent::permute<160, ROUNDS>(msg_blk);

    for (size_t j = 0; j < 20; j++) {
      msg_blk[j] ^= fmask[j];
    }

    for (size_t j = 0; j < 20; j++) {
      tag_[j] ^= msg_blk[j];
    }
  }

  // end authentication of associated data

  // begin authentication of cipher text

  const size_t padded_cipher_len = ctlen + 1;
  const size_t full_blk_cnt1 = padded_cipher_len / 20;
  const size_t rm_bytes1 = padded_cipher_len % 20;
  const size_t tot_blk_cnt1 = full_blk_cnt1 + br[rm_bytes1 > 0];

  std::memset(ekey, 0, sizeof(ekey));
  std::memcpy(ekey, key, 16);

  spongent::permute<160, ROUNDS>(ekey);

  for (size_t i = 0; i < tot_blk_cnt1; i++) {
    elephant::get_ith_cipher_block<160>(enc, ctlen, i, msg_blk);

    elephant::next_mask<160, 2>(ekey, hmask, fmask);
    std::memcpy(ekey, hmask, sizeof(hmask));

    for (size_t j = 0; j < 20; j++) {
      msg_blk[j] ^= fmask[j];
    }

    spongent::permute<160, ROUNDS>(msg_blk);

    for (size_t j = 0; j < 20; j++) {
      msg_blk[j] ^= fmask[j];
    }

    for (size_t j = 0; j < 20; j++) {
      tag_[j] ^= msg_blk[j];
    }
  }

  // end authentication of cipher text

  // begin step 12 of algorithm 1, 2

  std::memset(ekey, 0, sizeof(ekey));
  std::memcpy(ekey, key, 16);

  spongent::permute<160, ROUNDS>(ekey);

  for (size_t i = 0; i < 20; i++) {
    tag_[i] ^= ekey[i];
  }

  spongent::permute<160, ROUNDS>(tag_);

  for (size_t i = 0; i < 20; i++) {
    tag_[i] ^= ekey[i];
  }

  // end step 12 of algorithm 1, 2

  std::memcpy(tag, tag_, 8);
}

}
