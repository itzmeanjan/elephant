#pragma once
#include <cstddef>
#include <cstdint>

// Spongent-π[W] permutation | W ∈ {160, 176}
namespace spongent {

// Spongent permutation's 8-bit substitution Box, as defined in section 2.3.1 of
// Elephant specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
//
// Note, these precomputed constants are copied from
// https://github.com/TimBeyne/Elephant/blob/b1a6883/crypto_aead/elephant160v2/ref/spongent.c#L30-L48
constexpr uint8_t SBox[]{
  0xee, 0xed, 0xeb, 0xe0, 0xe2, 0xe1, 0xe4, 0xef, 0xe7, 0xea, 0xe8, 0xe5, 0xe9,
  0xec, 0xe3, 0xe6, 0xde, 0xdd, 0xdb, 0xd0, 0xd2, 0xd1, 0xd4, 0xdf, 0xd7, 0xda,
  0xd8, 0xd5, 0xd9, 0xdc, 0xd3, 0xd6, 0xbe, 0xbd, 0xbb, 0xb0, 0xb2, 0xb1, 0xb4,
  0xbf, 0xb7, 0xba, 0xb8, 0xb5, 0xb9, 0xbc, 0xb3, 0xb6, 0x0e, 0x0d, 0x0b, 0x00,
  0x02, 0x01, 0x04, 0x0f, 0x07, 0x0a, 0x08, 0x05, 0x09, 0x0c, 0x03, 0x06, 0x2e,
  0x2d, 0x2b, 0x20, 0x22, 0x21, 0x24, 0x2f, 0x27, 0x2a, 0x28, 0x25, 0x29, 0x2c,
  0x23, 0x26, 0x1e, 0x1d, 0x1b, 0x10, 0x12, 0x11, 0x14, 0x1f, 0x17, 0x1a, 0x18,
  0x15, 0x19, 0x1c, 0x13, 0x16, 0x4e, 0x4d, 0x4b, 0x40, 0x42, 0x41, 0x44, 0x4f,
  0x47, 0x4a, 0x48, 0x45, 0x49, 0x4c, 0x43, 0x46, 0xfe, 0xfd, 0xfb, 0xf0, 0xf2,
  0xf1, 0xf4, 0xff, 0xf7, 0xfa, 0xf8, 0xf5, 0xf9, 0xfc, 0xf3, 0xf6, 0x7e, 0x7d,
  0x7b, 0x70, 0x72, 0x71, 0x74, 0x7f, 0x77, 0x7a, 0x78, 0x75, 0x79, 0x7c, 0x73,
  0x76, 0xae, 0xad, 0xab, 0xa0, 0xa2, 0xa1, 0xa4, 0xaf, 0xa7, 0xaa, 0xa8, 0xa5,
  0xa9, 0xac, 0xa3, 0xa6, 0x8e, 0x8d, 0x8b, 0x80, 0x82, 0x81, 0x84, 0x8f, 0x87,
  0x8a, 0x88, 0x85, 0x89, 0x8c, 0x83, 0x86, 0x5e, 0x5d, 0x5b, 0x50, 0x52, 0x51,
  0x54, 0x5f, 0x57, 0x5a, 0x58, 0x55, 0x59, 0x5c, 0x53, 0x56, 0x9e, 0x9d, 0x9b,
  0x90, 0x92, 0x91, 0x94, 0x9f, 0x97, 0x9a, 0x98, 0x95, 0x99, 0x9c, 0x93, 0x96,
  0xce, 0xcd, 0xcb, 0xc0, 0xc2, 0xc1, 0xc4, 0xcf, 0xc7, 0xca, 0xc8, 0xc5, 0xc9,
  0xcc, 0xc3, 0xc6, 0x3e, 0x3d, 0x3b, 0x30, 0x32, 0x31, 0x34, 0x3f, 0x37, 0x3a,
  0x38, 0x35, 0x39, 0x3c, 0x33, 0x36, 0x6e, 0x6d, 0x6b, 0x60, 0x62, 0x61, 0x64,
  0x6f, 0x67, 0x6a, 0x68, 0x65, 0x69, 0x6c, 0x63, 0x66
};

// Precomputed 7 -bit lCounter constants, computed using LFSR defined in
// section 2.3.1 of Elephant specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
constexpr uint8_t LCounter160[]{
  117, 106, 84,  41,  83,  39,  79,  31, 62,  125, 122, 116, 104, 80,  33,  67,
  7,   14,  28,  56,  113, 98,  68,  9,  18,  36,  73,  19,  38,  77,  27,  54,
  109, 90,  53,  107, 86,  45,  91,  55, 111, 94,  61,  123, 118, 108, 88,  49,
  99,  70,  13,  26,  52,  105, 82,  37, 75,  23,  46,  93,  59,  119, 110, 92,
  57,  115, 102, 76,  25,  50,  101, 74, 21,  42,  85,  43,  87,  47,  95,  63
};

// Precomputed 7 -bit bit reversed lCounter constants, computed using LFSR
// defined in section 2.3.1 of Elephant specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
//
// Note, ∀ i ∈ [0, 80) RevLCounter160[i] = bit_reverse(LCounter160[i])
constexpr uint8_t RevLCounter160[]{
  174, 86,  42,  148, 202, 228, 242, 248, 124, 190, 94,  46,  22,  10,
  132, 194, 224, 112, 56,  28,  142, 70,  34,  144, 72,  36,  146, 200,
  100, 178, 216, 108, 182, 90,  172, 214, 106, 180, 218, 236, 246, 122,
  188, 222, 110, 54,  26,  140, 198, 98,  176, 88,  44,  150, 74,  164,
  210, 232, 116, 186, 220, 238, 118, 58,  156, 206, 102, 50,  152, 76,
  166, 82,  168, 84,  170, 212, 234, 244, 250, 252
};

// Precomputed 7 -bit lCounter constants, computed using LFSR defined in
// section 2.4.1 of Elephant specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
constexpr uint8_t LCounter176[]{
  69,  11,  22, 44,  89,  51,  103, 78,  29,  58,  117, 106, 84,  41, 83,
  39,  79,  31, 62,  125, 122, 116, 104, 80,  33,  67,  7,   14,  28, 56,
  113, 98,  68, 9,   18,  36,  73,  19,  38,  77,  27,  54,  109, 90, 53,
  107, 86,  45, 91,  55,  111, 94,  61,  123, 118, 108, 88,  49,  99, 70,
  13,  26,  52, 105, 82,  37,  75,  23,  46,  93,  59,  119, 110, 92, 57,
  115, 102, 76, 25,  50,  101, 74,  21,  42,  85,  43,  87,  47,  95, 63
};

// Precomputed 7 -bit bit reversed lCounter constants, computed using LFSR
// defined in section 2.4.1 of Elephant specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
//
// Note, ∀ i ∈ [0, 90) RevLCounter176[i] = bit_reverse(LCounter176[i])
constexpr uint8_t RevLCounter176[]{
  162, 208, 104, 52,  154, 204, 230, 114, 184, 92,  174, 86,  42,  148, 202,
  228, 242, 248, 124, 190, 94,  46,  22,  10,  132, 194, 224, 112, 56,  28,
  142, 70,  34,  144, 72,  36,  146, 200, 100, 178, 216, 108, 182, 90,  172,
  214, 106, 180, 218, 236, 246, 122, 188, 222, 110, 54,  26,  140, 198, 98,
  176, 88,  44,  150, 74,  164, 210, 232, 116, 186, 220, 238, 118, 58,  156,
  206, 102, 50,  152, 76,  166, 82,  168, 84,  170, 212, 234, 244, 250, 252
};

// XORs precomputed round constant into Spongent-π-W permutation state
//
// Ensure template parameter `slen` = W ∈ {160, 176}.
//
// Also note, when `slen` = 160, round identifier 0 <= `r_idx` < 80
//            when `slen` = 176, 0 <= `r_idx` < 90
//
// See line 1 of algorithms defined in section 2.{3, 4}.1 of Elephant
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
template<const size_t slen, const size_t r_idx>
inline static void
apply_rc(uint8_t* const state)
{
  constexpr size_t sbytes = slen >> 3;

  if constexpr (slen == 160) {
    static_assert(r_idx < 80);

    state[0] ^= LCounter160[r_idx];
    state[sbytes - 1] ^= RevLCounter160[r_idx];
  } else if constexpr (slen == 176) {
    static_assert(r_idx < 90);

    state[0] ^= LCounter176[r_idx];
    state[sbytes - 1] ^= RevLCounter176[r_idx];
  }
}

// Applies 8 -bit substitution box ( 20/ 22 times ) on 160/ 176 -bit
// Spongent-π-W permutation state
//
// Ensure template parameter `slen` = W ∈ {160, 176}.
//
// See line 2 of algorithms defined in section 2.{3, 4}.1 of Elephant
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
template<const size_t slen>
inline static void
apply_sbox(uint8_t* const state)
{
  constexpr size_t nsbox = slen >> 3;

  for (size_t i = 0; i < nsbox; i++) {
    state[i] = SBox[state[i]];
  }
}

}
