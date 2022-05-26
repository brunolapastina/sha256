#pragma once
#include <array>


class sha256_alg
{
public:
   constexpr sha256_alg() = default;

   void update(const uint8_t* data, size_t len) noexcept;
   std::array<uint8_t, 32> finish() noexcept;

private:
   std::array<uint32_t, 8> state_{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
   uint64_t len_{ 0 };
   size_t rem_{ 0 };
   std::array<uint8_t, 64> buff_{};

   void compress_block(const uint8_t* data) noexcept;
};