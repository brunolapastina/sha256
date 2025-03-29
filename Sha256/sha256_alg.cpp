#include <type_traits>
#include "sha256_alg.hpp"

#ifdef _MSC_VER
   #include <stdlib.h>
   #define bswap_32(x) _byteswap_ulong(x)
   #define bswap_64(x) _byteswap_uint64(x)
#elif defined(__APPLE__)
   // Mac OS X / Darwin features
   #include <libkern/OSByteOrder.h>
   #define bswap_32(x) OSSwapInt32(x)
   #define bswap_64(x) OSSwapInt64(x)
#elif defined(__sun) || defined(sun)
   #include <sys/byteorder.h>
   #define bswap_32(x) BSWAP_32(x)
   #define bswap_64(x) BSWAP_64(x)
#elif defined(__FreeBSD__)
   #include <sys/endian.h>
   #define bswap_32(x) bswap32(x)
   #define bswap_64(x) bswap64(x)
#elif defined(__OpenBSD__)
   #include <sys/types.h>
   #define bswap_32(x) swap32(x)
   #define bswap_64(x) swap64(x)
#elif defined(__NetBSD__)
   #include <sys/types.h>
   #include <machine/bswap.h>
   #if defined(__BSWAP_RENAME) && !defined(__bswap_32)
      #define bswap_32(x) bswap32(x)
      #define bswap_64(x) bswap64(x)
   #endif
#else
   #include <byteswap.h>
#endif


static constexpr uint32_t opt_bswap_32(uint32_t x) noexcept
{
   return std::is_constant_evaluated() ?
      ((x & 0x000000FF) << 24) | ((x & 0x0000FF00) << 8) | ((x & 0x00FF0000) >> 8) | ((x & 0xFF000000) >> 24) :
      bswap_32(x);
}


static constexpr uint64_t opt_bswap_64(uint64_t x) noexcept
{
   return std::is_constant_evaluated() ?
      ((x & 0x00000000000000ff) << 56) | ((x & 0x000000000000ff00) << 40) | ((x & 0x0000000000ff0000) << 24) | ((x & 0x00000000ff000000) << 8) |
      ((x & 0x000000ff00000000) >> 8) | ((x & 0x0000ff0000000000) >> 24) | ((x & 0x00ff000000000000) >> 40) | ((x & 0xff00000000000000) >> 56) :
      bswap_64(x);
}


void sha256_alg::update(const uint8_t* data, size_t len) noexcept
{
   if (rem_ > 0)
   {
      const auto to_copy = std::min(len, (64 - rem_));
      memcpy(&buff_[rem_], data, to_copy);
      rem_ += to_copy;
      data += to_copy;
      len -= to_copy;

      if (rem_ < 64)
      {
         return;
      }

      compress_block(buff_.data());
      len_ += 64;
      rem_ = 0;
   }

   while (len >= 64)
   {
      compress_block(data);
      data += 64;
      len -= 64;
      len_ += 64;
   }

   memcpy(buff_.data(), data, len);
   rem_ = len;
}


sha256_alg::result_t sha256_alg::finish() noexcept
{
   auto i = rem_;

   if (rem_ < 56)
   {  // Padding can be done in one block
      buff_[i] = 0x80;
      ++i;
      memset(buff_.data() + i, 0, 56 - i);
   }
   else
   {  //We'll need another block for padding
      buff_[i] = 0x80;
      ++i;
      memset(buff_.data() + i, 0, 64 - i);
      compress_block(buff_.data());
      memset(buff_.data(), 0, i);
   }

   len_ += rem_;

   // Append total message length in bits at the end
   const auto buff = std::bit_cast<uint64_t*>(buff_.data());
   buff[7] = opt_bswap_64(len_ * 8);
   compress_block(buff_.data());

   state_[0] = opt_bswap_32(state_[0]);
   state_[1] = opt_bswap_32(state_[1]);
   state_[2] = opt_bswap_32(state_[2]);
   state_[3] = opt_bswap_32(state_[3]);
   state_[4] = opt_bswap_32(state_[4]);
   state_[5] = opt_bswap_32(state_[5]);
   state_[6] = opt_bswap_32(state_[6]);
   state_[7] = opt_bswap_32(state_[7]);

   return std::bit_cast<sha256_alg::result_t>(state_);
}


static constexpr std::array<uint32_t, 64> k{
   0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
   0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
   0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
   0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
   0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
   0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
   0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
   0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static constexpr uint32_t ROTRIGHT(const uint32_t a, const uint8_t b) noexcept
{
   return (a >> b) | (a << (32 - b));
}

static constexpr uint32_t CH(const uint32_t x, const uint32_t y, const uint32_t z) noexcept
{
   return (x & y) ^ (~x & z);
}

static constexpr uint32_t MAJ(const uint32_t x, const uint32_t y, const uint32_t z) noexcept
{
   return (x & y) ^ (x & z) ^ (y & z);
}

static constexpr uint32_t EP0(const uint32_t x) noexcept
{
   return ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22);
}

static constexpr uint32_t EP1(const uint32_t x) noexcept
{
   return ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25);
}

static constexpr uint32_t SIG0(const uint32_t x) noexcept
{
   return ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ (x >> 3);
}

static constexpr uint32_t SIG1(const uint32_t x) noexcept
{
   return ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ (x >> 10);
}

static constexpr void Round(
   const uint32_t a, const uint32_t b, const uint32_t c, uint32_t& d,
   const uint32_t e, const uint32_t f, const uint32_t g, uint32_t& h,
   const uint32_t k_val, const uint32_t m_val) noexcept
{
   const uint32_t t1 = h + EP1(e) + CH(e, f, g) + k_val + m_val;
   const uint32_t t2 = EP0(a) + MAJ(a, b, c);
   d += t1;
   h = t1 + t2;
}


constexpr void sha256_alg::compress_block(const uint8_t* data) noexcept
{
   std::array<uint32_t, 64> m;   // This variable does not have to be initialized now. We will initialize as we need it
   uint32_t a = state_[0];
   uint32_t b = state_[1];
   uint32_t c = state_[2];
   uint32_t d = state_[3];
   uint32_t e = state_[4];
   uint32_t f = state_[5];
   uint32_t g = state_[6];
   uint32_t h = state_[7];

   const auto pdata = std::bit_cast<uint32_t*>(data);
   for (size_t i = 0; i < 16; )
   {
      m[i] = opt_bswap_32(pdata[i]);
      Round(a, b, c, d, e, f, g, h, k[i], m[i]);
      ++i;

      m[i] = opt_bswap_32(pdata[i]);
      Round(h, a, b, c, d, e, f, g, k[i], m[i]);
      ++i;

      m[i] = opt_bswap_32(pdata[i]);
      Round(g, h, a, b, c, d, e, f, k[i], m[i]);
      ++i;

      m[i] = opt_bswap_32(pdata[i]);
      Round(f, g, h, a, b, c, d, e, k[i], m[i]);
      ++i;

      m[i] = opt_bswap_32(pdata[i]);
      Round(e, f, g, h, a, b, c, d, k[i], m[i]);
      ++i;

      m[i] = opt_bswap_32(pdata[i]);
      Round(d, e, f, g, h, a, b, c, k[i], m[i]);
      ++i;

      m[i] = opt_bswap_32(pdata[i]);
      Round(c, d, e, f, g, h, a, b, k[i], m[i]);
      ++i;

      m[i] = opt_bswap_32(pdata[i]);
      Round(b, c, d, e, f, g, h, a, k[i], m[i]);
      ++i;
   }


   for (size_t i = 16; i < 64; )
   {
      m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
      Round(a, b, c, d, e, f, g, h, k[i], m[i]);
      ++i;

      m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
      Round(h, a, b, c, d, e, f, g, k[i], m[i]);
      ++i;

      m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
      Round(g, h, a, b, c, d, e, f, k[i], m[i]);
      ++i;

      m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
      Round(f, g, h, a, b, c, d, e, k[i], m[i]);
      ++i;

      m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
      Round(e, f, g, h, a, b, c, d, k[i], m[i]);
      ++i;

      m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
      Round(d, e, f, g, h, a, b, c, k[i], m[i]);
      ++i;

      m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
      Round(c, d, e, f, g, h, a, b, k[i], m[i]);
      ++i;

      m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
      Round(b, c, d, e, f, g, h, a, k[i], m[i]);
      ++i;
   }

   state_[0] += a;
   state_[1] += b;
   state_[2] += c;
   state_[3] += d;
   state_[4] += e;
   state_[5] += f;
   state_[6] += g;
   state_[7] += h;
}