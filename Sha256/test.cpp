#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <random>
#include <stdexcept>
#include <string_view>
#include <vector>
#include <Windows.h>
#include "sha256_alg.hpp"


struct test_case_t
{
   std::vector<uint8_t> msg;
   std::array<uint8_t, 32> md;
};


static std::string load_file(const std::string_view filename)
{
   std::string content;

   FILE* fp{ nullptr };
   auto ret = fopen_s(&fp, filename.data(), "r");
   if (ret != 0)
   {
      throw std::runtime_error("Error opening file");
   }

   while (!feof(fp))
   {
      std::array<uint8_t, 4096> buff{};

      size_t read = fread(buff.data(), 1, buff.size(), fp);
      if (read > 0)
      {
         content.insert(content.end(), buff.begin(), buff.begin() + read);
      }
   }

   fclose(fp);

   return content;
}


static std::vector<test_case_t> load_test_cases(const std::string_view filename)
{
   auto ascii_to_nibble = [](const char ch) -> uint8_t
   {
      if ((ch >= '0') && (ch <= '9'))        return ch - '0';
      else if ((ch >= 'A') && (ch <= 'F'))   return ch - 'A' + 10;
      else if ((ch >= 'a') && (ch <= 'f'))   return ch - 'a' + 10;
      else throw std::runtime_error("Invalid data");
   };

   const auto content = load_file(filename);

   size_t begin = 0;
   size_t eol = 0;
   std::vector<test_case_t> test_cases;

   size_t expected_len = 0;
   std::vector<uint8_t> last_msg;
   while ((eol = content.find_first_of("\r\n", begin)) != std::string::npos)
   {
      std::string line(content.begin() + begin, content.begin() + eol);
      begin = eol + 1;

      if (line.empty() || line[0] == '#' || line[0] == '[')
      {
         continue;
      }
      else if (line.starts_with("Len = "))
      {
         expected_len = atoi(&line[6]) / 8;
      }
      else if (line.starts_with("Msg = "))
      {
         last_msg.clear();
         last_msg.reserve(expected_len);
         for (size_t i = 6; (i < line.size()) && (last_msg.size() < expected_len); i += 2)
         {
            last_msg.push_back((ascii_to_nibble(line[i]) << 4) | ascii_to_nibble(line[i + 1]));
         }
      }
      else if (line.starts_with("MD = "))
      {
         std::array<uint8_t, 32> md{};
         for (size_t i = 5; i < line.size(); i += 2)
         {
            md[(i - 5) / 2] = (ascii_to_nibble(line[i]) << 4) | ascii_to_nibble(line[i + 1]);
         }

         test_cases.emplace_back(last_msg, md);
      }
   }

   //printf("Loaded %zd test cases from '%s'\n", test_cases.size(), filename.data());

   return test_cases;
}


static bool RunTests(const std::string_view label, const std::vector<test_case_t>& tests, bool byByte)
{
   bool passed = true;

   for (size_t i = 0; i < tests.size(); i++)
   {
      sha256_alg alg_tst;
      if (byByte)
      {
         for (size_t j = 0; j < tests[i].msg.size(); j++)
         {
            alg_tst.update(tests[i].msg.data() + j, 1);
         }
      }
      else
      {
         alg_tst.update(tests[i].msg.data(), tests[i].msg.size());
      }
      const auto md = alg_tst.finish();
      if (md == tests[i].md)
      {
         //printf("[%s #%-2lld] OK\n", label.data(), i+1);
      }
      else
      {
         printf("[%s #%-2lld] NOT OK\n", label.data(), i + 1);
         passed = false;
      }
   }

   return passed;
}


static void print_hash(const std::array<uint8_t, 32>& md)
{
   for (const auto bt : md)
   {
      printf("%02X", bt);
   }
   printf("\n");
}


int main()
{
   bool passed = true; 
   const auto short_msgs = load_test_cases("SHA256ShortMsg.rsp");
   passed = passed && RunTests("Short msgs", short_msgs, false);
   passed = passed && RunTests("Short msgs", short_msgs, true);

   const auto long_msgs = load_test_cases("SHA256ShortMsg.rsp");
   passed = passed && RunTests("Long msgs", long_msgs, false);
   passed = passed && RunTests("Long msgs", long_msgs, true);

   if (!passed)
   {
      printf("!!! Tests FAILED !!!\n");
      return -1;
   }

   printf("Tests PASSED\n");

#ifdef _DEBUG
   constexpr size_t bench_loop_times = 150LL;
#else
   constexpr size_t bench_loop_times = 1000LL;
#endif
   constexpr size_t bench_data_size = 1024LL * 1024LL;
   std::random_device rd;
   std::mt19937 gen(rd());
   std::uniform_int_distribution<> distrib(std::numeric_limits<uint8_t>::min(), std::numeric_limits<uint8_t>::max());
   std::vector<uint8_t> randData;
   randData.reserve(bench_data_size);
   std::generate_n(std::back_inserter(randData), bench_data_size, [&distrib, &gen]() { return static_cast<uint8_t>(distrib(gen)); });

   const auto begin = GetTickCount64();

   sha256_alg alg_tst;
   for (size_t i = 0; i < bench_loop_times; i++)
   {
      alg_tst.update(randData.data(), randData.size());
   }
   const auto md = alg_tst.finish();

   const auto end = GetTickCount64();

   constexpr auto total_size_in_mb = (bench_loop_times * bench_data_size) / (1024LL * 1024LL);
   const auto elapsed = end - begin;
   printf("Processed %lld MB in %lld ms -> %f MB/s\n\n", total_size_in_mb, elapsed, (total_size_in_mb * 1000.0) / elapsed);

   return 0;
}