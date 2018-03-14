#ifndef _CUDASHA3_H_
#define _CUDASHA3_H_

#include <atomic>
#include <mutex>
#include <string>
#include <vector>


class CUDASha3
{
public:
  CUDASha3() noexcept;
  void gpu_init();
  void runBenchmarks();
  char *read_in_messages();
  int32_t gcd( int32_t a, int32_t b );

private:
  // updated message the gpu_init() function
  int32_t clock_speed;
  int32_t number_multi_processors;
  int32_t number_blocks;
  int32_t number_threads;
  int32_t max_threads_per_mp;

  int32_t num_messages;
  const int32_t digest_size = 256;
  const int32_t digest_size_bytes = digest_size / 8;
  const size_t str_length = 7;	//change for different sizes

  cudaEvent_t start, stop;
};

#endif // !_SOLVER_H_
