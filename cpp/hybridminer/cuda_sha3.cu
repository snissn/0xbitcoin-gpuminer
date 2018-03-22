// default magic numbers
#define INTENSITY 23
#define CUDA_DEVICE 0
// default magic numbers

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <curand.h>
#include <assert.h>
#include <curand_kernel.h>

#if defined(_MSC_VER)
#  include <process.h>
#else
#  include <sys/types.h>
#  include <unistd.h>
#endif

#include "cudasolver.h"

/*
Author: Mikers
date march 4, 2018 for 0xbitcoin dev

based off of https://github.com/Dunhili/SHA3-gpu-brute-force-cracker/blob/master/sha3.cu

 * Author: Brian Bowden
 * Date: 5/12/14
 *
 * This is the parallel version of SHA-3.
 */

#ifdef __INTELLISENSE__
 /* reduce vstudio warnings (__byteperm, blockIdx...) */
#include <device_functions.h>
#include <device_launch_parameters.h>
#define __launch_bounds__(max_tpb, min_blocks)
#endif

#define TPB52 1024
#define TPB50 384
#define NPT 2
#define NBN 2

int32_t intensity;
int32_t cuda_device;
int32_t clock_speed;
int32_t compute_version;
int32_t h_done[1] = { 0 };
clock_t start;

uint64_t cnt;
uint64_t printable_hashrate_cnt;
uint64_t print_counter;

bool gpu_initialized;
bool new_input;

uint8_t * h_message;
uint8_t init_message[84];

int32_t* d_done;
uint8_t* d_solution;

uint8_t* d_challenge;
uint8_t* d_hash_prefix;
__constant__ uint8_t d_init_message[85];

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

__device__ __constant__ const uint64_t RC[24] = {
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
  0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
  0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
  0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
  0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
  0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

__device__ __forceinline__
uint64_t bswap_64( uint64_t x )
{
	uint64_t result;
	//result = __byte_perm((uint32_t) x, 0, 0x0123);
	//return (result << 32) + __byte_perm(_HIDWORD(x), 0, 0x0123);
	asm( "{ .reg .b32 x, y;"
		   "mov.b64 {x,y}, %1;"
		   "prmt.b32 x, x, 0, 0x0123;"
		   "prmt.b32 y, y, 0, 0x0123;"
		   "mov.b64 %0, {y,x};"
	     "}" : "=l"(result): "l"(x));
	return result;
}

__device__ __forceinline__
uint64_t xor5( uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e )
{
  uint64_t output;
  asm( "xor.b64 %0, %1, %2;" : "=l"(output) : "l"(d) ,"l"(e) );
  asm( "xor.b64 %0, %0, %1;" : "+l"(output) : "l"(c) );
  asm( "xor.b64 %0, %0, %1;" : "+l"(output) : "l"(b) );
  asm( "xor.b64 %0, %0, %1;" : "+l"(output) : "l"(a) );
  return output;
}

__device__ __forceinline__
uint64_t xor3( uint64_t a, uint64_t b, uint64_t c )
{
  uint64_t output;
  asm( "xor.b64 %0, %1, %2;" : "=l"(output) : "l"(b) ,"l"(c) );
  asm( "xor.b64 %0, %0, %1;" : "+l"(output) : "l"(a) );
  return output;
}

__device__
bool keccak( uint64_t *message, uint64_t target )
{
  uint64_t state[25], C[5];

  int32_t x;

#if __CUDA_ARCH__ >= 600
  uint64_t D[5];
#else
  uint64_t D;
#endif

  // Theta
  // for i = 0 to 5
  //    C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
  C[0] = xor5( message[0], message[5], message[10], (1ull << 32), 0 );
  C[1] = xor3( message[1], message[6], 0x8000000000000000ull );
  C[2] = message[2] ^ message[7];
  C[3] = message[3] ^ message[8];
  C[4] = message[4] ^ message[9];

  // for i = 0 to 5
  //     temp = C[(i + 4) % 5] ^ ROTL64(C[(i + 1) % 5], 1);
  //     for j = 0 to 25, j += 5
  //          state[j + i] ^= temp;
  state[15] = state[20] = ROTL64(C[1], 1) ^ C[4];
  state[ 0] = message[ 0] ^ state[20];
  state[ 5] = message[ 5] ^ state[20];
  state[10] = xor3( message[10],  state[20], (1ull << 32) );

  state[11] = state[21] = ROTL64(C[2], 1) ^ C[0];
  state[ 1] = message[ 1] ^ state[21];
  state[ 6] = message[ 6] ^ state[21];
  state[16] = 0x8000000000000000ull ^ state[21];

  state[12] = state[17] = state[22] = ROTL64(C[3], 1) ^ C[1];
  state[ 2] = message[ 2] ^ state[22];
  state[ 7] = message[ 7] ^ state[22];

  state[13] = state[18] = state[23] = ROTL64(C[4], 1) ^ C[2];
  state[ 3] = message[ 3] ^ state[23];
  state[ 8] = message[ 8] ^ state[23];

  state[14] = state[19] = state[24] = ROTL64(C[0], 1) ^ C[3];
  state[ 4] = message[ 4] ^ state[24];
  state[ 9] = message[ 9] ^ state[24];

  // Rho Pi
  // for i = 0 to 24
  //     j = piln[i];
  //     C[0] = state[j];
  //     state[j] = ROTL64(temp, r[i]);
  //     temp = C[0];
  C[0] = state[1];
  state[ 1] = ROTL64( state[ 6], 44 );
  state[ 6] = ROTL64( state[ 9], 20 );//D[4]
  state[ 9] = ROTL64( state[22], 61 );
  state[22] = ROTL64( state[14], 39 );
  state[14] = ROTL64( state[20], 18 );
  state[20] = ROTL64( state[ 2], 62 );//D[2]
  state[ 2] = ROTL64( state[12], 43 );
  state[12] = ROTL64( state[13], 25 );
  state[13] = ROTL64( state[19],  8 );
  state[19] = ROTL64( state[23], 56 );
  state[23] = ROTL64( state[15], 41 );
  state[15] = ROTL64( state[ 4], 27 );//D[4]
  state[ 4] = ROTL64( state[24], 14 );
  state[24] = ROTL64( state[21],  2 );
  state[21] = ROTL64( state[ 8], 55 );//S[8]
  state[ 8] = ROTL64( state[16], 45 );
  state[16] = ROTL64( state[ 5], 36 );
  state[ 5] = ROTL64( state[ 3], 28 );
  state[ 3] = ROTL64( state[18], 21 );
  state[18] = ROTL64( state[17], 15 );
  state[17] = ROTL64( state[11], 10 );
  state[11] = ROTL64( state[ 7],  6 );//D[2]
  state[ 7] = ROTL64( state[10],  3 );
  state[10] = ROTL64( C[0], 1 );

  //  Chi
  // for j = 0 to 25, j += 5
  //     for i = 0 to 5
  //         C[i] = state[j + i];
  //     for i = 0 to 5
  //         state[j + 1] ^= (~C[(i + 1) % 5]) & C[(i + 2) % 5];
  C[0] = state[ 0];
  C[1] = state[ 1];
  state[ 0] ^= ( ~state[ 1] ) & state[2];
  state[ 1] ^= ( ~state[ 2] ) & state[3];
  state[ 2] ^= ( ~state[ 3] ) & state[4];
  state[ 3] ^= ( ~state[ 4] ) & C[0];
  state[ 4] ^= ( ~C[0] ) & C[1];

  C[0] = state[ 5];
  C[1] = state[ 6];
  state[ 5] ^= ( ~state[ 6] ) & state[7];
  state[ 6] ^= ( ~state[ 7] ) & state[8];
  state[ 7] ^= ( ~state[ 8] ) & state[9];
  state[ 8] ^= ( ~state[ 9] ) & C[0];
  state[ 9] ^= ( ~C[0] ) & C[1];

  C[0] = state[10];
  C[1] = state[11];
  state[10] ^= ( ~state[11] ) & state[12];
  state[11] ^= ( ~state[12] ) & state[13];
  state[12] ^= ( ~state[13] ) & state[14];
  state[13] ^= ( ~state[14] ) & C[0];
  state[14] ^= ( ~C[0] ) & C[1];

  C[0] = state[15];
  C[1] = state[16];
  state[15] ^= ( ~state[16] ) & state[17];
  state[16] ^= ( ~state[17] ) & state[18];
  state[17] ^= ( ~state[18] ) & state[19];
  state[18] ^= ( ~state[19] ) & C[0];
  state[19] ^= ( ~C[0] ) & C[1];

  C[0] = state[20];
  C[1] = state[21];
  state[20] ^= ( ~state[21] ) & state[22];
  state[21] ^= ( ~state[22] ) & state[23];
  state[22] ^= ( ~state[23] ) & state[24];
  state[23] ^= ( ~state[24] ) & C[0];
  state[24] ^= ( ~C[0] ) & C[1];

  //  Iota
  state[0] ^= RC[0];

#if __CUDA_ARCH__ >= 600
#pragma unroll 22
#endif
  for( int32_t i = 1; i < 23; i++ )
  {
    // Theta
    // for i = 0 to 5
    //    C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
    for (x = 0; x < 5; x++) {
      C[x] = xor5( state[x], state[x + 5], state[x + 10], state[x + 15], state[x + 20] );
    }

    // for i = 0 to 5
    //     temp = C[(i + 4) % 5] ^ ROTL64(C[(i + 1) % 5], 1);
    //     for j = 0 to 25, j += 5
    //          state[j + i] ^= temp;
#if __CUDA_ARCH__ >= 600
    D[0] = ROTL64(C[1], 1) ^ C[4];
    D[1] = ROTL64(C[2], 1) ^ C[0];
    D[2] = ROTL64(C[3], 1) ^ C[1];
    D[3] = ROTL64(C[4], 1) ^ C[2];
    D[4] = ROTL64(C[0], 1) ^ C[3];

    for (x = 0; x < 5; x++) {
      state[x]      ^= D[x];
      state[x + 5]  ^= D[x];
      state[x + 10] ^= D[x];
      state[x + 15] ^= D[x];
      state[x + 20] ^= D[x];
    }
#else
    D = ROTL64(C[1], 1) ^ C[4];
    state[ 0] ^= D;
    state[ 5] ^= D;
    state[10] ^= D;
    state[15] ^= D;
    state[20] ^= D;

    D = ROTL64(C[2], 1) ^ C[0];
    state[ 1] ^= D;
    state[ 6] ^= D;
    state[11] ^= D;
    state[16] ^= D;
    state[21] ^= D;

    D = ROTL64(C[3], 1) ^ C[1];
    state[ 2] ^= D;
    state[ 7] ^= D;
    state[12] ^= D;
    state[17] ^= D;
    state[22] ^= D;

    D = ROTL64(C[4], 1) ^ C[2];
    state[ 3] ^= D;
    state[ 8] ^= D;
    state[13] ^= D;
    state[18] ^= D;
    state[23] ^= D;

    D = ROTL64(C[0], 1) ^ C[3];
    state[ 4] ^= D;
    state[ 9] ^= D;
    state[14] ^= D;
    state[19] ^= D;
    state[24] ^= D;
#endif

    // Rho Pi
    // for i = 0 to 24
    //     j = piln[i];
    //     C[0] = state[j];
    //     state[j] = ROTL64(temp, r[i]);
    //     temp = C[0];
    C[0] = state[1];
    state[ 1] = ROTL64( state[ 6], 44 );
    state[ 6] = ROTL64( state[ 9], 20 );
    state[ 9] = ROTL64( state[22], 61 );
    state[22] = ROTL64( state[14], 39 );
    state[14] = ROTL64( state[20], 18 );
    state[20] = ROTL64( state[ 2], 62 );
    state[ 2] = ROTL64( state[12], 43 );
    state[12] = ROTL64( state[13], 25 );
    state[13] = ROTL64( state[19],  8 );
    state[19] = ROTL64( state[23], 56 );
    state[23] = ROTL64( state[15], 41 );
    state[15] = ROTL64( state[ 4], 27 );
    state[ 4] = ROTL64( state[24], 14 );
    state[24] = ROTL64( state[21],  2 );
    state[21] = ROTL64( state[ 8], 55 );
    state[ 8] = ROTL64( state[16], 45 );
    state[16] = ROTL64( state[ 5], 36 );
    state[ 5] = ROTL64( state[ 3], 28 );
    state[ 3] = ROTL64( state[18], 21 );
    state[18] = ROTL64( state[17], 15 );
    state[17] = ROTL64( state[11], 10 );
    state[11] = ROTL64( state[ 7],  6 );
    state[ 7] = ROTL64( state[10],  3 );
    state[10] = ROTL64( C[0], 1 );

    //  Chi
    // for j = 0 to 25, j += 5
    //     for i = 0 to 5
    //         C[i] = state[j + i];
    //     for i = 0 to 5
    //         state[j + 1] ^= (~C[(i + 1) % 5]) & C[(i + 2) % 5];
    C[0] = state[ 0];
    C[1] = state[ 1];
    state[ 0] ^= ( ~state[1] ) & state[2];
    state[ 1] ^= ( ~state[2] ) & state[3];
    state[ 2] ^= ( ~state[3] ) & state[4];
    state[ 3] ^= ( ~state[4] ) & C[0];
    state[ 4] ^= ( ~C[0] ) & C[1];

    C[0] = state[ 5];
    C[1] = state[ 6];
    state[ 5] ^= ( ~state[6] ) & state[7];
    state[ 6] ^= ( ~state[7] ) & state[8];
    state[ 7] ^= ( ~state[8] ) & state[9];
    state[ 8] ^= ( ~state[9] ) & C[0];
    state[ 9] ^= ( ~C[0] ) & C[1];

    C[0] = state[10];
    C[1] = state[11];
    state[10] ^= ( ~state[11] ) & state[12];
    state[11] ^= ( ~state[12] ) & state[13];
    state[12] ^= ( ~state[13] ) & state[14];
    state[13] ^= ( ~state[14] ) & C[0];
    state[14] ^= ( ~C[0] ) & C[1];

    C[0] = state[15];
    C[1] = state[16];
    state[15] ^= ( ~state[16] ) & state[17];
    state[16] ^= ( ~state[17] ) & state[18];
    state[17] ^= ( ~state[18] ) & state[19];
    state[18] ^= ( ~state[19] ) & C[0];
    state[19] ^= ( ~C[0] ) & C[1];

    C[0] = state[20];
    C[1] = state[21];
    state[20] ^= ( ~state[21] ) & state[22];
    state[21] ^= ( ~state[22] ) & state[23];
    state[22] ^= ( ~state[23] ) & state[24];
    state[23] ^= ( ~state[24] ) & C[0];
    state[24] ^= ( ~C[0] ) & C[1];

    //  Iota
    state[0] ^= RC[i];
  }
  for (x = 0; x < 5; x++) {
    C[x] = xor5( state[x], state[x + 5], state[x + 10], state[x + 15], state[x + 20] );
  }

  state[ 0] ^= ROTL64(C[1], 1) ^ C[4];
  state[ 6] ^= ROTL64(C[2], 1) ^ C[0];
  state[12] ^= ROTL64(C[3], 1) ^ C[1];

  state[ 1] = ROTL64( state[ 6], 44 );
  state[ 2] = ROTL64( state[12], 43 );

  state[ 0] ^= ( ~state[1] ) & state[2];

  state[0] ^= RC[23];

  return bswap_64( state[0] ) <= target;
  // memcpy( output, state, 32 );
}

// hash length is 256 bits
#if __CUDA_ARCH__ > 500
__global__ __launch_bounds__( TPB52, 1 )
#else
__global__ __launch_bounds__( TPB50, 2 )
#endif
void gpu_mine( uint8_t* solution, int32_t* done, uint64_t cnt, uint32_t threads, uint64_t target )
{
  uint32_t thread = blockDim.x * blockIdx.x + threadIdx.x;
  uint8_t message[88] = { 0 };

  memcpy(message, d_init_message, 84);

#if __CUDA_ARCH__ > 500
  uint64_t step = gridDim.x * blockDim.x;
  uint64_t maxNonce = cnt + threads;
  for( uint64_t nounce = cnt + thread; nounce < maxNonce; nounce += step )
  {
#else
  uint32_t nounce = cnt + thread;
  if( thread < threads )
  {
#endif
    (uint64_t&)(message[60]) = nounce;

    if( keccak( (uint64_t*)message, target ) )
    {
	  const uint32_t temp = atomicExch( &done[0], thread );
      if( done[0] == thread )
      {
        memcpy( solution, &message[52], 32 );
      }
      return;
    }
  }
}

__host__
void stop_solving()
{
  h_done[0] = 0xff;
}

__host__
int32_t gcd( int32_t a, int32_t b )
{
  return ( a == 0 ) ? b : gcd( b % a, a );
}

__host__
uint64_t getHashCount()
{
  return cnt;
}
__host__
void resetHashCount()
{
  cnt = 0;
  //printable_hashrate_cnt = 0;
}

/**
 * Initializes the global variables by calling the cudaGetDeviceProperties().
 */
__host__
void gpu_init()
{
  cudaDeviceProp device_prop;
  int32_t device_count;
  start = clock();
  
  srand((time(NULL) & 0xFFFF) | (getpid() << 16));

  char config[10];
  FILE * inf;
  inf = fopen( "0xbtc.conf", "r" );
  if( inf )
  {
    fgets( config, 10, inf );
    fclose( inf );
    intensity = atol( strtok( config, " " ) );
    cuda_device = atol( strtok( NULL, " " ) );
  }
  else
  {
    intensity = INTENSITY;
    cuda_device = CUDA_DEVICE;
  }

  cudaGetDeviceCount( &device_count );

  if( cudaGetDeviceProperties( &device_prop, cuda_device ) != cudaSuccess )
  {
    printf( "Problem getting properties for device, exiting...\n" );
    exit( EXIT_FAILURE );
  }

  cudaSetDevice( cuda_device );

  if( !gpu_initialized )
  {
    cudaDeviceReset();
    cudaSetDeviceFlags( cudaDeviceScheduleBlockingSync );

    cudaMalloc( (void**)&d_done, sizeof( int32_t ) );
    cudaMalloc( (void**)&d_solution, 32 ); // solution
    cudaMallocHost( (void**)&h_message, 32 );

    (uint32_t&)(init_message[52]) = 014533075101u;
    (uint32_t&)(init_message[56]) = 014132271150u;
    for(int8_t i_rand = 60; i_rand < 84; i_rand++){
      init_message[i_rand] = (uint8_t)rand() % 256;
    }

    gpu_initialized = true;
  }

  compute_version = device_prop.major * 100 + device_prop.minor * 10;

  // convert from GHz to hertz
  clock_speed = (int32_t)( device_prop.memoryClockRate * 1000 * 1000 );

  //cnt = 0;
  printable_hashrate_cnt = 0;
  print_counter = 0;

  if( new_input ) new_input = false;
}

__host__
void update_mining_inputs()
{
  new_input = true;
}

__host__
bool find_message( uint64_t target, uint8_t * hash_prefix )
{
  h_done[0] = 0;
  if( !gpu_initialized )
  {
    gpu_init();
  }
  new_input = false;

  for(int8_t i = 0; i < 52; i++){
    init_message[i] = hash_prefix[i];
  }
  cudaMemcpyToSymbol( d_init_message, init_message, 84, cuda_device, cudaMemcpyHostToDevice );

  cudaMemcpy( d_done, h_done, sizeof( int32_t ), cudaMemcpyHostToDevice );
  cudaMemset( d_solution, 0xff, 32 );

  uint32_t threads = 1UL << intensity;

  uint32_t tpb;
  dim3 grid;
  if( compute_version > 500 )
  {
    tpb = TPB52;
    grid.x = ( threads + ( NPT*tpb ) - 1 ) / ( NPT*tpb );
  }
  else
  {
    tpb = TPB50;
    grid.x = ( threads + tpb - 1 ) / tpb;
  }
  const dim3 block( tpb );

  gpu_mine <<< grid, block >>> ( d_solution, d_done, cnt, threads, target );
  // cudaError_t cudaerr = cudaDeviceSynchronize();
  // if( cudaerr != cudaSuccess )
  // {
  //  printf( "kernel launch failed with error %d: \x1b[38;5;196m%s.\x1b[0m\n", cudaerr, cudaGetErrorString( cudaerr ) );
  //  exit( EXIT_FAILURE );
  // }

  if( h_done[0] < 0 ) return false;

  cnt += threads;
  printable_hashrate_cnt += threads;

  cudaMemcpy( h_done, d_done, sizeof( int32_t ), cudaMemcpyDeviceToHost );
  cudaMemcpy( h_message, d_solution, 32, cudaMemcpyDeviceToHost );

  clock_t t = clock() - start;

  if( (t / 100) >= print_counter )
  {
    print_counter++;
    // maybe breaking the control codes into macros is a good idea . . .
    printf( "\x1b[s\x1b[3;67f\x1b[38;5;221m%*.2f\x1b[0m\x1b[u"
            "\x1b[s\x1b[3;29f\x1b[38;5;208m%*llu\x1b[0m\x1b[u",
            8, ( (double)printable_hashrate_cnt / ( (double)t / CLOCKS_PER_SEC ) / 1000000 ),
            26, printable_hashrate_cnt );
  }
  return ( h_done[0] > 0 );
}

__host__
void gpu_cleanup()
{
  if( !gpu_initialized ) return;

  cudaThreadSynchronize();

  cudaFree( d_done );
  cudaFree( d_solution );
  cudaFreeHost( h_message );
}
