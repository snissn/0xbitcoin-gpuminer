// default magic numbers
#define INTENSITY 23
#define CUDA_DEVICE 0
// default magic numbers
#if defined(_MSC_VER)
#  include <process.h>
#else
#  include <sys/types.h>
#  include <unistd.h>
#endif


#include <time.h>
#include <curand.h>
#include <assert.h>
#include <curand_kernel.h>

/*
Author: Mikers
date march 4, 2018 for 0xbitcoin dev

based off of https://github.com/Dunhili/SHA3-gpu-brute-force-cracker/blob/master/sha3.cu

 * Author: Brian Bowden
 * Date: 5/12/14
 *
 * This is the parallel version of SHA-3.
 */

#include "cudasolver.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

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

bool gpu_initialized;

uint8_t * h_message;

int32_t* d_done;
uint8_t* d_solution;

uint8_t* d_challenge_hash;
uint8_t* d_hash_prefix;

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

__device__ const uint64_t RC[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

__device__ const int32_t r[24] = {
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

__device__ const int32_t piln[24] = {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

__device__
int32_t compare_hash( uint8_t *target, uint8_t *hash, int32_t length )
{
  int32_t i = 0;
  for( i = 0; i < length; i++ )
  {
    if( hash[i] != target[i] )break;
  }
  return (uint8_t)( hash[i] ) < (uint8_t)( target[i] );
}

__device__
void keccak( const uint8_t *message, int32_t message_len, uint8_t *output, int32_t output_len )
{
  uint64_t state[25];
  uint8_t temp_message[144];
  const int32_t rsize = 136;
  const int32_t rsize_byte = 17;

  memset( state, 0, sizeof( state ) );

  // last block and padding
  memcpy( temp_message, message, message_len );
  temp_message[message_len++] = 1;
  memset( temp_message + message_len, 0, rsize - message_len );
  temp_message[rsize - 1] |= 0x80;

  for( int32_t i = 0; i < rsize_byte; i++ )
  {
    state[i] ^= ( (uint64_t *)temp_message )[i];
  }

  uint64_t temp, C[5], D[5];
  int32_t j;

  for( int32_t i = 0; i < 24; i++ )
  {
    // Theta
    // for i = 0 to 5
    //    C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
    uint32_t x;
    for (x = 0; x < 5; x++) {
      C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }


    // for i = 0 to 5
    //     temp = C[(i + 4) % 5] ^ ROTL64(C[(i + 1) % 5], 1);
    //     for j = 0 to 25, j += 5
    //          state[j + i] ^= temp;
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


    // Rho Pi
    // for i = 0 to 24
    //     j = piln[i];
    //     C[0] = state[j];
    //     state[j] = ROTL64(temp, r[i]);
    //     temp = C[0];
    temp = state[1];
    j = piln[0];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[0] );
    temp = C[0];

    j = piln[1];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[1] );
    temp = C[0];

    j = piln[2];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[2] );
    temp = C[0];

    j = piln[3];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[3] );
    temp = C[0];

    j = piln[4];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[4] );
    temp = C[0];

    j = piln[5];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[5] );
    temp = C[0];

    j = piln[6];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[6] );
    temp = C[0];

    j = piln[7];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[7] );
    temp = C[0];

    j = piln[8];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[8] );
    temp = C[0];

    j = piln[9];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[9] );
    temp = C[0];

    j = piln[10];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[10] );
    temp = C[0];

    j = piln[11];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[11] );
    temp = C[0];

    j = piln[12];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[12] );
    temp = C[0];

    j = piln[13];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[13] );
    temp = C[0];

    j = piln[14];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[14] );
    temp = C[0];

    j = piln[15];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[15] );
    temp = C[0];

    j = piln[16];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[16] );
    temp = C[0];

    j = piln[17];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[17] );
    temp = C[0];

    j = piln[18];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[18] );
    temp = C[0];

    j = piln[19];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[19] );
    temp = C[0];

    j = piln[20];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[20] );
    temp = C[0];

    j = piln[21];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[21] );
    temp = C[0];

    j = piln[22];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[22] );
    temp = C[0];

    j = piln[23];
    C[0] = state[j];
    state[j] = ROTL64( temp, r[23] );
    temp = C[0];

    //  Chi
    // for j = 0 to 25, j += 5
    //     for i = 0 to 5
    //         C[i] = state[j + i];
    //     for i = 0 to 5
    //         state[j + 1] ^= (~C[(i + 1) % 5]) & C[(i + 2) % 5];
    C[0] = state[0];
    C[1] = state[1];
    C[2] = state[2];
    C[3] = state[3];
    C[4] = state[4];

    state[0] ^= ( ~C[1] ) & C[2];
    state[1] ^= ( ~C[2] ) & C[3];
    state[2] ^= ( ~C[3] ) & C[4];
    state[3] ^= ( ~C[4] ) & C[0];
    state[4] ^= ( ~C[0] ) & C[1];

    C[0] = state[5];
    C[1] = state[6];
    C[2] = state[7];
    C[3] = state[8];
    C[4] = state[9];

    state[5] ^= ( ~C[1] ) & C[2];
    state[6] ^= ( ~C[2] ) & C[3];
    state[7] ^= ( ~C[3] ) & C[4];
    state[8] ^= ( ~C[4] ) & C[0];
    state[9] ^= ( ~C[0] ) & C[1];

    C[0] = state[10];
    C[1] = state[11];
    C[2] = state[12];
    C[3] = state[13];
    C[4] = state[14];

    state[10] ^= ( ~C[1] ) & C[2];
    state[11] ^= ( ~C[2] ) & C[3];
    state[12] ^= ( ~C[3] ) & C[4];
    state[13] ^= ( ~C[4] ) & C[0];
    state[14] ^= ( ~C[0] ) & C[1];

    C[0] = state[15];
    C[1] = state[16];
    C[2] = state[17];
    C[3] = state[18];
    C[4] = state[19];

    state[15] ^= ( ~C[1] ) & C[2];
    state[16] ^= ( ~C[2] ) & C[3];
    state[17] ^= ( ~C[3] ) & C[4];
    state[18] ^= ( ~C[4] ) & C[0];
    state[19] ^= ( ~C[0] ) & C[1];

    C[0] = state[20];
    C[1] = state[21];
    C[2] = state[22];
    C[3] = state[23];
    C[4] = state[24];

    state[20] ^= ( ~C[1] ) & C[2];
    state[21] ^= ( ~C[2] ) & C[3];
    state[22] ^= ( ~C[3] ) & C[4];
    state[23] ^= ( ~C[4] ) & C[0];
    state[24] ^= ( ~C[0] ) & C[1];

    //  Iota
    state[0] ^= RC[i];
  }
  memcpy( output, state, output_len );
}

// hash length is 256 bits
#if __CUDA_ARCH__ > 500
__global__ __launch_bounds__( TPB52, 1 )
#else
__global__ __launch_bounds__( TPB50, 2 )
#endif
  void gpu_mine( uint8_t* init_message, uint8_t* challenge_hash, uint8_t* device_solution, int32_t* done, uint8_t* hash_prefix, int32_t now, uint64_t cnt, uint32_t threads )
{
  uint32_t thread = blockDim.x * blockIdx.x + threadIdx.x;
  uint8_t message[84];
  memcpy(message, init_message, 84);

  int32_t str_len = 84;

  int32_t len = 0;
  for( len = 0; len < 52; len++ )
  {
    message[len] = hash_prefix[len];
  }

  //uint2 s[25], t[5], v, w, u[5];
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
    (uint64_t&)(message[52]) = nounce;

    const int32_t output_len = 32;
    uint8_t output[output_len];
    keccak( message, str_len, output, output_len );

    if( compare_hash( challenge_hash, output, output_len ) )
    {
      if( done[0] != 1 )
      {
        done[0] = 1;
        memcpy( device_solution, message, str_len );
      }
      return;
    }
  }
}

__host__
void stop_solving()
{
  h_done[0] = 1;
}

/**
 * Initializes the global variables by calling the cudaGetDeviceProperties().
 */
__host__
void gpu_init()
{
  if( gpu_initialized ) return;

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

  compute_version = device_prop.major * 100 + device_prop.minor * 10;

  // convert from GHz to hertz
  clock_speed = (int32_t)( device_prop.memoryClockRate * 1000 * 1000 );

  h_message = (uint8_t*)malloc( 84 );

  cudaMalloc( (void**)&d_done, sizeof( int32_t ) );
  cudaMalloc( (void**)&d_solution, 84 ); // solution
  cudaMalloc( (void**)&d_challenge_hash, 32 );
  cudaMalloc( (void**)&d_hash_prefix, 52 );
  cudaMallocHost( (void**)&h_message, 84 );

  //cnt = 0;
  printable_hashrate_cnt = 0;

  gpu_initialized = true;
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
  //cnt = 0;
  printable_hashrate_cnt = 0;
}

__host__
void update_mining_inputs( uint8_t * challenge_target, uint8_t * hash_prefix )
{
  cudaMemcpy( d_done, h_done, sizeof( int32_t ), cudaMemcpyHostToDevice );
  cudaMemset( d_solution, 0xff, 84 );
  cudaMemcpy( d_challenge_hash, challenge_target, 32, cudaMemcpyHostToDevice );
  cudaMemcpy( d_hash_prefix, hash_prefix, 52, cudaMemcpyHostToDevice );
}

__host__
bool find_message( uint8_t * challenge_target, uint8_t * hash_prefix )
{
  h_done[0] = 0;

  cudaMemcpy( d_done, h_done, sizeof( int32_t ), cudaMemcpyHostToDevice );
  cudaMemset( d_solution, 0xff, 84 );
  cudaMemcpy( d_challenge_hash, challenge_target, 32, cudaMemcpyHostToDevice );
  cudaMemcpy( d_hash_prefix, hash_prefix, 52, cudaMemcpyHostToDevice );

  int32_t now = (int32_t)time( 0 );
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

  uint8_t init_message[84];
  uint8_t* device_init_message;

  for(int32_t i_rand = 0; i_rand < 84; i_rand++){
    init_message[i_rand] = (uint8_t)rand() % 256;
  }
  cudaMalloc( (void**)&device_init_message, 84 );
  cudaMemcpy( device_init_message, init_message, 84, cudaMemcpyHostToDevice );

  gpu_mine <<< grid, block >>> ( device_init_message, d_challenge_hash, d_solution, d_done, d_hash_prefix, now, cnt, threads );
  cudaError_t cudaerr = cudaDeviceSynchronize();
  if( cudaerr != cudaSuccess )
  {
   printf( "kernel launch failed with error %d: %s.\n", cudaerr, cudaGetErrorString( cudaerr ) );
   exit( EXIT_FAILURE );
  }
  cnt += threads;
  printable_hashrate_cnt += threads;

  cudaMemcpy( h_done, d_done, sizeof( int32_t ), cudaMemcpyDeviceToHost );
  cudaMemcpy( h_message, d_solution, 84, cudaMemcpyDeviceToHost );

  clock_t t = clock() - start;

  // maybe breaking the control codes into macros is a good idea . . .
  printf( "\x1b[1A\x1b[37mHash Rate: \x1b[38;5;27m%*.2f \x1b[37mMH/second\tTotal hashes: \x1b[38;5;27m%*llu\x1b[0m\n",
           7, ( (double)printable_hashrate_cnt / ( (double)t / CLOCKS_PER_SEC ) / 1000000 ),
           12, printable_hashrate_cnt );
  return ( h_done[0] == 1 );
}

__host__
void gpu_cleanup()
{
  cudaThreadSynchronize();

  cudaFree( d_done );
  cudaFree( d_solution );
  cudaFree( d_challenge_hash );
  cudaFree( d_hash_prefix );
  cudaFreeHost( h_message );
}
