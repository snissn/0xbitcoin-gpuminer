#include <time.h>
#include <curand.h>
#include <assert.h>
#include <curand_kernel.h>
#include <cuda_helper.h>
#include <cuda_vectors.h>

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

void gpu_init();
//void runBenchmarks();
//char *read_in_messages();
int gcd( int a, int b );

// updated message the gpu_init() function
//int clock_speed;
//int number_multi_processors;
//int max_threads_per_mp;
//int sm_version;
int number_blocks;
int number_threads;
int num_loops;
int h_done[1] = { 0 };

unsigned long long cnt = 0;

int num_messages;
const int digest_size = 256;
const int digest_size_bytes = digest_size / 8;
const size_t str_length = 7;	//change for different sizes

unsigned char * h_message;
static unsigned char *d_solution;

//unsigned char *d_challenge_hash;
//unsigned char *d_hash_prefix;
//__device__ unsigned char *d_hash;
//__managed__ char * m_working_memory_nonce;

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

#define RHOPI(x)	j = piln[(x)]; \
                  C[0] = state[j]; \
                  state[j] = ROTL64( temp, r[(x)] ); \
                  temp = C[0];

#define CUDA_SAFE_CALL(call)                                      \
do {                                                              \
	cudaError_t err = call;                                         \
	if (cudaSuccess != err) {                                       \
		fprintf(stderr, "Cuda error in func '%s' at line %i : %s.\n", \
		         __FUNCTION__, __LINE__, cudaGetErrorString(err) );   \
		exit(EXIT_FAILURE);                                           \
	}                                                               \
} while (0)

__constant__ uint64_t RC[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

__constant__ int r[24] = {
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

__constant__ int piln[24] = {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

#define TPB52 1024
#define TPB50 384
#define NPT 2
#define NBN 2

static uint32_t *d_nonces[MAX_GPUS];
static uint32_t *h_nonces[MAX_GPUS];

__constant__ uint2 c_message48[6];
__constant__ uint2 c_mid[17];

__constant__ uint2 keccak_round_constants[24] = {
  { 0x00000001, 0x00000000 },{ 0x00008082, 0x00000000 },{ 0x0000808a, 0x80000000 },{ 0x80008000, 0x80000000 },
{ 0x0000808b, 0x00000000 },{ 0x80000001, 0x00000000 },{ 0x80008081, 0x80000000 },{ 0x00008009, 0x80000000 },
{ 0x0000008a, 0x00000000 },{ 0x00000088, 0x00000000 },{ 0x80008009, 0x00000000 },{ 0x8000000a, 0x00000000 },
{ 0x8000808b, 0x00000000 },{ 0x0000008b, 0x80000000 },{ 0x00008089, 0x80000000 },{ 0x00008003, 0x80000000 },
{ 0x00008002, 0x80000000 },{ 0x00000080, 0x80000000 },{ 0x0000800a, 0x00000000 },{ 0x8000000a, 0x80000000 },
{ 0x80008081, 0x80000000 },{ 0x00008080, 0x80000000 },{ 0x80000001, 0x00000000 },{ 0x80008008, 0x80000000 }
};

__device__ __forceinline__
uint2 xor3x( const uint2 a, const uint2 b, const uint2 c )
{
  uint2 result;
#if __CUDA_ARCH__ >= 500 && CUDA_VERSION >= 7050
  asm( "lop3.b32 %0, %1, %2, %3, 0x96;" : "=r"( result.x ) : "r"( a.x ), "r"( b.x ), "r"( c.x ) ); //0x96 = 0xF0 ^ 0xCC ^ 0xAA
  asm( "lop3.b32 %0, %1, %2, %3, 0x96;" : "=r"( result.y ) : "r"( a.y ), "r"( b.y ), "r"( c.y ) ); //0x96 = 0xF0 ^ 0xCC ^ 0xAA
#else
  result = a ^ b^c;
#endif
  return result;
}

__device__ __forceinline__
uint2 chi( const uint2 a, const uint2 b, const uint2 c )
{ // keccak chi
  uint2 result;
#if __CUDA_ARCH__ >= 500 && CUDA_VERSION >= 7050
  asm( "lop3.b32 %0, %1, %2, %3, 0xD2;" : "=r"( result.x ) : "r"( a.x ), "r"( b.x ), "r"( c.x ) ); //0xD2 = 0xF0 ^ ((~0xCC) & 0xAA)
  asm( "lop3.b32 %0, %1, %2, %3, 0xD2;" : "=r"( result.y ) : "r"( a.y ), "r"( b.y ), "r"( c.y ) ); //0xD2 = 0xF0 ^ ((~0xCC) & 0xAA)
#else
  result = a ^ ( ~b ) & c;
#endif
  return result;
}

__device__ __forceinline__
uint64_t xor5( uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e )
{
  uint64_t result;
  asm( "xor.b64 %0, %1, %2;" : "=l"( result ) : "l"( d ), "l"( e ) );
  asm( "xor.b64 %0, %0, %1;" : "+l"( result ) : "l"( c ) );
  asm( "xor.b64 %0, %0, %1;" : "+l"( result ) : "l"( b ) );
  asm( "xor.b64 %0, %0, %1;" : "+l"( result ) : "l"( a ) );
  return result;
}

__device__ int compare_hash( const unsigned char *target, const unsigned char *hash, const int length )
{
  int i = 0;

  for( i = 0; i < length; i++ )
  {
    if( hash[i] != target[i] )break;
  }
  return (unsigned char)( hash[i] ) < (unsigned char)( target[i] );
}

__device__ void keccak256( uint64_t state[25] )
{
  uint64_t temp, C[5];
  int j;
  for( int i = 0; i < 24; i++ )
  {
    // Theta
// for i = 0 to 5
//    C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
    C[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
    C[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
    C[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
    C[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
    C[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

    // for i = 0 to 5
    //     temp = C[(i + 4) % 5] ^ ROTL64(C[(i + 1) % 5], 1);
    //     for j = 0 to 25, j += 5
    //          state[j + i] ^= temp;
    temp = C[4] ^ ROTL64( C[1], 1 );
    state[0] ^= temp;
    state[5] ^= temp;
    state[10] ^= temp;
    state[15] ^= temp;
    state[20] ^= temp;

    temp = C[0] ^ ROTL64( C[2], 1 );
    state[1] ^= temp;
    state[6] ^= temp;
    state[11] ^= temp;
    state[16] ^= temp;
    state[21] ^= temp;

    temp = C[1] ^ ROTL64( C[3], 1 );
    state[2] ^= temp;
    state[7] ^= temp;
    state[12] ^= temp;
    state[17] ^= temp;
    state[22] ^= temp;

    temp = C[2] ^ ROTL64( C[4], 1 );
    state[3] ^= temp;
    state[8] ^= temp;
    state[13] ^= temp;
    state[18] ^= temp;
    state[23] ^= temp;

    temp = C[3] ^ ROTL64( C[0], 1 );
    state[4] ^= temp;
    state[9] ^= temp;
    state[14] ^= temp;
    state[19] ^= temp;
    state[24] ^= temp;

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
}

__device__ void keccak( const unsigned char *message, int message_len, unsigned char *output, int output_len )
{
  uint64_t state[25];
  uint8_t temp[144];
  int rsize = 136;
  int rsize_byte = 17;

  memset( state, 0, sizeof( state ) );

  for( ; message_len >= rsize; message_len -= rsize, message += rsize )
  {
    for( int i = 0; i < rsize_byte; i++ )
    {
      state[i] ^= ( (uint64_t *)message )[i];
    }
    keccak256( state );
  }

  // last block and padding
  memcpy( temp, message, message_len );
  temp[message_len++] = 1;
  memset( temp + message_len, 0, rsize - message_len );
  temp[rsize - 1] |= 0x80;
  for( int i = 0; i < rsize_byte; i++ )
  {
    state[i] ^= ( (uint64_t *)temp )[i];
  }

  keccak256( state );
  memcpy( output, state, output_len );
}

// hash length is 256 bits
__global__ void gpu_mine( unsigned char *d_solution, const unsigned char *d_challenge_hash, const unsigned char *d_hash_prefix, int now, unsigned long long cnt, int loops )
{
  const unsigned int tid = threadIdx.x + ( blockIdx.x * blockDim.x );
  const unsigned int str_len = 84;
  unsigned char message[str_len];
  bool done = false;

  curandState_t state;
  /* we have to initialize the state */
  curand_init( now, tid, cnt, &state );
  unsigned int len = 0;
  for( len = 0; len < 52; len++ )
  {
    message[len] = d_hash_prefix[len];
  }
  for( unsigned int i = 0; i < loops; i++ )
  {
    for( len = 0; len < 32; len++ )
    {
      char r = (char)curand( &state ) % 256;
      message[52 + len] = r;
    }

    const unsigned int output_len = 32;
    unsigned char output[output_len];
    keccak( message, str_len, output, output_len );

    if( compare_hash( d_challenge_hash, output, output_len ) )
    {
      if( !done )
      {
        done = true;
        memcpy( d_solution, message, str_len );
      }
      return;
    }

  }
}

__host__ void stop_solving()
{
  h_done[0] = 1;
}

/**
 * Initializes the global variables by calling the cudaGetDeviceProperties().
 */
__host__ void gpu_init()
{
  cudaDeviceProp device_prop;
  int device_count;
  cnt = 0;

  CUDA_SAFE_CALL( cudaGetDeviceCount( &device_count ) );

  if( cudaGetDeviceProperties( &device_prop, 0 ) != cudaSuccess )
  {
    printf( "Problem getting properties for device, exiting...\n" );
    exit( EXIT_FAILURE );
  }

  //number_threads = device_prop.maxThreadsPerBlock;
  //number_multi_processors = device_prop.multiProcessorCount;
  //max_threads_per_mp = device_prop.maxThreadsPerMultiProcessor;
  //sm_version = device_prop.major * 100 + device_prop.minor * 10;

  char config[30];
  FILE * inf;
  inf = fopen( "0xbtc.conf", "r" );
  if( inf )
  {
    fgets( config, 30, inf );
    fclose( inf );
  }
  num_loops = atol( strtok( config, " " ) );
  number_threads = atol( strtok( NULL, " " ) );
  number_blocks = atol( strtok( NULL, " " ) );

  //clock_speed = (int)( device_prop.memoryClockRate * 1000 * 1000 );    // convert from GHz to hertz

  CUDA_SAFE_CALL( cudaMalloc( &d_solution, 84 ) ); // solution
  //CUDA_SAFE_CALL( cudaMalloc( (void**)&d_challenge_hash, 32 ) );
  //CUDA_SAFE_CALL( cudaMalloc( (void**)&d_hash_prefix, 52 ) );
  CUDA_SAFE_CALL( cudaMemset( d_solution, 0xff, 84 ) );
}

int gcd( int a, int b )
{
  return ( a == 0 ) ? b : gcd( b % a, a );
}

__host__ unsigned long long getHashCount()
{
  return cnt;
}
__host__ void resetHashCount()
{
  cnt = 0;
}

__host__ void update_mining_inputs( const unsigned char * challenge_target, const unsigned char * hash_prefix ) // can accept challenge
{
  //CUDA_SAFE_CALL( cudaMalloc( (void**)&d_solution, 84 ) ); // solution
  //CUDA_SAFE_CALL( cudaMalloc( (void**)&d_challenge_hash, 32 ) );
  //CUDA_SAFE_CALL( cudaMalloc( (void**)&d_hash_prefix, 52 ) );

  //CUDA_SAFE_CALL( cudaMemset( d_solution, 0xff, 84 ) );
  //CUDA_SAFE_CALL( cudaMemcpy( d_challenge_hash, challenge_target, 32, cudaMemcpyHostToDevice ) );
  //CUDA_SAFE_CALL( cudaMemcpy( d_hash_prefix, hash_prefix, 52, cudaMemcpyHostToDevice ) );
  //stop_solving();
}

__host__ unsigned char * find_message( const unsigned char * challenge_target, const unsigned char * hash_prefix ) // can accept challenge
{
  //CUDA_SAFE_CALL( cudaThreadSetLimit( cudaLimitMallocHeapSize, 2 * ( 84 * number_blocks*number_threads + 32 * number_blocks*number_threads ) ) );

  unsigned int workers = number_blocks * number_threads;
  h_message = (unsigned char*)malloc( 84 );
  //  cudaMallocManaged( &m_working_memory_nonce, workers * 84 );

  int now = (int)time( 0 );
  dim3 grid( number_blocks ),
    block( number_threads );

  gpu_mine <<< grid, block >>> ( d_solution, challenge_target, hash_prefix, now, cnt, num_loops );
  //CUDA_SAFE_CALL( cudaThreadSynchronize() );
  cnt += workers * num_loops;

  cudaMemcpy( h_message, &d_solution, 84, cudaMemcpyDeviceToHost );
  fprintf( stderr, "Total hashes: %llu\n", cnt );

  return h_message;
}

__host__ void gpu_cleanup()
{
  CUDA_SAFE_CALL( cudaFree( &d_solution ) );
  //CUDA_SAFE_CALL( cudaFree( &d_challenge_hash ) );

  //CUDA_SAFE_CALL( cudaFree( &d_hash_prefix ) );
  //  CUDA_SAFE_CALL( cudaFree( &m_working_memory_nonce ) );
}