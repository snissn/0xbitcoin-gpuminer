// default magic numbers
#define INTENSITY 23
#define CUDA_DEVICE 0
// default magic numbers

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <sys/timeb.h>

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
struct timeb start, end;

uint64_t cnt;
uint64_t printable_hashrate_cnt;
uint64_t print_counter;

bool gpu_initialized;
bool new_input;

uint8_t solution[32] = { 0 };
uint8_t* h_message;
uint8_t init_message[84];

int32_t* d_done;
uint64_t* d_solution;

uint8_t* d_challenge;
uint8_t* d_hash_prefix;
__constant__ uint64_t d_mid[25];

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
	return ((uint64_t)(__byte_perm((uint32_t) x, 0, 0x0123)) << 32)
		   + __byte_perm((uint32_t)(x >> 32), 0, 0x0123);
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

__device__
bool keccak( uint64_t nounce, uint64_t target )
{
  uint64_t state[25], C[5], D[5];

  int32_t x;

  state[ 2] = d_mid[ 2] ^ ROTL64(nounce, 44);
  state[ 4] = d_mid[ 4] ^ ROTL64(nounce, 14);

  state[ 6] = d_mid[ 6] ^ ROTL64(nounce, 20);
  state[ 9] = d_mid[ 9] ^ ROTL64(nounce, 62);

  state[11] = d_mid[11] ^ ROTL64(nounce, 7);
  state[13] = d_mid[13] ^ ROTL64(nounce, 8);

  state[15] = d_mid[15] ^ ROTL64(nounce, 27);
  state[18] = d_mid[18] ^ ROTL64(nounce, 16);

  state[20] = d_mid[20] ^ ROTL64(nounce, 63);
  state[21] = d_mid[21] ^ ROTL64(nounce, 55);
  state[22] = d_mid[22] ^ ROTL64(nounce, 39);

  //  Chi
  // for j = 0 to 25, j += 5
  //     for i = 0 to 5
  //         C[i] = state[j + i];
  //     for i = 0 to 5
  //         state[j + 1] ^= (~C[(i + 1) % 5]) & C[(i + 2) % 5];
  state[ 0] = d_mid[ 0] ^ ( ~d_mid[ 1] ) & state[ 2];
  state[ 1] = d_mid[ 1] ^ ( ~state[ 2] ) & d_mid[ 3];
  state[ 2] = state[ 2] ^ ( ~d_mid[ 3] ) & state[ 4];
  state[ 3] = d_mid[ 3] ^ ( ~state[ 4] ) & d_mid[ 0];
  state[ 4] = state[ 4] ^ ( ~d_mid[ 0] ) & d_mid[ 1];

  C[0] = state[ 6];
  state[ 5] = d_mid[ 5] ^ ( ~state[ 6] ) & d_mid[7];
  state[ 6] = state[ 6] ^ ( ~d_mid[ 7] ) & d_mid[8];
  state[ 7] = d_mid[ 7] ^ ( ~d_mid[ 8] ) & state[9];
  state[ 8] = d_mid[ 8] ^ ( ~state[ 9] ) & d_mid[5];
  state[ 9] = state[ 9] ^ ( ~d_mid[ 5] ) & C[0];

  C[0] = state[11];
  state[10] = d_mid[10] ^ ( ~state[11] ) & d_mid[12];
  state[11] = state[11] ^ ( ~d_mid[12] ) & state[13];
  state[12] = d_mid[12] ^ ( ~state[13] ) & d_mid[14];
  state[13] = state[13] ^ ( ~d_mid[14] ) & d_mid[10];
  state[14] = d_mid[14] ^ ( ~d_mid[10] ) & C[0];

  C[0] = state[15];
  state[15] = state[15] ^ ( ~d_mid[16] ) & d_mid[17];
  state[16] = d_mid[16] ^ ( ~d_mid[17] ) & state[18];
  state[17] = d_mid[17] ^ ( ~state[18] ) & d_mid[19];
  state[18] = state[18] ^ ( ~d_mid[19] ) & C[0];
  state[19] = d_mid[19] ^ ( ~C[0] ) & d_mid[16];

  C[0] = state[20];
  C[1] = state[21];
  state[20] = state[20] ^ ( ~state[21] ) & state[22];
  state[21] = state[21] ^ ( ~state[22] ) & d_mid[23];
  state[22] = state[22] ^ ( ~d_mid[23] ) & d_mid[24];
  state[23] = d_mid[23] ^ ( ~d_mid[24] ) & C[0];
  state[24] = d_mid[24] ^ ( ~C[0] ) & C[1];

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
    D[0] = ROTL64(C[1], 1) ^ C[4];
    state[ 0] ^= D[0];
    state[ 5] ^= D[0];
    state[10] ^= D[0];
    state[15] ^= D[0];
    state[20] ^= D[0];

    D[0] = ROTL64(C[2], 1) ^ C[0];
    state[ 1] ^= D[0];
    state[ 6] ^= D[0];
    state[11] ^= D[0];
    state[16] ^= D[0];
    state[21] ^= D[0];

    D[0] = ROTL64(C[3], 1) ^ C[1];
    state[ 2] ^= D[0];
    state[ 7] ^= D[0];
    state[12] ^= D[0];
    state[17] ^= D[0];
    state[22] ^= D[0];

    D[0] = ROTL64(C[4], 1) ^ C[2];
    state[ 3] ^= D[0];
    state[ 8] ^= D[0];
    state[13] ^= D[0];
    state[18] ^= D[0];
    state[23] ^= D[0];

    D[0] = ROTL64(C[0], 1) ^ C[3];
    state[ 4] ^= D[0];
    state[ 9] ^= D[0];
    state[14] ^= D[0];
    state[19] ^= D[0];
    state[24] ^= D[0];
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
void gpu_mine( uint64_t* solution, int32_t* done, uint64_t cnt, uint32_t threads, uint64_t target )
{
  uint32_t thread = blockDim.x * blockIdx.x + threadIdx.x;

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

    if( keccak( nounce, target ) )
    {
	  const uint32_t temp = atomicExch( &done[0], thread );
      if( done[0] == thread )
      {
        *solution = nounce;
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

__host__
void send_to_device( uint64_t* message )
{
	uint64_t C[4], D[5], mid[25];
	C[0] = message[0] ^ message[5] ^ message[10] ^ 0x100000000ull;
	C[1] = message[1] ^ message[6] ^ 0x8000000000000000ull;
	C[2] = message[2] ^ message[7];
	C[3] = message[4] ^ message[9];

	D[0] = ROTL64(C[1], 1) ^ C[3];
	D[1] = ROTL64(C[2], 1) ^ C[0];
	D[2] = ROTL64(message[3], 1) ^ C[1];
	D[3] = ROTL64(C[3], 1) ^ C[2];
	D[4] = ROTL64(C[0], 1) ^ message[3];

	mid[ 0] = message[ 0] ^ D[0];//S[0]
	mid[ 1] = ROTL64( message[6] ^ D[1], 44 );//S[1]
	mid[ 2] = ROTL64(D[2], 43);//D[2]
	mid[ 3] = ROTL64(D[3], 21);//D[0]
	mid[ 4] = ROTL64(D[4], 14);
	mid[ 5] = ROTL64( message[3] ^ D[3], 28 );//S[5]
	mid[ 6] = ROTL64( message[9] ^ D[4], 20 );//S[6]
	mid[ 7] = ROTL64( message[10] ^ D[0] ^ 0x100000000ull, 3 );//S[7]
	mid[ 8] = ROTL64( 0x8000000000000000ull ^ D[1], 45 );//S[8]
	mid[ 9] = ROTL64(D[2], 61);
	mid[10] = ROTL64( message[1] ^ D[1],  1 );//S[10]
	mid[11] = ROTL64( message[7] ^ D[2],  6 );//S[11]
	mid[12] = ROTL64(D[3], 25);
	mid[13] = ROTL64(D[4],  8);
	mid[14] = ROTL64(D[0], 18);
	mid[15] = ROTL64( message[4] ^ D[4], 27 );//S[15]
	mid[16] = ROTL64( message[5] ^ D[0], 36 );//S[16]
	mid[17] = ROTL64(D[1], 10);
	mid[18] = ROTL64(D[2], 15);
	mid[19] = ROTL64(D[3], 56);
	mid[20] = ROTL64( message[2] ^ D[2], 62 );//S[20]
	mid[21] = ROTL64(D[3], 55);
	mid[22] = ROTL64(D[4], 39);
	mid[23] = ROTL64(D[0], 41);
	mid[24] = ROTL64(D[1],  2);

	cudaMemcpyToSymbol( d_mid, mid, sizeof( mid ), cuda_device, cudaMemcpyHostToDevice);
}

/**
 * Initializes the global variables by calling the cudaGetDeviceProperties().
 */
__host__
void gpu_init()
{
  cudaDeviceProp device_prop;
  int32_t device_count;
  ftime( &start );
  
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
	memcpy( solution, &init_message[52], 32 );

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
  send_to_device( (uint64_t*)init_message );

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
  cudaMemcpy( h_message, d_solution, 8, cudaMemcpyDeviceToHost );
  memcpy( &solution[12], h_message, 8 );

  ftime( &end );
  double t = (double)((end.time * 1000 + end.millitm) - (start.time * 1000 + start.millitm)) / 1000;

  if( t*10 > print_counter )
  {
    print_counter++;

	// maybe breaking the control codes into macros is a good idea . . .
	printf( "\x1b[s\x1b[3;67f\x1b[38;5;221m%*.2f\x1b[0m\x1b[u"
			"\x1b[s\x1b[3;29f\x1b[38;5;208m%*" PRIu64 "\x1b[0m\x1b[u",
			8, ( (double)printable_hashrate_cnt / t / 1000000 ),
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
