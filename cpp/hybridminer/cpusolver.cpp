#include "cpusolver.h"
#include "sha3.h"

#include <assert.h>

static uint8_t fromAscii( uint8_t c )
{
  if( c >= '0' && c <= '9' )
    return ( c - '0' );
  if( c >= 'a' && c <= 'f' )
    return ( c - 'a' + 10 );
  if( c >= 'A' && c <= 'F' )
    return ( c - 'A' + 10 );

#if defined(__EXCEPTIONS) || defined(DEBUG)
  throw std::runtime_error( "invalid character" );
#else
  return 0xff;
#endif
}

static uint8_t ascii_r( uint8_t a, uint8_t b )
{
  return fromAscii( a ) * 16 + fromAscii( b );
}

static void HexToBytes( std::string const& hex, uint8_t bytes[] )
{
  for( std::string::size_type i = 0, j = 0; i < hex.length(); i += 2, ++j )
  {
    bytes[j] = ascii_r( hex[i], hex[i + 1] );
  }
}

// --------------------------------------------------------------------

// static
std::atomic<uint32_t> CPUSolver::hashes( 0u ); // statistics only

CPUSolver::CPUSolver() noexcept :
m_address( ADDRESS_LENGTH ),
m_challenge( UINT256_LENGTH ),
m_target( UINT256_LENGTH ),
m_target_tmp( UINT256_LENGTH ),
m_buffer( ADDRESS_LENGTH + 2 * UINT256_LENGTH ),
m_buffer_tmp( ADDRESS_LENGTH + 2 * UINT256_LENGTH ),
m_buffer_ready( false ),
m_target_ready( false )
{
}

void CPUSolver::setAddress( std::string const& addr )
{
  assert( addr.length() == ( ADDRESS_LENGTH * 2 + 2 ) );
  hexToBytes( addr, m_address );
  updateBuffer();
}

void CPUSolver::setChallenge( std::string const& chal )
{
  assert( chal.length() == ( UINT256_LENGTH * 2 + 2 ) );
  hexToBytes( chal, m_challenge );
  updateBuffer();
}

void CPUSolver::setTarget( std::string const& target )
{
  assert( target.length() <= ( UINT256_LENGTH * 2 + 2 ) );
  std::string const t( static_cast<std::string::size_type>( UINT256_LENGTH * 2 + 2 ) - target.length(), '0' );

  // Double-buffer system, the trySolution() function will be blocked
  //  only when a change occurs.
  {
    std::lock_guard<std::mutex> g( m_target_mutex );
    hexToBytes( "0x" + t + target.substr( 2 ), m_target_tmp );
  }
  m_target_ready = true;
}

// Buffer order: 1-challenge 2-ethAddress 3-solution
void CPUSolver::updateBuffer()
{
  // The idea is to have a double-buffer system in order not to try
  //  to acquire a lock on each hash() loop
  {
    std::lock_guard<std::mutex> g( m_buffer_mutex );
    std::copy( m_challenge.cbegin(), m_challenge.cend(), m_buffer_tmp.begin() );
    std::copy( m_address.cbegin(), m_address.cend(), m_buffer_tmp.begin() + m_challenge.size() );
  }
  m_buffer_ready = true;
}

void CPUSolver::hash( bytes_t const& solution, bytes_t& digest )
{
  if( m_buffer_ready )
  {
    std::lock_guard<std::mutex> g( m_buffer_mutex );
    m_buffer.swap( m_buffer_tmp );
    m_buffer_ready = false;
  }

  std::copy( solution.cbegin(), solution.cend(), m_buffer.begin() + m_challenge.size() + m_address.size() );
  keccak_256( &digest[0], digest.size(), &m_buffer[0], m_buffer.size() );
}

bool CPUSolver::trySolution( bytes_t const& solution )
{
  bytes_t digest( UINT256_LENGTH );
  hash( solution, digest );

  if( m_target_ready )
  {
    std::lock_guard<std::mutex> g( m_target_mutex );
    m_target.swap( m_target_tmp );
    m_target_ready = false;
  }

  ++hashes;

  return lte( digest, m_target );
}

// static
void CPUSolver::hexToBytes( std::string const& hex, bytes_t& bytes )
{
  assert( hex.length() % 2 == 0 );
  assert( bytes.size() == ( hex.length() / 2 - 1 ) );
  HexToBytes( hex.substr( 2 ), &bytes[0] );
}

// static
std::string CPUSolver::bytesToString( bytes_t const& buffer )
{
  static const char table[] = "0123456789ABCDEF";
  std::string output;
  output.reserve( buffer.size() * 2 + 1 );

  for( unsigned i = 0; i < buffer.size(); ++i )
    output += table[buffer[i]];

  return output;
}

// static
bool CPUSolver::lte( bytes_t const& left, bytes_t const& right )
{
  assert( left.size() == right.size() );

  for( unsigned i = 0; i < left.size(); ++i )
  {
    if( left[i] == right[i] )
      continue;
    if( left[i] > right[i] )
      return false;
    return true;
  }
  return true;
}
