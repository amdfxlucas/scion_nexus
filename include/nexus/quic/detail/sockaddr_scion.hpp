#pragma once

#include <boost/asio.hpp>
#include "nexus/quic/detail/scion-utils.h"
#include "sha3/Keccak.h"
#include "sha3/Hex.h"
#include "sha3/HashFunction.h"


#define AF_SCION 47  // one more than AF_MAX

inline bool operator==( const sockaddr& x, const sockaddr& y)
{
    return x.sa_family == y.sa_family && std::ranges::equal(y.sa_data,x.sa_data);
}

/* read scion address might look something like:
  struct sockaddr_scion
  {
    __SOCKADDR_COMMON (scion_)=AF_SCION;
    uint64_t scion_ia;
    sa_family_t host_family;

    union host_address
    {
        sockaddr addr;
     sockaddr_in addr4;
     sockaddr_in6 addr6;   
    };   
   
  };*/

struct ScionUDPAddr
{   ScionUDPAddr(){}

    ScionUDPAddr( std::string addr )
    {
       auto [_ia,iisd,as,host,_port] = parseScionImpl(addr);

       ip = boost::asio::ip::address::from_string(host);
    port = _port;       
    this->ia = _ia;
        
    }

    uint64_t ia;
    boost::asio::ip::address ip;
    uint16_t port;
    auto operator<=>(const ScionUDPAddr& )const = default;

    void setISD( uint16_t isd )
    {
        ia = _MAKE_IA_(isd, getAS() );
    }

    void setAS( uint64_t as )
    {
        ia = _MAKE_IA_(getISD(), as );
    }

    void setIA( uint64_t _ia ){ ia= _ia; }
    constexpr uint64_t getIA()const{return ia;}
    constexpr uint16_t getISD()const{ return ISD_FROM_IA(ia);}
    constexpr uint64_t getAS()const{return AS_FROM_IA(ia); }

    std::string toString() const
    {
        return std::format("{}-{},{}:{}", getISD()
        , ASToDottedHex(getAS() ),ip.to_string(),port );
    }
};


/* parse the proxyHeader as written by ListenSockAdapter::panToUnix()
*/
inline ScionUDPAddr parseProxyHeader(const char* buffer, size_t len)
{
     using namespace boost;
    ScionUDPAddr addr;

    if (len < 30 ) {
        throw std::runtime_error("Invalid unix socket packet header");
    }

    uint64_t big_ia = BigEndian::fromByte( (const uint8_t*)buffer ) ;  
    addr.setIA( big_ia );

    uint32_t addrLen = *(uint32_t*)&buffer[8];
    if (addrLen == 4) {
        asio::ip::address_v4::bytes_type bytes;
        std::copy_n(buffer + 12, 4, bytes.begin());
        addr.ip = asio::ip::address_v4(bytes);
    } else if (addrLen == 16) {
        asio::ip::address_v6::bytes_type bytes;
        std::copy_n(buffer + 12, 16, bytes.begin());
        addr.ip = asio::ip::address_v6(bytes);
    } else {
        throw std::runtime_error("Invalid unix socket packet header");
    }

    addr.port = *(uint16_t*)&buffer[28];

    return addr;
}

/* make a proxy header as expected by ListenSockAdapter::unixToPan() 
*/
inline void makeProxyHeader( char* buffer, const ScionUDPAddr& addr )
{

       BigEndian::toBytes( (uint8_t*) buffer, addr.getIA() );

    if(addr.ip.is_v4() )
    {
    *(uint32_t*)&buffer[8] = 4;
       std::copy_n( addr.ip.to_v4().to_bytes().begin(), 4, buffer+12 );
    }else if (addr.ip.is_v6() )
    {
        *(uint32_t*)&buffer[8] = 16;
     
        std::copy_n( addr.ip.to_v6().to_bytes().begin(), 16, buffer+12 );
    } else
    {
        throw std::runtime_error( "invalid ScionUdpAddr");
    }
     *(uint16_t*)&buffer[28] = addr.port ;

}

/*!
    \brief 
    \details as long as there is no Kernel support for scion
            (i.e. new address family AF_SCION and sockaddr_scion struct)
             scion addresses can be mapped to fake IPv4 addresses 
             in order for them to being processed by the lsquic engine

 \param addr_str  string representation of an address
                with arbitrary length
 i.e. scion address: 
  "19-ffaa:1:1067,192.168.2.222:5555"
  \returns a unix sockaddr struct whose  'char sa_data[14]'
            array is filled with the 14 byte Shake hash of the passed address
*/

  inline sockaddr hashSockaddr( const std::string& addr_str,
   const std::optional<uint16_t>& port = std::nullopt )
  {
    sockaddr addr { .sa_family=AF_INET };   

    Shake sh{32,14};    
    // das ist eigentlich suboptimal, weil der port so quasi zweimal in den hash eingeht
    // er ist im string enthalten, und in sa_data[0-1]
    const uint8_t* byte_array = reinterpret_cast<const uint8_t*>(addr_str.data());
	sh.addData(byte_array, 0, addr_str.length() );
    std::vector<unsigned char> op = sh.digest();

    //  maybe use the first 2 bytes of sa_data for the port  ( and make the hash only 12 byte )
    // as with sockaddr_in ('   in_port_t sin_port;			/* Port number.  */ ')
    // and sockaddr_in6 (in_port_t sin6_port;	/* Transport layer port # */)

    if( !port )
    {
    for( int i=0; auto c : op )
    {
        addr.sa_data[i++] = c;
    }
    }else
    {
        addr.sa_data[0] = ((uint8_t*)(&*port))[0];
        addr.sa_data[1] = ((uint8_t*)(&*port))[1];
    for( int i=2; i< 14; ++i)
    {
        addr.sa_data[i] =  op[i];
    }
    }

    return addr;
  }

/* fits a scion address with an IPv4 host part into a sockaddr struct (lossless)
*/
inline sockaddr scion2Sockaddr( uint64_t ia, uint16_t port,
                     const boost::asio::ip::address & host )
{
    sockaddr addr{.sa_family = AF_INET };

    addr.sa_data[0] = ((uint8_t*)(&port))[0];
    addr.sa_data[1] = ((uint8_t*)(&port))[1];

    addr.sa_data[2] = ((uint8_t*)(&ia))[0];
    addr.sa_data[3] = ((uint8_t*)(&ia))[1];
    addr.sa_data[4] = ((uint8_t*)(&ia))[2];    
    addr.sa_data[5] = ((uint8_t*)(&ia))[3];
    addr.sa_data[6] = ((uint8_t*)(&ia))[4];
    addr.sa_data[7] = ((uint8_t*)(&ia))[5];
    addr.sa_data[8] = ((uint8_t*)(&ia))[6];
    addr.sa_data[9] = ((uint8_t*)(&ia))[7];

    if(host.is_v4() )
    {   auto ip = host.to_v4().to_bytes();
        addr.sa_data[10] = ip[0];
        addr.sa_data[11] = ip[1];
        addr.sa_data[12] = ip[2];
        addr.sa_data[13] = ip[3];
    } else
    {
        //  cant fit 16 byte IPv6 address in remaining 4 byte storage
        throw std::runtime_error( "unsupported operation: scion address with IPv6 host part ");
    }

    return addr;
}

inline sockaddr hashSockaddr( const Pan::udp::Endpoint& endpoint )
{
   // if you want to support IPv6 host parts 
  //  return hashSockaddr(endpoint.toString());
  return scion2Sockaddr(endpoint.getIA(), endpoint.getPort() , endpoint.getIP() );
}


  std::string sockaddr2str( const sockaddr& add )
  {
    return std::format( "{}-{}" , add.sa_family, std::string_view(add.sa_data,14) );
  }

namespace std {
  template <> struct hash<sockaddr>
  {
    size_t operator()(const sockaddr & x) const
    {
      return std::hash<std::string>()( sockaddr2str(x)  );
    }
  };
}

  class addrMapper
  {
    public:
    static addrMapper& instance()
    {static addrMapper add;
    return add;
    }

    void insertMapping( const sockaddr& hash,const ScionUDPAddr& remote )
    {
        if( auto val = lookupHash(hash); val)
        {
            if( *(*val) == remote )
                return;
        }
        m_map.insert( {hash,remote} );
    }    

    std::optional<const ScionUDPAddr*> lookupHash( const sockaddr& hash )const
    {
        if( m_map.contains( hash) )
        {
            return &m_map.at(hash);
        } else
        {
            return std::nullopt;
        }
    }

private:
    addrMapper(){}

    std::unordered_map<sockaddr, ScionUDPAddr> m_map;

  };


