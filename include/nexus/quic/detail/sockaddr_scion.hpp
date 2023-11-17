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
    
   
  };



struct ScionUDPAddr
{   ScionUDPAddr(){}

    ScionUDPAddr( std::string addr )
    {
       auto [ia,iisd,as,host,_port] = parseScionImpl(addr);

       ip = boost::asio::ip::address::from_string(host);
    
        uint64_t ia_big;

        reverseBytes( (uint8_t*)&ia, (uint8_t*)&ia_big,8);

        port = _port;
        isd[0] = ( ((uint8_t*)(&iisd ) )[0]);
        isd[1] = ( ((uint8_t*)(&iisd ))[1]);

   
        for( int i = 0; i < 6; ++i)
        {
            asn[i] = ( ((uint8_t*)(&ia_big ))[i+2]);
        }
    }

    uint8_t isd[2]; // in BigEndian ?!
    uint8_t asn[6]; // in BigEndian ?!
    boost::asio::ip::address ip;
    uint16_t port;
    auto operator<=>(const ScionUDPAddr& )const = default;

        // parameter in littleE
     void setISD( uint16_t  _isd )
    {
        for( uint8_t i=0; i<2 ; ++i)
        {
            isd[i] = ((uint8_t*)&_isd)[i];
        }

    }
    //parameter in littleE
    void setAS( uint64_t _as )
    {
        uint64_t big_as = reverseEndian( _as);
        for( uint8_t i=0; i<6 ; ++i)
        {
            asn[i] = ((uint8_t*)&big_as)[i+2];
        }
    }

    constexpr uint16_t getISD()const
    {
        uint16_t iisd;
        for( int i = 0; i<2; ++i)
        {
                ((uint8_t*)&iisd)[i] = isd[i];
        }
        return iisd;
    }

    constexpr uint64_t getAS()const
    {
          uint64_t as_big{0};
        uint64_t as{0};

         for( int i=0; i<6;++i )
         
        {
             ((uint8_t*)(&as_big) )[2+i] = asn[i];
           
        }
    reverseBytes( (uint8_t*)&as_big, (uint8_t*)&as,8 );

        return as;
        
    }

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
    uint64_t _ia = reverseEndian( big_ia);

    uint16_t _isd = ISD_FROM_IA( _ia );
    uint64_t _as = AS_FROM_IA( _ia );

    addr.setISD(_isd);
    addr.setAS( _as );


    /*
    for (size_t i = 0; i < 2; ++i)
        addr.isd[i] = buffer[i];
    for (size_t i = 0; i < 6; ++i)
        addr.asn[i] = buffer[2 + i];
    */

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

  for (size_t i = 0; i < 2; ++i)
        buffer[i] = addr.isd[i];
    for (size_t i = 0; i < 6; ++i)
         buffer[2 + i] = addr.asn[i] ;

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



  inline sockaddr hashSockaddr( const std::string& addr_str )
  {
    sockaddr addr { .sa_family=AF_INET };   

    Shake sh{32,14};
    const uint8_t* byte_array = reinterpret_cast<const uint8_t*>(addr_str.data());
	sh.addData(byte_array, 0, addr_str.length() );
    std::vector<unsigned char> op = sh.digest();

    for( int i=0; auto c : op )
    {
        addr.sa_data[i++] = c;
    }

    return addr;
  }
    inline sockaddr hashSockaddr( const Pan::udp::Endpoint& endpoint )
  {return hashSockaddr(endpoint.toString()); }


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


