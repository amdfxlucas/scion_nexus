
#pragma once

#include <arpa/inet.h>
#include <assert.h>
#include <iomanip>
#include <regex>
#include <sstream>
#include <expected>

#include "pan.hpp"

using  IA_t = uint64_t;
using AS_t = uint64_t;
using ISD_t = uint16_t;


#define AS_FROM_IA( ia ) ( ((uint64_t)ia<<16) >>16  )// ( (uint64_t)ia & 0xffffffffffff ) 
// get last 48bit of 64 bit IA that correspond to the AS
#define ISD_FROM_IA( ia ) (ia >> 48 )
 // get first 16 bit of 64 bit IA that correspond to ISD
#define _MAKE_IA_(isd, as) ((((uint64_t)isd) << 48) | ((uint64_t)as))

#define MAKE_BIG_IA(as,isd ) (  ( ( (uint64_t)as)<<16 ) | ( (uint64_t)isd )  )

namespace
{
constexpr void reverseBytes( const uint8_t* in, uint8_t* out, const uint64_t bytes )
{
    for(int i=0;i< bytes;++i)
      out[i] = in[ bytes-i-1];
}

constexpr uint64_t reverseEndian( uint64_t little )
{
    uint64_t result;

    reverseBytes( (uint8_t*)&little, (uint8_t*)&result,8 );
    return result;
}



bool
inline isValidIPv4(const char* IPAddress)
{
    int a, b, c, d;
    return sscanf(IPAddress, "%d.%d.%d.%d", &a, &b, &c, &d) == 4;
}

bool
inline is_ipv6_address(const char* str)
{
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, str, &(sa.sin6_addr)) != 0;
}

// this should move to string-utils.h
std::vector<std::string>
inline tokenize(const std::string str, const std::regex re)
{
    std::sregex_token_iterator it{str.begin(), str.end(), re, -1};
    std::vector<std::string> tokenized{it, {}};

    // Additional check to remove empty strings
    tokenized.erase(std::remove_if(tokenized.begin(),
                                   tokenized.end(),
                                   [](const std::string& s) { return s.size() == 0; }),
                    tokenized.end());

    return tokenized;
}

} // namespace


constexpr inline std::string paddTo4( std::string x)
{    
    return std::format("{:0>4}", x);    
}


// converts the AS part of a SCION Address i.e. 19-faa:1:1067,192.168.127.1
// "ffaa:1:106" first into a hexadecimal number 0xffaa00010106 and then to integer

AS_t
inline AsFromDottedHex(const std::string& str)
{
    auto token = tokenize(str, std::regex{R"([:]+)"});

    std::stringstream ss;

    std::stringstream hexStr;
    hexStr << "0x";
    hexStr << std::setfill('0') << std::setw(4); //<< "0x";
    for (const auto& t : token)
    {
        
        hexStr << paddTo4(t);
        
    }
    AS_t x;
    // std::cout <<"hexStr: "<< hexStr.str() << std::endl;
    ss << std::hex << hexStr.str();
    ss >> x;
    return x;
}

// TODO: add bool parameter "emit all zeros"
// as is a 64 bit number ( )
std::string
inline ASToDottedHex(AS_t as)
{
    std::stringstream result;
    std::stringstream ss;
    ss << std::hex << (as);

    bool begin = true;
    int encounteredZerosInRow = 0;
    for (int pos = 0; auto s : ss.str())
    {
        // the !begin is for the codepath that we last encountered 4 zeros in a row( and dont emit a
        // second ':' )
        if (pos != 0 && pos % 4 == 0 && !begin)
        {
            result << ":";
            encounteredZerosInRow = 0;
            begin = true;
            // ++pos;

            // continue;
        }
        // trim leading zeros
        if (begin)
        {
            if (s == '0')
            {
                ++pos;
                ++encounteredZerosInRow;
                //    std::cout << "zeros in row: " << encounteredZerosInRow << std::endl;
                if (encounteredZerosInRow == 4)
                {
                    //       std::cout << "4 zeros  in row" << std::endl;
                    result << '0' << ':';
                    begin = true;
                    encounteredZerosInRow = 0;
                }
                // do not emit leading zeros
                // and leave begin at true
                // break;
                continue;
            }
            else
            {
                result << s;
                encounteredZerosInRow = 0;
                begin = false;
                pos++;
            }
        }
        else
        {
            // leave begin at false
            result << s;
            ++pos;
        }
    }

    return result.str();
}


std::string
inline ASToDottedHexFull(AS_t as)
{
    std::stringstream result;
    std::stringstream ss;
    ss << std::hex << (as);

    for (int pos = 0; auto s : ss.str())
    {
        
        if (pos != 0 && pos % 4 == 0 )
        {
            result << ":";                                         
        }
            result << s;
            ++pos;        
    }

    return result.str();
}

inline
std::tuple< IA_t,uint16_t,uint64_t,std::string, uint16_t > 
parseScionImpl( const std::string& hostScionAddr,const std::string& portstr ="0" )
{
 uint16_t port;
    IA_t ia;
    uint64_t as;
    uint16_t iisd;
    std::string host;
     //  std::string ipv6reg =
  //  "((?:((?:[0-9A-Fa-f]{1,4}:){1,6}:)|(?:(?:[0-9A-Fa-f]{1,4}:){7}))(?:[0-9A-Fa-f]{1,4}))";
    //"((([0-9A-Fa-f]{1,4}:){1,6}:)|(([0-9A-Fa-f]{1,4}:){7}))([0-9A-Fa-f]{1,4})";
    //    std::regex scionRegex{"^(\\d+)-([\\d:A-Fa-f]+),([^:]+|\\[" +ipv6reg
    //    +"\\]])(?::(\\d+))?$"}; // (?<=:)(\\d+)?$

    std::regex scionRegex{
        "^(?:(\\d+)-([\\d:A-Fa-f]+)),(?:\\[([^\\]]+)\\]|([^\\[\\]:]+))(?::(\\d+))?$"};
    // host part  (?:\[([^\]]+)\]|([^\[\]:]+))(?::(\d+))

    std::smatch pieces_match;

    if (std::regex_match( hostScionAddr, pieces_match, scionRegex))
    {
        auto isd = pieces_match[1].str();
        as = AsFromDottedHex(pieces_match[2].str());
        iisd = std::stoi(isd);

        //ia = MAKE_BIG_IA(as,iisd); 
        ia = _MAKE_IA_(iisd, as);

        host = pieces_match[3].str();
        if (host.empty())
        {
            host = pieces_match[4].str();
        }

  /*      if (isValidIPv4(host.c_str()))
        {
            //  std::stringstream ss;
           //   ss << host;
           //   Ipv4Address ip;
           //   ss >>ip;
          //    _hostAddr = ip;
         //     // _hostAddr = Ipv4Address(host.c_str());
           
            _hostAddr = Ipv4Address(ntohl(inet_addr(host.c_str())));

            addrType = AddrType_t::T4Ip;
        }
        else if (is_ipv6_address(host.c_str()))
        {
            _hostAddr = Ipv6Address(host.c_str());
            addrType = AddrType_t::T16Ip;
        }
        else // TODO service addresses
        {
            assert(false);
        }
*/
        if (pieces_match.size() > 5 && !pieces_match[5].str().empty())
        {    port = std::stoi(pieces_match[5].str());
        }else
        {
            port = std::stoi( portstr );
        }
    }
    else
    {
        assert(false);// ," cannot construct SCIONAddress from invalid String: ");// << hostScionAddr );
    }

    return {ia,iisd,as,host,port};
}

/*
  19-ffaa:0:1067,192.168.1.1:8080
  submatch 0: 19-ffaa:0:1067,192.168.1.1:8080
  submatch 1: 19
  submatch 2: ffaa:0:1067
  submatch 3: 192.168.1.1
  submatch 4: 8080*/
  
inline std::expected<Pan::udp::Endpoint,boost::system::error_code>
 ParseScionEndpoint( std::string hostScionAddr, std::string portstr = "0")
{
   auto [ia,isd,as,host,port ] = parseScionImpl( hostScionAddr,portstr);
    
    boost::system::error_code ec;
    if( auto addr = boost::asio::ip::make_address(host,ec); ec )
    {
        return std::unexpected(ec);
    }else
    {
        //uint64_t ia_big;
        //reverseBytes( (uint8_t*)&ia, (uint8_t*)&ia_big,8);
        //return Pan::udp::Endpoint(ia_big, std::move(addr) ,port );

        return Pan::udp::Endpoint( reverseEndian(ia), std::move(addr) ,port );
    }
}