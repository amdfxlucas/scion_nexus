
#pragma once
#include <source_location>
#include <iostream>

#ifndef NDEBUG

#define qDebug( _msg_ ) std::cout << _msg_ << std::endl

// l is for source Location
#define qlDebug(_msg_) std::cout<<  std::source_location::current().file_name() \
                << "("<< std::source_location::current().line() << ":" \
              << std::source_location::current().column() << ") `"  \
              << std::source_location::current().function_name() << "`: " \
              << _msg_ << std::endl

#define QDEBUG( _msg_ ) std::cout << _msg_ << std::endl

#elif

#define qlDebug( _msg_ ) (void)0
#define qDebug(_msg_) (void)(0)
#define QDEBUG(_msg_) (void)(0) 



#endif