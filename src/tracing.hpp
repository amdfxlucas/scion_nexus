#pragma once
// #define BOOST_ASIO_ENABLE_HANDLER_TRACKING
#include <source_location>
#include <boost/asio.hpp>

#define HANDLER_LOCATION \
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__))

  /*
  location = source_location::current()
   "file: "
              << location.file_name() << '('
              << location.line() << ':'
              << location.column() << ") `"
              << location.function_name() << "`: "
  */