//
//  Stream.cpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 5/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Stream.hpp"
#include "Connection.hpp"

#include <iostream>

namespace Protocol
{
	namespace QUIC
	{
		Stream::~Stream()
		{
		}
		
		void Stream::extend_maximum_data(std::size_t maximum_data)
		{
			send_data();
		}
		
		void Stream::close(std::uint32_t flags, std::uint64_t error_code)
		{
		}
		
		void Stream::reset(std::size_t final_size, std::uint64_t error_code)
		{
		}
		
		void Stream::shudown_read(std::uint64_t error_code)
		{
			ngtcp2_conn_shutdown_stream_read(_connection.native_handle(), _stream_id, error_code);
		}
		
		void Stream::shudown_write(std::uint64_t error_code)
		{
			ngtcp2_conn_shutdown_stream_write(_connection.native_handle(), _stream_id, error_code);
		}
		
		void Stream::shutdown(std::uint64_t error_code)
		{
			ngtcp2_conn_shutdown_stream(_connection.native_handle(), _stream_id, error_code);
		}
		
		void Stream::stop_sending(std::uint64_t error_code)
		{
		}
		
		std::ostream & operator<<(std::ostream & output, const Stream & stream)
		{
			output << "<Stream@" << &stream << " connection=" << stream.connection() << " id=" << stream.stream_id() << ">";
			
			return output;
		}
	}
}
