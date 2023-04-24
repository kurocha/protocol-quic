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
		void Stream::receive_data(std::size_t offset, const void *data, std::size_t size, std::uint32_t flags)
		{
				// Append the data to the input buffer and mark it as closed if the FIN flag is set:
				_input_buffer.append(data, size);
				if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
					_input_buffer.close();
				}
				
				// Echo the data:
				{
					std::cerr << *this << " *** stream_data ***" << std::endl;
					auto data = _input_buffer.data();
					std::cerr << *this << " *** stream_data: " << data << " ***" << std::endl;
					_input_buffer.consume(data.size());
					
					// Echo:
					_output_buffer.append(data);
					send_data();
				}
		}
		
		std::size_t Stream::send_data()
		{
			ngtcp2_path_storage path_storage;
			ngtcp2_path_storage_zero(&path_storage);
			ngtcp2_pkt_info packet_info;
			ngtcp2_ssize written_length = 0;
			
			std::array<Byte, 1024*64> packet;
			
			StreamDataFlags flags = 0;
			if (_output_buffer.closed()) {
				flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
			}
			
			auto chunks = _output_buffer.chunks();
			
			while (true) {
				auto result = ngtcp2_conn_writev_stream(_connection.native_handle(), &path_storage.path, &packet_info, packet.data(), packet.size(), &written_length, flags, _stream_id, chunks.data(), chunks.size(), timestamp());
				
				if (result == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
					return 0;
				}
				
				if (result < 0) {
					throw std::system_error(result, ngtcp2_category(), "ngtcp2_conn_write_stream");
				}
				
				if (written_length > 0) {
					_output_buffer.increment(written_length);
				}
				
				if (result > 0) {
					auto & socket = *reinterpret_cast<Socket*>(path_storage.path.user_data);
					
					socket.send_packet(packet.data(), result, path_storage.path.remote, static_cast<ECN>(packet_info.ecn));
				}
				
				if (written_length > 0) {
					return written_length;
				}
				
				if (chunks.empty()) {
					return 0;
				}
			}
		}
		
		void Stream::close(std::uint32_t flags, std::uint64_t error_code)
		{
			_input_buffer.close();
			_output_buffer.close();
		}
		
		void Stream::shudown_read(std::uint64_t error_code)
		{
			ngtcp2_conn_shutdown_stream_read(_connection.native_handle(), _stream_id, error_code);
		}
		
		void Stream::shudown_write(std::uint64_t error_code)
		{
			ngtcp2_conn_shutdown_stream_read(_connection.native_handle(), _stream_id, error_code);
		}
		
		void Stream::shutdown(std::uint64_t error_code)
		{
			ngtcp2_conn_shutdown_stream(_connection.native_handle(), _stream_id, error_code);
		}
		
		std::ostream & operator<<(std::ostream & output, const Stream & stream)
		{
			output << "<Stream@" << &stream << " id=" << stream.stream_id() << ">";
			
			return output;
		}
	}
}
