//
//  BufferedStream.cpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 24/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "BufferedStream.hpp"
#include "Connection.hpp"

#include <iostream>

namespace Protocol
{
	namespace QUIC
	{
		BufferedStream::BufferedStream(Connection & connection, StreamID stream_id) : Stream(connection, stream_id)
		{
		}
		
		BufferedStream::~BufferedStream()
		{
		}
		
		void BufferedStream::receive_data(std::size_t offset, const void *data, std::size_t size, std::uint32_t flags)
		{
			_input_buffer.append(data, size);
			
			if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
				_input_buffer.close();
			}
			
			send_data();
		}
		
		Stream::Status BufferedStream::send_data()
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
				
				if (result == NGTCP2_ERR_STREAM_SHUT_WR) {
					_output_buffer.close();
				}
				
				if (result < 0) {
					return Status(result);
				}
				
				if (written_length > 0) {
					_output_buffer.increment(written_length);
				}
				
				if (result > 0) {
					auto & socket = *reinterpret_cast<Socket*>(path_storage.path.user_data);
					
					socket.send_packet(packet.data(), result, path_storage.path.remote, static_cast<ECN>(packet_info.ecn));
				}
				
				if (written_length > 0 || chunks.empty()) {
					break;
				}
			}
			
			return Status::OK;
		}
		
		void BufferedStream::acknowledge_data(std::size_t length)
		{
			_output_buffer.acknowledge(length);
		}
		
		void BufferedStream::close(std::uint32_t flags, std::uint64_t error_code)
		{
			_input_buffer.close();
			_output_buffer.close();
			
			Stream::close(flags, error_code);
		}
		
		void BufferedStream::reset(std::size_t final_size, std::uint64_t error_code)
		{
			_output_buffer.close(error_code);
		}
		
		void BufferedStream::stop_sending(std::uint64_t error_code)
		{
			_input_buffer.close(error_code);
		}
	}
}
