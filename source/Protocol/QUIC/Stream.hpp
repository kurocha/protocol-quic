//
//  Stream.hpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 5/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include <vector>
#include <string>

#include <ngtcp2/ngtcp2.h>

namespace Protocol
{
	namespace QUIC
	{
		using StreamID = std::int64_t;
		using StreamDataFlags = std::uint32_t;
		
		class Connection;
		
		// The Stream class represents a QUIC stream, which is a unidirectional or bidirectional sequence of data within a QUIC connection. This class is used by the QUIC implementation to manage individual streams within a connection.
		class Stream
		{
		protected:
			Connection & _connection;
			StreamID _stream_id;
			
		public:
			Stream(Connection &connection, StreamID stream_id) : _connection(connection), _stream_id(stream_id) {}
			virtual ~Stream();
			
			enum class Status {
				OK = 0,
				
				// The stream does not exist:
				NOT_FOUND = NGTCP2_ERR_STREAM_NOT_FOUND,
				
				// The stream is half closed (local); or stream is being reset:
				SHUTDOWN_WRITE = NGTCP2_ERR_STREAM_SHUT_WR,
				
				// The total length of stream data is too large:
				INVALID_ARGUMENT = NGTCP2_ERR_INVALID_ARGUMENT,
				
				// Stream is blocked because of flow control:
				DATA_BLOCKED = NGTCP2_ERR_STREAM_DATA_BLOCKED,
				
				// Out of memory:
				NO_MEMORY = NGTCP2_ERR_NOMEM,
				
				// User callback failed:
				CALLBACK_FAILURE = NGTCP2_ERR_CALLBACK_FAILURE,
				
				// Packet number is exhausted, and cannot send any more packet:
				PACKET_NUMBER_EXHAUSTED = NGTCP2_ERR_PKT_NUM_EXHAUSTED,
			};
			
			// Indicates the stream has been disconnected due to a connection failure.
			virtual void disconnect();
			
			// The stream has received data and will append it to the input buffer.
			virtual void receive_data(std::size_t offset, const void * data, std::size_t size, StreamDataFlags flags) = 0;
			virtual Status send_data() = 0;
			
			virtual void acknowledge_data(std::size_t length) = 0;
			virtual void extend_maximum_data(std::size_t maximum_data);
			
			// The stream has been closed by the remote peer.
			virtual void close(std::uint32_t flags, std::uint64_t error_code);
			
			// The stream has been reset by the remote peer before receiving all data.
			// @parameter final_size is the number of bytes that were received before the stream was reset.
			virtual void reset(std::size_t final_size, std::uint64_t error_code);
			
			// Shutdown the read and write sides of the stream.
			void shutdown(std::uint64_t error_code = 0);
			
			// Shutdown the read end of the stream. The application will not receive any more data and the remote stream will receive `stop_sending`.
			void shudown_read(std::uint64_t error_code = 0);
			
			// Shutdown the write end of the stream. The application will not be able to write any more data and the remote stream will receive `reset`. Use `output_buffer.close()` if you intend to close the stream gracefully.
			void shudown_write(std::uint64_t error_code = 0);
			
			// Stop sending data to the remote peer.
			virtual void stop_sending(std::uint64_t error_code = 0);
			
			Connection & connection() noexcept {return _connection;}
			const Connection & connection() const noexcept {return _connection;}
			
			StreamID stream_id() const noexcept {return _stream_id;}
		};
		
		std::ostream & operator<<(std::ostream & output, const Stream & stream);
	}
}
