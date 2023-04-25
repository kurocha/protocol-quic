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
		class Connection;
		
		class Stream
		{
		protected:
			Connection & _connection;
			StreamID _stream_id;
			
		public:
			Stream(Connection &connection, StreamID stream_id) : _connection(connection), _stream_id(stream_id) {}
			virtual ~Stream();
			
			// The stream has received data and will append it to the input buffer.
			virtual void receive_data(std::size_t offset, const void * data, std::size_t size, std::uint32_t flags) = 0;
			virtual std::size_t send_data() = 0;
			
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
			
			StreamID stream_id() const noexcept {return _stream_id;}
		};
		
		std::ostream & operator<<(std::ostream & output, const Stream & stream);
	}
}
