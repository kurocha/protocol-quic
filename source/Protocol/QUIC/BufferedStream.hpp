//
//  BufferedStream.hpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 24/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include "Stream.hpp"

#include <stdexcept>

namespace Protocol
{
	namespace QUIC
	{
		class Buffer
		{
			// Whether the buffer is closed or not.
			bool _closed = false;
			
			// The error code associated with the buffer, if any.
			// May be set when the buffer is closed.
			std::uint64_t _error_code = 0;
			
		public:
		// Close the buffer.
			void close() {_closed = true;}
			
			// Close the buffer and set the error code.
			void close(std::uint64_t error_code) {close(); _error_code = error_code;}
			
			// Check if the buffer is closed.
			bool closed() const {return _closed;}
			
			// Get the error code associated with the buffer (only valid if closed).
			std::uint64_t error_code() const {return _error_code;}
		};
		
		class OutputBuffer final : public Buffer
		{
			std::vector<std::string> _chunks;
			std::size_t _acknowledged = 0;
			std::size_t _offset = 0;
			
		public:
			OutputBuffer() {}
			~OutputBuffer() {}
			
			// Acknowledge that size bytes are now completely written to the remote peer and can be discarded.
			void acknowledge(std::size_t size)
			{
				size += _acknowledged;
				
				for (auto iterator = _chunks.begin(); iterator != _chunks.end(); ++iterator) {
					auto & chunk = *iterator;
					
					if (size >= chunk.size()) {
						size -= chunk.size();
					} else {
						_acknowledged = size;
						_chunks.erase(_chunks.begin(), iterator);
						break;
					}
				}
			}
			
			void stop_sending()
			{
				close();
				_chunks.clear();
			}
			
			// Write data to the buffer at the end of the buffer.
			void append(const void * data, std::size_t size)
			{
				append(std::string_view(reinterpret_cast<const char*>(data), size));
			}
			
			void append(std::string_view data)
			{
				if (closed())
					throw std::runtime_error("Cannot append to closed buffer!");
				
				_chunks.emplace_back(data);
			}
			
			std::vector<ngtcp2_vec> chunks()
			{
				std::vector<ngtcp2_vec> result;
				result.reserve(_chunks.size());
				
				std::size_t start = 0;
				
				for (auto & chunk : _chunks) {
					auto end = start + chunk.size();
					
					// The chunk is before the offset, so we can skip it completely:
					if (end <= _offset) continue;
					
					if (start < _offset) {
						// The chunk intersects the offset, so we need to skip the start of it:
						auto delta = _offset - start;
						result.emplace_back(ngtcp2_vec{
							reinterpret_cast<uint8_t*>(chunk.data()) + delta,
							chunk.size() - delta
						});
					}
					else {
						// The chunk is after the offset, so we can use it as is:
						result.emplace_back(ngtcp2_vec{
							reinterpret_cast<uint8_t*>(chunk.data()),
							chunk.size()
						});
					}
				}
				
				return result;
			}
			
			// Mark size bytes as written to the network. We won't try to write those bytes again.
			void increment(std::size_t size)
			{
				_offset += size;
			}
		};
		
		class InputBuffer final : public Buffer
		{
			std::string _data;
			
		public:
			InputBuffer() {}
			~InputBuffer() {}
			
			void append(const void * data, std::size_t size)
			{
				_data.append(static_cast<const char *>(data), size);
			}
			
			void consume(std::size_t size)
			{
				if (size > _data.size())
					throw std::runtime_error("Cannot consume more data than is available!");
				
				_data.erase(0, size);
			}
			
			const std::string & data() const noexcept {return _data;}
		};
		
		// The BufferedStream class extends the Stream class to add buffering capabilities. It maintains an input buffer and an output buffer for the stream.
		class BufferedStream : public Stream
		{
		protected:
			InputBuffer _input_buffer;
			OutputBuffer _output_buffer;
			
		public:
			BufferedStream(Connection & connection, StreamID stream_id);
			virtual ~BufferedStream();
			
			// Receive data from the QUIC stream and append it to the input buffer.
			void receive_data(std::size_t offset, const void *data, std::size_t size, std::uint32_t flags) override;
			
			// Send data from the output buffer to the QUIC stream.
			// @returns the number of bytes sent.
			Status send_data() override;
			
			// Acknowledge receipt of data up to a given length.
			void acknowledge_data(std::size_t length) override;
			
			// Close the stream with the given flags and error code.
			void close(std::uint32_t flags, std::uint64_t error_code) override;
			
			// Reset the stream with the given final size and error code.
			void reset(std::size_t final_size, std::uint64_t error_code) override;
			
			// Stop sending data on the stream with the given error code.
			void stop_sending(std::uint64_t error_code) override;
			
			// Get a reference to the input buffer for the stream.
			// The application reads from the input buffer.
			InputBuffer & input_buffer() noexcept {return _input_buffer;}
			
			// Get a reference to the output buffer for the stream.
			// The application writes to the output buffer.
			OutputBuffer & output_buffer() noexcept {return _output_buffer;}
		};
	}
}
