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
		
		class Buffer
		{
			bool _closed = false;
			
		public:
			void close() {_closed = true;}
			bool closed() const {return _closed;}
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
			
			// Write data to the buffer at the end of the buffer.
			void append(const void * data, std::size_t size)
			{
				_chunks.emplace_back(static_cast<const char *>(data), size);
			}
			
			void append(std::string_view data)
			{
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
				_data.erase(0, size);
			}
			
			const std::string & data() const noexcept {return _data;}
		};
		
		class Stream
		{
			StreamID _stream_id;
			InputBuffer _input_buffer;
			OutputBuffer _output_buffer;
			
		public:
			Stream(StreamID stream_id) : _stream_id(stream_id) {}
			~Stream() {}
			
			StreamID stream_id() const noexcept {return _stream_id;}
			
			// The application reads from the input buffer:
			InputBuffer & input_buffer() noexcept {return _input_buffer;}
			
			// The application writes to the output buffer:
			OutputBuffer & output_buffer() noexcept {return _output_buffer;}
		};
	}
}
