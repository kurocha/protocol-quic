//
//  Connection.hpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 17/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include "Stream.hpp"
#include "Socket.hpp"
#include "Random.hpp"
#include "TLS/Session.hpp"

#include <system_error>
#include <vector>
#include <unordered_map>
#include <memory>
#include <iosfwd>

#include <ngtcp2/ngtcp2.h>

namespace Protocol
{
	namespace QUIC
	{
		class Configuration;
		
		constexpr size_t DEFAULT_SCID_LENGTH = 8;
		
		ngtcp2_tstamp timestamp();
		
		template <typename ValueType>
		ValueType * extract_optional(std::optional<ValueType> value)
		{
			if (value) {
				return &*value;
			} else {
				return nullptr;
			}
		}
		
		const std::error_category & ngtcp2_category();
		
		// The Connection class is an abstract base class that defines the common interface for QUIC connections. It has Client and Server sub-classes. This class is used by the QUIC implementation to manage the state of a QUIC connection, and provides a common interface for both client and server connections.
		class Connection
		{
		public:
			void generate_cid(ngtcp2_cid *cid, std::size_t length = DEFAULT_SCID_LENGTH);
			
			Connection(Configuration & configuration, ngtcp2_conn * connection = nullptr);
			virtual ~Connection();
			
			ngtcp2_conn * native_handle() {return _connection;}
			
			enum class Status {
				OK = 0,
				
				RETRY = NGTCP2_ERR_RETRY,
				DROP = NGTCP2_ERR_DROP_CONN,
				
				DRAINING = NGTCP2_ERR_DRAINING,
				CLOSING = NGTCP2_ERR_CLOSING,
			};
			
			// Invoked when receiving a close frame or closing the connection.
			virtual void disconnect();
			
			// Send the close packet, and then invoke `disconnect()`.
			void close();
			
			virtual void handle_expiry();
			virtual Status handle_error(int result, std::string_view reason = "");
			
			ngtcp2_connection_close_error last_error() const {return _last_error;}
			
			const ngtcp2_cid * client_initial_dcid();
			std::vector<ngtcp2_cid> scids();
			
			bool is_closing() const {return ngtcp2_conn_is_in_closing_period(_connection);}
			bool is_draining() const {return ngtcp2_conn_is_in_draining_period(_connection);}
			
			std::optional<Timestamp> expiry_timeout();
			Time::Duration close_duration();
			
			std::uint64_t bidirectional_streams_available()
			{
				return ngtcp2_conn_get_streams_bidi_left(_connection);
			}
			
			std::uint64_t unidirectional_streams_available()
			{
				return ngtcp2_conn_get_streams_uni_left(_connection);
			}
			
			Stream* open_bidirectional_stream();
			Stream* open_unidirectional_stream();
			
			void create_connection_id();
			
			virtual void handshake_completed();
			
			// This is often used as an entry point to create new streams:
			virtual void extend_maximum_local_bidirectional_streams(std::uint64_t maximum_streams);
			virtual void extend_maximum_local_unidirectional_streams(std::uint64_t maximum_streams);
			
			virtual Stream* stream_open(StreamID stream_id);
			virtual void stream_close(Stream * stream, std::int32_t flags, std::uint64_t error_code);
			virtual void stream_reset(Stream * stream, std::size_t final_size, std::uint64_t error_code);
			void remove_stream(StreamID stream_id);
			
			virtual void generate_connection_id(ngtcp2_cid *cid, std::size_t length, uint8_t *token);
			
			void set_last_error(int result, std::string_view reason = "");
			
			Status send_packets();
			
			// Receive packets from the specified path.
			Status receive_packets(const ngtcp2_path & path, Socket & socket, std::size_t count = 1);
			Status receive_packets(const ngtcp2_path & path, std::size_t count = 1);
			
			virtual void print(std::ostream & output) const;
			
		protected:
			Configuration & _configuration;
			
			ngtcp2_conn *_connection = nullptr;
			ngtcp2_connection_close_error _last_error;
			
			Random _random;
			
			std::unordered_map<StreamID, Stream *> _streams;
			Stream *open_stream(StreamID stream_id);
			virtual Stream * create_stream(StreamID stream_id) = 0;
			
			// Setup default callbacks and related settings.
			void setup(ngtcp2_callbacks *callbacks, ngtcp2_settings *settings, ngtcp2_transport_params *params);
		};
		
		std::ostream & operator<<(std::ostream & output, const Connection & connection);
	}
}
