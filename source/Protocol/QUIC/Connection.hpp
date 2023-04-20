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

#include <ngtcp2/ngtcp2.h>

namespace Protocol
{
	namespace QUIC
	{
		class Configuration;
		
		using Timestamp = ngtcp2_tstamp;
		using StreamDataFlags = std::uint32_t;
		using StreamID = std::int64_t;
		
		constexpr size_t DEFAULT_SCID_LENGTH = 18;
		
		Timestamp timestamp();
		
		const std::error_category & ngtcp2_category();
		
		class Connection
		{
		public:
			void generate_cid(ngtcp2_cid *cid, std::size_t length = DEFAULT_SCID_LENGTH);
			
			Connection(Configuration & configuration, ngtcp2_conn * connection = nullptr);
			virtual ~Connection();
			
			ngtcp2_conn * native_handle() {return _connection;}
			
			ngtcp2_connection_close_error last_error() const {return _last_error;}
			
			const ngtcp2_cid * client_initial_dcid();
			std::vector<ngtcp2_cid> scids();
			
			bool is_in_closing_period() const {return ngtcp2_conn_is_in_closing_period(_connection);}
			bool is_in_draining_period() const {return ngtcp2_conn_is_in_draining_period(_connection);}
			
			StreamID open_bidirectional_stream(void *user_data = nullptr);
			StreamID open_unidirectional_stream(void *user_data = nullptr);
			
			void receive_from(Socket & socket, std::size_t count = 1);
			
			void create_connection_id();
			
			virtual void handle_error();
			virtual void disconnect();
			
			virtual void handshake_completed();
			
			virtual void receive_stream_data(StreamDataFlags flags, StreamID stream_id, const Byte *buffer, std::size_t length, void * user_data);
			void write_stream_data(StreamID stream_id, const Byte *buffer, std::size_t length, StreamDataFlags flags = 0);
			
			virtual void generate_connection_id(ngtcp2_cid *cid, std::size_t length, uint8_t *token);
			
			void set_last_error(int result);
			
		protected:
			Configuration & _configuration;
			
			ngtcp2_conn *_connection = nullptr;
			ngtcp2_connection_close_error _last_error;
			
			Random _random;
			
			// Setup default callbacks and related settings.
			void setup(ngtcp2_callbacks *callbacks, ngtcp2_settings *settings, ngtcp2_transport_params *params);
		};
	}
}
