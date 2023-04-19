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
#include "TLS/Session.hpp"

#include <vector>

#include <ngtcp2/ngtcp2.h>


namespace Protocol
{
	namespace QUIC
	{
		using Timestamp = ngtcp2_tstamp;
		using StreamDataFlags = std::uint32_t;
		using StreamID = std::int64_t;
		
		Timestamp timestamp();
		
		class Connection : public TLS::Handle
		{
		public:
			ngtcp2_cid generate_cid(std::size_t length = NGTCP2_MAX_CIDLEN);
			
			Connection(ngtcp2_conn * connection = nullptr);
			virtual ~Connection();
			
			ngtcp2_conn * native_handle() {return _connection;}
			virtual ngtcp2_conn * ngtcp2_connection() override {return _connection;}
			
			ngtcp2_connection_close_error last_error() const {return _last_error;}
			
			void receive_from(Socket & socket, std::size_t count = 1);
			
			virtual void handle_error();
			virtual void disconnect();
			
			virtual void handshake_completed();
			virtual void receive_stream_data(StreamDataFlags flags, StreamID stream_id, const Byte *buffer, std::size_t length, void * user_data);
			
		protected:
			ngtcp2_conn *_connection;
			ngtcp2_connection_close_error _last_error;
			
			std::vector<Socket> _sockets;
			Socket & socket_for(const Address & remote_address);
			
			static int handshake_completed_callback(ngtcp2_conn *conn, void *user_data);
			static int receive_stream_data_callback(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t size, void *user_data, void *stream_user_data);
		};
	}
}
