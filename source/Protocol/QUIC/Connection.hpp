//
//  Connection.hpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 17/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include "TLS/Session.hpp"

#include <ngtcp2/ngtcp2.h>
#include "Socket.hpp"

namespace Protocol
{
	namespace QUIC
	{
		using Timestamp = ngtcp2_tstamp;
		
		Timestamp timestamp();
		
		class Connection : public TLS::Handle
		{
		public:
			Connection(ngtcp2_conn * connection = nullptr);
			virtual ~Connection();
			
			ngtcp2_conn * native_handle() {return _connection;}
			virtual ngtcp2_conn * ngtcp2_connection() override {return _connection;}
			
			ngtcp2_connection_close_error last_error() const {return _last_error;}
			
			void receive_from(Socket & socket, std::size_t count = 1);
			
			virtual void handle_error();
			virtual void disconnect();
			
		protected:
			ngtcp2_conn *_connection;
			ngtcp2_connection_close_error _last_error;
		};
	}
}
