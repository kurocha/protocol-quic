//
//  ServerSession.cpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 18/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "ServerSession.hpp"

#include <stdexcept>

namespace Protocol
{
	namespace QUIC
	{
		namespace TLS
		{
			ServerSession::ServerSession(ServerContext &server_context, ngtcp2_conn *connection) : Session(server_context, connection)
			{
				_context.ptls = ptls_server_new(server_context.native_handle());
				
				if (_context.ptls == nullptr) {
					throw std::runtime_error("Could not create server session!");
				}
				
				set_connection_reference();
				setup_extensions();
				
				if (ngtcp2_crypto_picotls_configure_server_session(&_context)) {
					throw std::runtime_error("Could not configure server session!");
				}
			}
			
			ServerSession::~ServerSession()
			{
			}
		}
	}
}
