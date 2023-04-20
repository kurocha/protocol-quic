//
//  ServerSession.cpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 18/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "ServerSession.hpp"

namespace Protocol
{
	namespace QUIC
	{
		namespace TLS
		{
			ServerSession::ServerSession(ServerContext &server_context, ngtcp2_conn *connection) : Session(server_context, connection)
			{
				_context.ptls = ptls_server_new(server_context.native_handle());
				set_connection_reference();
			}
			
			ServerSession::~ServerSession()
			{
			}
		}
	}
}
