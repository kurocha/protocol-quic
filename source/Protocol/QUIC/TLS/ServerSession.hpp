//
//  ServerSession.hpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 18/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include "Session.hpp"
#include "ServerContext.hpp"

#include <string_view>
#include <vector>

namespace Protocol
{
	namespace QUIC
	{
		namespace TLS
		{
			class ServerSession : public Session
			{
			public:
				ServerSession(ServerContext &server_context, ngtcp2_conn *connection);
				virtual ~ServerSession();
				
			private:
				
			};
		}
	}
}
