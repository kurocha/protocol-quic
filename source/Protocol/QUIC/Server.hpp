//
//  Server.hpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 5/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include <memory>

#include "Connection.hpp"
#include "TLS/ServerSession.hpp"

namespace Protocol
{
	namespace QUIC
	{
		class Server : public Connection
		{
		public:
			Server();
			virtual ~Server();
			
		private:
			std::shared_ptr<TLS::ServerContext> _tls_context;

		};
	}
}
