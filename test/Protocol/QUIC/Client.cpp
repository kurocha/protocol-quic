//
//  Client.cpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 17/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Protocol/QUIC/TLS/ServerContext.hpp"
#include <UnitTest/UnitTest.hpp>

#include <Protocol/QUIC/Client.hpp>
#include <Protocol/QUIC/Server.hpp>

namespace Protocol
{
	namespace QUIC
	{
		using namespace UnitTest::Expectations;
		
		UnitTest::Suite ClientTestSuite {
			"Protocol::QUIC::Client",
			
			{"it should have some real tests",
				[](UnitTest::Examiner & examiner) {
					auto addresses = Protocol::QUIC::Address::resolve("localhost", "4433");
					
					auto tls_server_context = std::make_shared<Protocol::QUIC::TLS::ServerContext>();
					Protocol::QUIC::Server server(tls_server_context);
					
					for (auto & address : addresses) {
						server.listen(address);
					}
					
					auto tls_client_context = std::make_shared<Protocol::QUIC::TLS::ClientContext>();
					Protocol::QUIC::Client client(tls_client_context);
				}
			},
		};
	}
}
