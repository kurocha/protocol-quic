//
//  Client.cpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 17/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include <UnitTest/UnitTest.hpp>

#include <Protocol/QUIC/Client.hpp>
#include <Protocol/QUIC/Server.hpp>

#include <Scheduler/Reactor.hpp>
#include <Scheduler/Fiber.hpp>
#include <memory>

namespace Protocol
{
	namespace QUIC
	{
		using namespace UnitTest::Expectations;
		
		UnitTest::Suite ClientTestSuite {
			"Protocol::QUIC::Client",
			
			{"it should have some real tests",
				[](UnitTest::Examiner & examiner) {
					Scheduler::Reactor::Bound bound;
					
					auto addresses = Protocol::QUIC::Address::resolve("localhost", "4433");
					
					auto tls_server_context = std::make_shared<Protocol::QUIC::TLS::ServerContext>();
					Protocol::QUIC::Server server(tls_server_context);
					
					std::vector<std::unique_ptr<Scheduler::Fiber>> fibers;
					for (auto & address : addresses) {
						auto fiber = std::make_unique<Scheduler::Fiber>([&] {
							server.listen(address);
						});
						
						fiber->resume();
						
						fibers.push_back(std::move(fiber));
					}
					
					// {
					// 	auto tls_client_context = std::make_shared<Protocol::QUIC::TLS::ClientContext>();
					// 	Protocol::QUIC::Client client(tls_client_context);
						
					// 	Scheduler::Fiber connect_fiber([&] {
					// 		client.connect(addresses[0]);
					// 	});
						
					// 	connect_fiber.resume();
						
					// 	auto stream_id = client->open_bidirectional_stream();
						
					// 	client->write(stream_id, "Hello World!", 12);
					// 	client->read(stream_id, 12);
					// }
					
					bound.reactor.update(0);
				}
			},
		};
	}
}
