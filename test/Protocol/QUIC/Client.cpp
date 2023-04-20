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
#include <Protocol/QUIC/Binding.hpp>
#include <Protocol/QUIC/Configuration.hpp>

#include <Scheduler/Reactor.hpp>
#include <Scheduler/Fiber.hpp>
#include <memory>

namespace Protocol
{
	namespace QUIC
	{
		using namespace UnitTest::Expectations;
		
		class EchoServer : public Server
		{
		public:
			using Server::Server;
			
			void receive_stream_data(StreamDataFlags flags, StreamID stream_id, const Byte *buffer, std::size_t length, void * user_data) override
			{
				std::cerr << "EchoServer::receive_stream_data: " << std::string((const char*)buffer, length) << std::endl;
				write_stream_data(stream_id, buffer, length);
			}
		};

		class EchoServerBinding : public Binding
		{
		public:
			using Binding::Binding;
			
			std::unique_ptr<Server> create_server(Socket &socket, const Address &address, const ngtcp2_pkt_hd &packet_header) override
			{
				return std::make_unique<EchoServer>(this, _configuration, _tls_context, socket, address, packet_header);
			}
		};
		
		class EchoClient : public Client
		{
		public:
			using Client::Client;
			
			void handshake_completed() override
			{
				std::cerr << "EchoClient::handshake_completed" << std::endl;
				
				auto stream_id = open_bidirectional_stream();
				
				write_stream_data(stream_id, (Byte*)"Hello World!", 12);
			}
			
			void receive_stream_data(StreamDataFlags flags, StreamID stream_id, const Byte *buffer, std::size_t length, void * user_data) override
			{
				std::cerr << "EchoClient::receive_stream_data: " << std::string((const char*)buffer, length) << std::endl;
			}
		};
		
		UnitTest::Suite ClientTestSuite {
			"Protocol::QUIC::Client",
			
			{"it should have some real tests",
				[](UnitTest::Examiner & examiner) {
					Scheduler::Reactor::Bound bound;
					Configuration configuration;
					
					auto addresses = Protocol::QUIC::Address::resolve("localhost", "4433");
					
					Protocol::QUIC::TLS::ServerContext tls_server_context;
					EchoServerBinding binding(configuration, tls_server_context);
					
					std::vector<std::unique_ptr<Scheduler::Fiber>> fibers;
					for (auto & address : addresses) {
						auto listening_fiber = std::make_unique<Scheduler::Fiber>([&] {
							binding.listen(address);
						});
						
						listening_fiber->resume();
						
						fibers.push_back(std::move(listening_fiber));
					}
					
					Protocol::QUIC::TLS::ClientContext tls_client_context;
					
					for (auto & address : addresses) {
						Scheduler::Fiber client_fiber([&]{
							Socket socket(address.family());
							socket.connect(address);
							
							EchoClient client(configuration, tls_client_context, socket, address);
						});
						
						client_fiber.resume();
					}
					
					bound.reactor.update(0);
				}
			},
		};
	}
}
