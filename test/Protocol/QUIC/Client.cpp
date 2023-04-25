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
#include <Protocol/QUIC/BufferedStream.hpp>

#include <Scheduler/Reactor.hpp>
#include <Scheduler/Fiber.hpp>
#include <Scheduler/After.hpp>

#include <memory>
#include <iostream>
#include <string_view>


namespace Protocol
{
	namespace QUIC
	{
		using namespace UnitTest::Expectations;
		
		class EchoStream : public BufferedStream
		{
		public:
			using BufferedStream::BufferedStream;
			
			void receive_data(std::size_t offset, const void *data, std::size_t size, std::uint32_t flags) override
			{
				std::cerr << *this << " Received " << size << " bytes: " << std::string_view((const char *)data, size) << std::endl;
				
				if (!_output_buffer.closed()) {
					// Echo the data:
					_output_buffer.append(data, size);
				}
				
				BufferedStream::receive_data(offset, data, size, flags);
			}
		};
		
		class EchoClient : public Client
		{
		public:
			using Client::Client;
			
			void handshake_completed() override
			{
				std::cerr << *this << " Handshake completed -> creating stream" << std::endl;
				BufferedStream *stream = dynamic_cast<BufferedStream*>(open_bidirectional_stream());
				stream->output_buffer().append("Hello World");
				stream->output_buffer().close();
			}
			
			std::unique_ptr<Stream> create_stream(StreamID stream_id) override
			{
				return std::make_unique<EchoStream>(*this, stream_id);
			}
		};
		
		class EchoServer : public Server
		{
		public:
			using Server::Server;
			
			std::unique_ptr<Stream> create_stream(StreamID stream_id) override
			{
				return std::make_unique<EchoStream>(*this, stream_id);
			}
		};
		
		class EchoBinding : public Binding
		{
		public:
			using Binding::Binding;
			
			std::unique_ptr<Server> create_server(Socket &socket, const Address &address, const ngtcp2_pkt_hd &packet_header) override
			{
				return std::make_unique<EchoServer>(this, _configuration, _tls_context, socket, address, packet_header);
			}
		};
		
		UnitTest::Suite ClientTestSuite {
			"Protocol::QUIC::Client",
			
			{"it should have some real tests",
				[](UnitTest::Examiner & examiner) {
					Scheduler::Reactor::Bound bound;
					Configuration configuration;
					
					auto addresses = Protocol::QUIC::Address::resolve("localhost", "4433");
					addresses.resize(1);
					
					Protocol::QUIC::TLS::ServerContext tls_server_context;
					tls_server_context.load_certificate_file("Protocol/QUIC/server.pem");
					tls_server_context.load_private_key_file("Protocol/QUIC/server.key");
					tls_server_context.protocols().push_back("txt");
					
					EchoBinding binding(configuration, tls_server_context);
					
					std::vector<std::unique_ptr<Scheduler::Fiber>> fibers;
					
					auto binding_fiber = std::make_unique<Scheduler::Fiber>("binding", [&] {
						Scheduler::After delay(0.001);
						while (true) {
							binding.send_packets();
							delay.wait();
						}
					});
					
					binding_fiber->transfer();
					
					for (auto & address : addresses) {
						std::cerr << "Listening on: " << address.to_string() << std::endl;
						std::string annotation = std::string("listening on ") + address.to_string();
						
						auto listening_fiber = std::make_unique<Scheduler::Fiber>(annotation, [&] {
							binding.listen(address);
						});
						
						listening_fiber->transfer();
						
						fibers.push_back(std::move(listening_fiber));
					}
					
					Protocol::QUIC::TLS::ClientContext tls_client_context;
					tls_client_context.protocols().push_back("txt");
					
					std::cerr << "Creating clients..." << std::endl;
					for (auto & address : addresses) {
						std::string annotation = std::string("connecting to ") + address.to_string();

						auto client_fiber = std::make_unique<Scheduler::Fiber>(annotation, [&] {
							Socket socket(address.family());
							socket.connect(address);
							
							EchoClient client(configuration, tls_client_context, socket, address);
							client.connect();
						});
						
						client_fiber->transfer();
						
						fibers.push_back(std::move(client_fiber));
					}
					
					bound.reactor.wait(1.0);
				}
			},
		};
	}
}
