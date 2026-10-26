#include <UnitTest/UnitTest.hpp>

#include <Protocol/QUIC/Client.hpp>
#include <Protocol/QUIC/Server.hpp>
#include <Protocol/QUIC/Dispatcher.hpp>
#include <Protocol/QUIC/Configuration.hpp>

#include <Scheduler/Reactor.hpp>
#include <Scheduler/Fiber.hpp>
#include <Scheduler/After.hpp>

#include <memory>
#include <stdexcept>
#include <vector>

namespace Protocol
{
	namespace QUIC
	{
		using namespace UnitTest::Expectations;

		// Ends idle connections after half a second:
		class IdleConfiguration : public Configuration
		{
		public:
			void setup(ngtcp2_settings *settings, ngtcp2_transport_params *params) override
			{
				params->max_idle_timeout = NGTCP2_SECONDS / 2;
			}
		};

		// Thrown when a server keeps handling an expired timer, so that the test fails instead of spinning forever.
		struct Spinning {};

		class StreamlessServer : public Server
		{
		public:
			using Server::Server;

			std::size_t expiries = 0;

			void handle_expiry() override
			{
				Server::handle_expiry();

				// A connection handles a few timers over its lifetime, not thousands:
				if (++expiries > 1000) throw Spinning();
			}

		protected:
			Stream * create_stream(StreamID stream_id) override
			{
				(void)stream_id;
				return nullptr;
			}
		};

		class StreamlessDispatcher : public Dispatcher
		{
		public:
			using Dispatcher::Dispatcher;

			std::vector<std::unique_ptr<Server>> created_servers;
			std::vector<Server *> removed_servers;

			Server * create_server(Socket &socket, const Address &address, const ngtcp2_pkt_hd &packet_header) override
			{
				auto & server = created_servers.emplace_back(std::make_unique<StreamlessServer>(*this, _configuration, _tls_context, socket, address, packet_header));

				return server.get();
			}

			void remove(Server * server) override
			{
				Dispatcher::remove(server);

				removed_servers.push_back(server);
			}
		};

		// A client which completes the handshake and then goes away, neither sending anything nor closing the connection.
		class VanishingClient : public Client
		{
		public:
			using Client::Client;

			bool handshake = false;

			void handshake_completed() override
			{
				handshake = true;
			}

			// Drive the connection like `connect` does, but only until the handshake completes:
			void complete_handshake()
			{
				while (!handshake) {
					send_packets();

					if (receive_packets(*ngtcp2_conn_get_path(_connection)) != Status::OK) {
						throw std::runtime_error("Handshake failed!");
					}
				}

				// Send the rest of the handshake, so that the server completes it too:
				send_packets();
			}

		protected:
			Stream * create_stream(StreamID stream_id) override
			{
				(void)stream_id;
				return nullptr;
			}
		};

		UnitTest::Suite ServerTestSuite {
			"Protocol::QUIC::Server",

			{"it stops accepting once the connection ends by the idle timeout",
				[](UnitTest::Examiner & examiner) {
					Scheduler::Reactor::Bound bound;
					IdleConfiguration configuration;

					auto address = Address::resolve("localhost", "0").front();

					TLS::ServerContext tls_server_context;
					tls_server_context.load_certificate_file("Protocol/QUIC/server.pem");
					tls_server_context.load_private_key_file("Protocol/QUIC/server.key");
					tls_server_context.protocols().push_back("txt");

					TLS::ClientContext tls_client_context;
					tls_client_context.protocols().push_back("txt");

					StreamlessDispatcher dispatcher(configuration, tls_server_context);

					Socket server_socket(address.family());
					server_socket.bind(address);

					bool accept_returned = false;
					std::vector<std::unique_ptr<Scheduler::Fiber>> fibers;

					auto listening_fiber = std::make_unique<Scheduler::Fiber>("listening", [&] {
						// This fiber won't prevent the event loop from exiting.
						Scheduler::Fiber::current->transient = true;

						while (true) {
							auto server = dispatcher.listen(server_socket);

							if (server) {
								auto server_fiber = std::make_unique<Scheduler::Fiber>("server", [&, server] {
									try {
										server->accept();
										accept_returned = true;
									} catch (Spinning &) {
										// Reported by the expectations below.
									}
								});

								Scheduler::Reactor::current->transfer(server_fiber.get());

								fibers.push_back(std::move(server_fiber));
							}
						}
					});

					listening_fiber->transfer();

					fibers.push_back(std::move(listening_fiber));

					auto client_fiber = std::make_unique<Scheduler::Fiber>("client", [&] {
						Socket socket(address.family());
						socket.connect(server_socket.local_address());

						{
							VanishingClient client(configuration, tls_client_context, socket, server_socket.local_address());
							client.complete_handshake();
						}

						// Outlast the idle timeout, which is at least three probe timeouts:
						Scheduler::After after(3.0);
						after.wait();
					});

					client_fiber->transfer();

					fibers.push_back(std::move(client_fiber));

					bound.reactor.run();

					examiner.expect(dispatcher.created_servers.size()).to(be == 1);
					examiner.expect(dispatcher.removed_servers.size()).to(be >= 1);
					examiner.expect(accept_returned).to(be == true);
				}
			},
		};
	}
}
