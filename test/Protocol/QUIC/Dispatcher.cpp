#include <UnitTest/UnitTest.hpp>

#include <Protocol/QUIC/Dispatcher.hpp>
#include <Protocol/QUIC/Server.hpp>
#include <Protocol/QUIC/Configuration.hpp>

#include <memory>
#include <stdexcept>
#include <vector>

namespace Protocol
{
	namespace QUIC
	{
		using namespace UnitTest::Expectations;

		class NullServer : public Server
		{
		public:
			using Server::Server;

		protected:
			Stream * create_stream(StreamID stream_id) override
			{
				(void)stream_id;
				return nullptr;
			}
		};

		// Keeps removed servers alive until the end of the test, like the Ruby binding which only frees them once they are garbage collected. A stale entry then routes packets to a removed server rather than crashing.
		class RecordingDispatcher : public Dispatcher
		{
		public:
			using Dispatcher::Dispatcher;

			std::vector<std::unique_ptr<Server>> created_servers;
			std::vector<Server *> removed_servers;

			Server * create_server(Socket &socket, const Address &address, const ngtcp2_pkt_hd &packet_header) override
			{
				auto & server = created_servers.emplace_back(std::make_unique<NullServer>(*this, _configuration, _tls_context, socket, address, packet_header));

				return server.get();
			}

			void remove(Server * server) override
			{
				Dispatcher::remove(server);

				removed_servers.push_back(server);
			}
		};

		// Delivers packets to a dispatcher as if they were received from a client on the loopback interface.
		class DispatcherHarness
		{
			Configuration _configuration;
			TLS::ServerContext _tls_context;
			Address _address;
			Socket _socket;

			// Anything the server sends back goes to this socket:
			Socket _client_socket;

		public:
			RecordingDispatcher dispatcher;

			DispatcherHarness() : _address(Address::resolve("localhost", "0").front()), _socket(_address.family()), _client_socket(_address.family()), dispatcher(_configuration, _tls_context)
			{
				_socket.bind(_address);
				_client_socket.bind(_address);
			}

			void deliver(const std::vector<Byte> & packet)
			{
				ngtcp2_version_cid version_cid;

				if (ngtcp2_pkt_decode_version_cid(&version_cid, packet.data(), packet.size(), DEFAULT_SCID_LENGTH) != 0) {
					throw std::runtime_error("Could not decode packet!");
				}

				dispatcher.process_packet(_socket, _client_socket.local_address(), packet.data(), packet.size(), ECN::UNSPECIFIED, version_cid);
			}
		};

		// Build a client Initial packet (QUIC version 1) which fills a datagram of the minimum size a server accepts. The payload is garbage, so the server can never decrypt it. The Length field covers the rest of the datagram, plus `excess_length` bytes which the datagram doesn't contain.
		std::vector<Byte> initial_packet(std::size_t excess_length = 0)
		{
			std::vector<Byte> packet;

			// Long header with the fixed bit set, packet type Initial:
			packet.push_back(0xc0);

			// Version 1:
			packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x01});

			// Destination connection ID:
			packet.push_back(8);
			packet.insert(packet.end(), {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});

			// Source connection ID:
			packet.push_back(8);
			packet.insert(packet.end(), {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});

			// Token length:
			packet.push_back(0x00);

			// Length, as a two byte variable-length integer:
			std::size_t length = NGTCP2_MAX_UDP_PAYLOAD_SIZE - packet.size() - 2 + excess_length;
			packet.push_back(static_cast<Byte>(0x40 | (length >> 8)));
			packet.push_back(static_cast<Byte>(length & 0xff));

			// Packet number and payload:
			packet.resize(NGTCP2_MAX_UDP_PAYLOAD_SIZE, 0x00);

			return packet;
		}

		UnitTest::Suite DispatcherTestSuite {
			"Protocol::QUIC::Dispatcher",

			{"it forgets a server whose first Initial packet can't be decrypted",
				[](UnitTest::Examiner & examiner) {
					DispatcherHarness harness;
					auto packet = initial_packet();

					harness.deliver(packet);

					examiner.expect(harness.dispatcher.created_servers.size()).to(be == 1);
					examiner.expect(harness.dispatcher.removed_servers.size()).to(be == 1);

					// The connection was dropped, so the same packet should start a new connection rather than being routed to the removed server:
					harness.deliver(packet);

					examiner.expect(harness.dispatcher.created_servers.size()).to(be == 2);
				}
			},

			{"it forgets a server whose first Initial packet is truncated",
				[](UnitTest::Examiner & examiner) {
					DispatcherHarness harness;

					// ngtcp2 drops this packet before it records the client's initial connection ID:
					auto packet = initial_packet(1);

					harness.deliver(packet);

					examiner.expect(harness.dispatcher.created_servers.size()).to(be == 1);
					examiner.expect(harness.dispatcher.removed_servers.size()).to(be == 1);

					// The connection was dropped, so the same packet should start a new connection rather than being routed to the removed server:
					harness.deliver(packet);

					examiner.expect(harness.dispatcher.created_servers.size()).to(be == 2);
				}
			},
		};
	}
}
