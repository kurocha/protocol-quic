//
//  Server.cpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 5/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Server.hpp"
#include "Dispatcher.hpp"

#include <Scheduler/After.hpp>

#include <iostream>

#include "ngtcp2/ngtcp2.h"

namespace Protocol
{
	namespace QUIC
	{
		void Server::setup(TLS::ServerContext & tls_context, const ngtcp2_cid *dcid, const ngtcp2_cid *scid, const ngtcp2_path *path, uint32_t client_chosen_version, ngtcp2_settings *settings, ngtcp2_transport_params *params, const ngtcp2_mem *mem)
		{
			auto callbacks = ngtcp2_callbacks{};
			Connection::setup(&callbacks, settings, params);
			
			// Random::generate_secure(params->stateless_reset_token, sizeof(params->stateless_reset_token));
			// params->stateless_reset_token_present = 1;
			
			if (ngtcp2_conn_server_new(&_connection, dcid, scid, path, client_chosen_version, &callbacks, settings, params, mem, this)) {
				throw std::runtime_error("Failed to create QUIC server connection!");
			}
			
			_tls_session = std::make_unique<TLS::ServerSession>(tls_context, _connection);
		}
		
		Server::Server(Dispatcher & binding, Configuration & configuration, TLS::ServerContext & tls_context, Socket & socket, const Address & remote_address, const ngtcp2_pkt_hd & packet_header, ngtcp2_cid *ocid) : Connection(configuration), _binding(binding)
		{
			// Generate the server connection ID:
			generate_cid(&_scid);

			auto settings = ngtcp2_settings{};
			ngtcp2_settings_default(&settings);
			
			settings.token = packet_header.token;
			settings.tokenlen = packet_header.tokenlen;
			
			auto params = ngtcp2_transport_params{};
			ngtcp2_transport_params_default(&params);
			
			if (ocid) {
				params.original_dcid = *ocid;
				params.retry_scid = packet_header.dcid;
				params.retry_scid_present = 1;
			} else {
				params.original_dcid = packet_header.dcid;
				params.original_dcid_present = 1;
			}
			
			auto path = ngtcp2_path{
				.local = socket.local_address(),
				.remote = remote_address,
				.user_data = &socket,
			};
			
			setup(tls_context, &packet_header.scid, &_scid, &path, packet_header.version, &settings, &params);
		}
		
		Server::~Server()
		{
		}
		
		void Server::drain()
		{
			// Scheduler::After after(3.0 * ngtcp2_conn_get_pto(_connection) / NGTCP2_SECONDS);
			
			// after.wait();
			
			// _binding.remove(this);
		}
		
		void Server::close()
		{
			// Scheduler::After after(3.0 * ngtcp2_conn_get_pto(_connection) / NGTCP2_SECONDS);
			
			// after.wait();
			
			// _binding.remove(this);
		}
		
		void Server::process_packet(Socket & socket, const Address & remote_address, const Byte *data, std::size_t length, ECN ecn)
		{
			auto path = ngtcp2_path{
				.local = socket.local_address(),
				.remote = remote_address,
				.user_data = &socket,
			};
			
			auto packet_info = ngtcp2_pkt_info{
				.ecn = static_cast<uint32_t>(ecn),
			};
			
			auto result = ngtcp2_conn_read_pkt(_connection, &path, &packet_info, data, length, timestamp());
			
			if (result == 0) return;
			
			// Error handling:
			switch (result) {
				case NGTCP2_ERR_DRAINING:
					drain();

				case NGTCP2_ERR_RETRY:
				case NGTCP2_ERR_DROP_CONN:
					break;
					// TODO: Oops?
			}
			
			set_last_error(result);
			handle_error();
		}
		
		void Server::print(std::ostream & output) const
		{
			output << "<Server@" << this << ">";
		}
	}
}
