//
//  Client.cpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 5/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Client.hpp"
#include "BufferedStream.hpp"

#include <stdexcept>
#include <iostream>

#include "Scheduler/Handle.hpp"
#include <Scheduler/After.hpp>
#include <Scheduler/Fiber.hpp>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

namespace Protocol
{
	namespace QUIC
	{
		void Client::setup(TLS::ClientContext & tls_context, const ngtcp2_cid *dcid, const ngtcp2_cid *scid, const ngtcp2_path *path, std::uint32_t chosen_version, ngtcp2_settings *settings, ngtcp2_transport_params *params)
		{
			auto callbacks = ngtcp2_callbacks{};
			Connection::setup(&callbacks, settings, params);
			
			if (ngtcp2_conn_client_new(&_connection, dcid, scid, path, chosen_version, &callbacks, settings, params, nullptr, this)) {
				throw std::runtime_error("Failed to create QUIC client connection!");
			}
			
			_tls_session = std::make_unique<TLS::ClientSession>(tls_context, _connection);
		}
		
		Client::Client(Configuration & configuration, TLS::ClientContext & tls_context, Socket &socket, const Address &remote_address, std::uint32_t chosen_version) : Connection(configuration)
		{
			ngtcp2_cid dcid, scid;
			generate_cid(&dcid);
			generate_cid(&scid);
			
			ngtcp2_path path = {
				.local = socket.local_address(),
				.remote = remote_address,
				.user_data = &socket,
			};
			
			socket.annotate("client");
			
			auto settings = ngtcp2_settings{};
			ngtcp2_settings_default(&settings);
			
			auto params = ngtcp2_transport_params{};
			ngtcp2_transport_params_default(&params);
			
			setup(tls_context, &dcid, &scid, &path, chosen_version, &settings, &params);
		}
		
		Client::~Client()
		{
		}
		
		void Client::extend_maximum_local_bidirectional_streams(std::uint64_t maximum_streams)
		{
		}
		
		void Client::drain()
		{
			auto duration = close_duration();
			
			Scheduler::After after(duration);
			
			after.wait();
		}
		
		void Client::connect()
		{
			while (true) {
				send_packets();
				
				auto path = ngtcp2_conn_get_path(_connection);
				assert(path);
				
				auto status = receive_packets(*path);
				
				if (status == Status::DRAINING || status == Status::CLOSING) {
					// We can immediately disconnect.
					return;
				}
			}
		}
		
		// void Client::decode_early_transport_parameters(std::string_view buffer)
		// {
		// 	ngtcp2_conn_decode_early_transport_params(_connection, buffer.data(), buffer.size());
		// }
		
		void Client::print(std::ostream & output) const
		{
			output << "<Client@" << this << ">";
		}
	}
}
