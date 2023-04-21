//
//  Client.cpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 5/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Client.hpp"
#include "Scheduler/Handle.hpp"

#include <Scheduler/After.hpp>
#include <Scheduler/Fiber.hpp>

#include <ngtcp2/ngtcp2.h>
#include <stdexcept>

#include <ngtcp2/ngtcp2_crypto.h>

namespace Protocol
{
	namespace QUIC
	{
		void Client::setup(TLS::ClientContext & tls_context, const ngtcp2_cid *dcid, const ngtcp2_cid *scid, const ngtcp2_path *path, std::uint32_t chosen_version, ngtcp2_settings *settings, ngtcp2_transport_params *params)
		{
			auto callbacks = ngtcp2_callbacks{};
			Connection::setup(&callbacks, settings, params);
			
			params->initial_max_streams_bidi = 3;
			params->initial_max_streams_uni = 3;
			params->initial_max_stream_data_bidi_local = 128 * 1024;
			params->initial_max_data = 1024 * 1024;
			
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
		
		void Client::connect()
		{
			auto path = ngtcp2_conn_get_path(_connection);
			Socket & socket = *static_cast<Socket *>(path->user_data);
			
			Scheduler::Fiber reader([&](){
				while (true) {
					read_packets(socket);
				}
			});
			
			Scheduler::After delay(0.1);
			
			while (true) {
				write_packets();
				delay.wait();
			}
		}
		
		// void Client::decode_early_transport_parameters(std::string_view buffer)
		// {
		// 	ngtcp2_conn_decode_early_transport_params(_connection, buffer.data(), buffer.size());
		// }
	}
}
