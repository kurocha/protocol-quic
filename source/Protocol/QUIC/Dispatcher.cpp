//
//  Dispatcher.cpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 20/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Dispatcher.hpp"
#include "Server.hpp"

#include <array>
#include <ngtcp2/ngtcp2.h>
#include <stdexcept>
#include <iostream>
#include <memory>

namespace Protocol
{
	namespace QUIC
	{
		Dispatcher::Dispatcher(Configuration & configuration, TLS::ServerContext & tls_context) : _configuration(configuration), _tls_context(tls_context)
		{
		}
		
		Dispatcher::~Dispatcher()
		{
			std::cerr << "Dispatcher going out of scope..." << std::endl;
		}
		
		std::string cid_key(const Byte * cid, std::size_t length)
		{
			return std::string(reinterpret_cast<const char *>(cid), length);
		}
		
		void Dispatcher::associate(const ngtcp2_cid *cid, Server * server)
		{
			_servers.emplace(cid_key(cid->data, cid->datalen), server);
		}
		
		void Dispatcher::disassociate(const ngtcp2_cid *cid)
		{
			_servers.erase(cid_key(cid->data, cid->datalen));
		}
		
		void Dispatcher::remove(Server * server)
		{
			disassociate(server->client_initial_dcid());
			
			auto scids = server->scids();
			for (auto & scid : scids) {
				disassociate(&scid);
			}
			
			delete server;
		}
		
		void Dispatcher::send_packets()
		{
			for (auto & server : _servers) {
				server.second->send_packets();
			}
		}
		
		void Dispatcher::listen(Socket &socket)
		{
			Address remote_address;
			ECN ecn = ECN::UNSPECIFIED;
			std::array<Byte, 1024*64> buffer;
			
			while (socket) {
				auto length = socket.receive_packet(buffer.data(), buffer.size(), remote_address, ecn);
				
				ngtcp2_version_cid version_cid;
				auto result = ngtcp2_pkt_decode_version_cid(&version_cid, buffer.data(), length, DEFAULT_SCID_LENGTH);
				
				if (result == 0) {
					process_packet(socket, remote_address, buffer.data(), length, ecn, version_cid);
				}
				else if (result == NGTCP2_ERR_VERSION_NEGOTIATION) {
					send_version_negotiation(socket, version_cid, remote_address);
				}
				else {
					std::cerr << "listen: " << ngtcp2_strerror(result) << std::endl;
				}
			}
		}
		
		void Dispatcher::process_packet(Socket & socket, const Address &remote_address, const Byte * data, std::size_t length, ECN ecn, ngtcp2_version_cid &version_cid)
		{
			auto dcid_key = cid_key(version_cid.dcid, version_cid.dcidlen);
			auto iterator = _servers.find(dcid_key);
			
			if (iterator == std::end(_servers)) {
				ngtcp2_pkt_hd packet_header;
				// The incoming packet is for a new connection.
				auto result = ngtcp2_accept(&packet_header, data, length);
				
				if (result != 0) {
					std::cerr << "process_packet: " << ngtcp2_strerror(result) << std::endl;
					return;
				}
				
				// TODO: Stateless retry.
				auto server = this->create_server(socket, remote_address, packet_header);
				server->process_packet(socket, remote_address, data, length, ecn);
				
				// Associate all the connection IDs with the server:
				_servers.emplace(dcid_key, server);
				
				auto scids = server->scids();
				for (auto & scid : scids) {
					associate(&scid, server);
				}
			}
			else {
				auto server = iterator->second;
				server->process_packet(socket, remote_address, data, length, ecn);
			}
		}
		
		void Dispatcher::send_version_negotiation(Socket & socket, ngtcp2_version_cid &version_cid, const Address &address)
		{
			// std::array<Byte, NGTCP2_MAX_UDP_PAYLOAD_SIZE> buffer;
		}
	}
}
