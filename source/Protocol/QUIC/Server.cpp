//
//  Server.cpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 5/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Server.hpp"

namespace Protocol
{
	namespace QUIC
	{
		Server::Server(std::shared_ptr<TLS::ServerContext> tls_context) : _tls_context(tls_context)
		{
		}
		
		Server::~Server()
		{
		}
		
		void Server::listen(const Address & address)
		{
			Socket & socket = _sockets.emplace_back(address.family(), SOCK_DGRAM, IPPROTO_UDP);
			
			socket.bind(address);
			
			while (socket) {
				this->receive_from(socket);
			}
		}
	}
}
