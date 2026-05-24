//
//  ServerContext.hpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 18/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include "Context.hpp"

namespace Protocol
{
	namespace QUIC
	{
		namespace TLS
		{
			class ServerContext : public Context
			{
			public:
				ServerContext();
				virtual ~ServerContext();
				
				void set_require_client_authentication(bool enabled);
				
			private:
				struct ClientHelloCallback
				{
					ptls_on_client_hello_t super;
					ServerContext *context;
				};

				ClientHelloCallback _client_hello;

				static int client_hello_callback(ptls_on_client_hello_t *self, ptls_t *ptls, ptls_on_client_hello_parameters_t *params);

			protected:
				virtual int client_hello(ptls_t *ptls, ptls_on_client_hello_parameters_t *params);
			};
		}
	}
}
