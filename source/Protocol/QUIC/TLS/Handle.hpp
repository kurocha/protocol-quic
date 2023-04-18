//
//  Handle.hpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 18/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include "ngtcp2/ngtcp2_crypto.h"
#include <ngtcp2/ngtcp2_crypto_picotls.h>
#include <picotls.h>

namespace Protocol
{
	namespace QUIC
	{
		namespace TLS
		{
			class Handle
			{
				// This is a function for ngtcp2_crypto_conn_ref::get_conn.
				static ngtcp2_conn *conn_ref_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
				{
					auto handle = reinterpret_cast<Handle*>(conn_ref->user_data);
					return handle->ngtcp2_connection();
				}
				
			public:
				Handle() : _connection_ref{&conn_ref_get_conn, this} {}
				
				static Handle* get(ptls_t * ptls)
				{
					ngtcp2_crypto_conn_ref *conn_ref = reinterpret_cast<ngtcp2_crypto_conn_ref*>(*ptls_get_data_ptr(ptls));
					
					if (conn_ref) {
						return reinterpret_cast<Handle*>(conn_ref->user_data);
					} else {
						return nullptr;
					}
				}
				
				void set(ptls_t * ptls)
				{
					*ptls_get_data_ptr(ptls) = reinterpret_cast<void*>(&_connection_ref);
				}
				
				virtual ~Handle();
				
				// This is required for TLS negotiation:
				virtual ngtcp2_conn * ngtcp2_connection() = 0;
				
			private:
				ngtcp2_crypto_conn_ref _connection_ref;
			};
		}
	}
}
