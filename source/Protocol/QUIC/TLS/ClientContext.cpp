//
//  ClientContext.cpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 7/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "ClientContext.hpp"

#include <memory>
#include <stdexcept>
#include <string>

#include <openssl/pem.h>

namespace Protocol
{
	namespace QUIC
	{
		namespace TLS
		{
			ClientContext::ClientContext() : Context()
			{
				if (ngtcp2_crypto_picotls_configure_client_context(&_context) != 0) {
					throw std::runtime_error("ngtcp2_crypto_picotls_configure_client_context failed");
				}
			}
		}
	}
}
