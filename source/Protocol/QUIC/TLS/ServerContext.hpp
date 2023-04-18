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
				
			};
		}
	}
}
