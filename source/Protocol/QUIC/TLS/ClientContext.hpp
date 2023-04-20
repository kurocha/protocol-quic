//
//  ClientContext.hpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 7/4/2023.
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
			class ClientContext : public Context
			{
			public:
				ClientContext();
				virtual ~ClientContext();
			};
		}
	}
}
