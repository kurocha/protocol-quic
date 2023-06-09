//
//  Configuration.hpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 20/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include <array>
#include <cstdint>

#include <ngtcp2/ngtcp2.h>

namespace Protocol
{
	namespace QUIC
	{
		// The Configuration class is responsible for holding configuration settings for the QUIC implementation. It provides a virtual method for setting up ngtcp2 settings and transport parameters.
		class Configuration
		{
		public:
			Configuration();
			virtual ~Configuration();
			
			std::array<std::uint8_t, 32> static_secret;
			
			virtual void setup(ngtcp2_settings *settings, ngtcp2_transport_params *params);
		};
	}
}
