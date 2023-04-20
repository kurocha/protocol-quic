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

namespace Protocol
{
	namespace QUIC
	{
		class Configuration
		{
		public:
			Configuration();
			~Configuration();
			
			std::array<std::uint8_t, 32> static_secret;
		private:
			
		};
	}
}
