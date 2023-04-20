//
//  Configuration.cpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 20/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Configuration.hpp"
#include "Random.hpp"

namespace Protocol
{
	namespace QUIC
	{
		Configuration::Configuration()
		{
			Random::generate_secret(static_secret);
		}
		
		Configuration::~Configuration()
		{
		}
	}
}
