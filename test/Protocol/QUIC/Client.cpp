//
//  Client.cpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 17/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include <UnitTest/UnitTest.hpp>

#include <Protocol/QUIC/Client.hpp>

namespace Protocol
{
	namespace QUIC
	{
		using namespace UnitTest::Expectations;
		
		UnitTest::Suite ClientTestSuite {
			"Protocol::QUIC::Client",
			
			{"it should have some real tests",
				[](UnitTest::Examiner & examiner) {
					examiner.expect(true).to(be_true);
				}
			},
		};
	}
}
