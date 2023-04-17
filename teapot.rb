# Teapot v3.5.0 configuration generated at 2023-04-17 12:31:24 +1200

required_version "3.0"

define_project "protocol-quic" do |project|
	project.title = "Protocol QUIC"
end

# Build Targets

define_target 'protocol-quic-library' do |target|
	target.depends 'Language/C++14'
	
	target.provides 'Library/ProtocolQUIC' do
		source_root = target.package.path + 'source'
		
		library_path = build static_library: 'ProtocolQUIC', source_files: source_root.glob('ProtocolQUIC/**/*.cpp')
		
		append linkflags library_path
		append header_search_paths source_root
	end
end

define_target 'protocol-quic-test' do |target|
	target.depends 'Library/ProtocolQUIC'
	target.depends 'Library/UnitTest'
	
	target.depends 'Language/C++14'
	
	target.provides 'Test/ProtocolQUIC' do |arguments|
		test_root = target.package.path + 'test'
		
		run tests: 'ProtocolQUIC-tests', source_files: test_root.glob('ProtocolQUIC/**/*.cpp'), arguments: arguments
	end
end

define_target 'protocol-quic-executable' do |target|
	target.depends 'Library/ProtocolQUIC'
	
	target.depends 'Language/C++14'
	
	target.provides 'Executable/ProtocolQUIC' do
		source_root = target.package.path + 'source'
		
		executable_path = build executable: 'ProtocolQUIC', source_files: source_root.glob('ProtocolQUIC.cpp')
		
		protocol_quic_executable executable_path
	end
end

define_target 'protocol-quic-run' do |target|
	target.depends 'Executable/ProtocolQUIC'
	
	target.depends :executor
	
	target.provides 'Run/ProtocolQUIC' do |*arguments|
		run executable_file: environment[:protocol_quic_executable], arguments: arguments
	end
end

# Configurations

define_configuration 'development' do |configuration|
	configuration[:source] = "https://github.com/kurocha"
	configuration.import "protocol-quic"
	
	# Provides all the build related infrastructure:
	configuration.require 'platforms'
	
	# Provides unit testing infrastructure and generators:
	configuration.require 'unit-test'
	
	# Provides some useful C++ generators:
	configuration.require 'generate-cpp-class'
	
	configuration.require "generate-project"
end

define_configuration "protocol-quic" do |configuration|
	configuration.public!
end
