--[[ This Source Code Form is subject to the terms of the Mozilla Public
     License, v. 2.0. If a copy of the MPL was not distributed with this
     file, You can obtain one at http://mozilla.org/MPL/2.0/. ]]

solution "Asinine"
	configurations { "Debug", "Release" }
	includedirs { "include" }

	flags { "FatalWarnings" }
	buildoptions { "-ansi", "-std=c99", "-pedantic", "-ffunction-sections",
		"-Wextra" }

	configuration "Debug"
		defines { "DEBUG" }
		flags { "Symbols" }

	configuration "Release"
		defines { "NDEBUG" }
		flags { "OptimizeSize" }

	project "asinine"
		kind "StaticLib"
		language "C"

		files { "include/asinine/*.h", "src/*.c" }

	project "tests"
		kind "ConsoleApp"
		language "C"

		files { "include/asinine/*.h", "src/**.c" }