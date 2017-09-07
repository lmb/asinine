--[[ This Source Code Form is subject to the terms of the Mozilla Public
     License, v. 2.0. If a copy of the MPL was not distributed with this
     file, You can obtain one at http://mozilla.org/MPL/2.0/. ]]

solution "Asinine"
	configurations { "Debug", "Release" }
	includedirs { "include" }

	buildoptions { "-std=c99", "-Wpedantic", "-ffunction-sections",
		"-Wextra", "-Wall", "-fvisibility=hidden", "-Wstrict-overflow",
		"-fno-strict-aliasing", "-Wno-missing-field-initializers",
		"-Wno-missing-braces", "-Wconversion" }

	configuration "Debug"
		defines { "DEBUG" }
		flags { "Symbols", "FatalWarnings" }
		buildoptions { "-Wshadow" }

	configuration "Release"
		defines { "NDEBUG" }
		flags { "OptimizeSize" }

	project "asinine"
		kind "StaticLib"
		language "C"

		files { "include/asinine/*.h", "include/internal/*.h", "src/*.c" }

	project "dump"
		kind "ConsoleApp"
		language "C"
		links { "asinine" }

		files { "src/utils/dump.c", "src/utils/hex.c", "src/utils/load.c" }

	project "x509"
		kind "ConsoleApp"
		language "C"
		links { "asinine" }

		files { "src/utils/x509.c", "src/utils/hex.c", "src/utils/load.c" }

	project "tests"
		kind "ConsoleApp"
		language "C"
		links { "asinine" }

		files { "include/tests/*.h", "src/tests/*.c" }
