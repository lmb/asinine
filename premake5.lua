--[[ This Source Code Form is subject to the terms of the Mozilla Public
     License, v. 2.0. If a copy of the MPL was not distributed with this
     file, You can obtain one at http://mozilla.org/MPL/2.0/. ]]

workspace "Asinine"
	configurations { "Debug", "Release" }
	includedirs { "include" }
	flags { "FatalWarnings", "ShadowedVariables", "UndefinedIdentifiers" }
	buildoptions {
		"-std=c99",
		"-ffunction-sections",
		"-fvisibility=hidden",
		"-fno-strict-aliasing",
		"-Wno-missing-field-initializers",
		"-Wno-missing-braces",
		"-Wstrict-overflow",
		"-Wconversion"
	}

	filter "configurations:Debug"
		defines { "DEBUG" }
		symbols "On"
		warnings "Extra"

	filter "configurations:Release"
		defines { "NDEBUG" }
		optimize "Size"

	project "asinine"
		kind "StaticLib"
		language "C"

		files { "include/asinine/*.h", "include/internal/*.h", "src/*.c" }

	project "asn1"
		kind "ConsoleApp"
		language "C"
		links { "asinine" }

		files { "src/utils/asn1.c", "src/utils/hex.c", "src/utils/load.c" }

	project "x509"
		kind "ConsoleApp"
		language "C"
		links { "asinine", "mbedcrypto" }

		files { "src/utils/x509.c", "src/utils/hex.c", "src/utils/load.c" }

	project "tests"
		kind "ConsoleApp"
		language "C"
		links { "asinine" }

		files { "include/tests/*.h", "src/tests/*.c", "src/utils/load.c" }
