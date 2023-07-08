cmake_minimum_required(VERSION 3.0)
project(SteamQueryProxy C CXX)

get_filename_component(PROJECT_TOP "${PROJECT_SOURCE_DIR}" ABSOLUTE)

if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
	message(FATAL_ERROR
		"\n"
		"In-source builds are not supported\n"
		"See build instructions provided in: "
		"${PROJECT_TOP}/doc/build.rst\n"
		"Refusing to continue"
	)
endif()

list(APPEND CMAKE_MODULE_PATH "${PROJECT_TOP}/cmake/" "${PROJECT_SOURCE_DIR}/cmake/")

include(GNUInstallDirs)
include(CheckCCompilerFlag)
include(FeatureSummary)

set(OPTIMIZE_FOR_NATIVE_DEFAULT ON)
include(OptimizeForNative) # option(OPTIMIZE_FOR_NATIVE)
include(UninstallTarget)

find_package(PkgConfig)
pkg_check_modules(NETFILTER REQUIRED IMPORTED_TARGET
	libnetfilter_queue
	libmnl
)

add_compile_options(
  "-Wall"
  "-Wextra"
  "-Wno-sign-compare"
  "-Wno-unused-parameter"
  "-Wstrict-prototypes"
  "$<$<C_COMPILER_ID:GNU>:-Wimplicit-fallthrough=2>"
  "-Werror"
  "-Wfatal-errors"
  "-ffast-math"
  "-fdata-sections"
  "-ffunction-sections"
  "$<$<CONFIG:DEBUG>:-O0;-g3;-ggdb>"
)

set(EXE_FLAGS "-Wl,--gc-sections -z noexecstack")
set(CMAKE_C_STANDARD 11)

if(ENABLE_ASAN)
  add_compile_options("-fno-omit-frame-pointer" "-fsanitize=address")
  set(EXE_FLAGS "${EXE_FLAGS} -fno-omit-frame-pointer -fsanitize=address")
endif()

if(ENABLE_UBSAN)
  add_compile_options("-fsanitize=undefined")
  set(EXE_FLAGS "${EXE_FLAGS} -fsanitize=undefined")
endif()

include_directories(
	${PROJECT_TOP}
	${PROJECT_SOURCE_DIR}/include
	${CMAKE_BINARY_DIR}/include
	${PROJECT_TOP}/repo
)

link_libraries(
	${CMAKE_DL_LIBS}
	pthread
	rt
	m
)

set(SOURCES
	src/global.c
	src/client.c
	src/util.c
	src/challenge.c
)

add_executable(SteamQueryProxy src/main.c ${SOURCES})
add_executable(Test src/test.c ${SOURCES})

target_link_libraries(SteamQueryProxy
	${EXE_FLAGS}
	PkgConfig::NETFILTER
)

target_link_libraries(Test
	${EXE_FLAGS}
	PkgConfig::NETFILTER
)

install(TARGETS SteamQueryProxy
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	COMPONENT binary)

feature_summary(WHAT ENABLED_FEATURES DISABLED_FEATURES)
