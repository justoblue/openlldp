cmake_minimum_required(VERSION 3.0)
project(openlldpd)

include(CoriantOsCommon)

INCLUDE_DIRECTORIES(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(platform)

set(OsBasePath $ENV{WORKING_DIR}/$ENV{REPO_CORIANTOS})
set(3rdBasePath $ENV{WORKING_DIR}/$ENV{REPO_3RDPARTY})

add_subproject_dir(${OsBasePath}/BaseServices)
add_subproject_dir(${BasePath}/DBF)

include_directories(include
					${OsBasePath}/BaseServices
					${OsBasePath}/BaseServices
                    ${OsBasePath}/BaseServices/include
                    ${OsBasePath}/BaseServices/Tcl/include
					${OsBasePath}/Services/Networking
					${OsBasePath}/Services/Networking/LinkMonitor/muduo
                    platform/framehandlers/linux)

#add_definitions("-D__LINUX__ -D_REENTRANT -D__LEAK_DETECTOR__")
add_definitions("-D__LINUX__ -D_REENTRANT")

add_compile_options( -Wno-strict-aliasing)
add_compile_options( -Wno-unused)
add_compile_options( -Wno-maybe-uninitialized)
add_compile_options( -Wno-sign-compare)
add_compile_options( -Wno-pointer-arith)


################################################################################
# Make ospflldpd application
################################################################################
set(LIBRARY_NAME openlldpd)
file(GLOB OPENLLDPD_SOURCES src/*.c 
platform/framehandlers/linux/lldp_linux_framer.c src/*.cpp)

# Define the library
add_library(${LIBRARY_NAME} STATIC ${OPENLLDPD_SOURCES})

target_link_libraries(${LIBRARY_NAME} base_services dbf crypt)
