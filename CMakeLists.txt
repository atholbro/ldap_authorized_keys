cmake_minimum_required(VERSION 3.10)
project(ldap_authorized_keys)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(Ldap)

set(CMAKE_C_STANDARD 11)

include_directories(${LDAP_INCLUDE_DIR})
add_executable(ldap_authorized_keys src/main.c src/config_parser.h src/config_parser.c src/drop_privileges.h src/drop_privileges.c)
target_link_libraries(ldap_authorized_keys ${LDAP_LIBRARIES})