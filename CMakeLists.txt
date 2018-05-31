cmake_minimum_required(VERSION 3.10)
project(ldap_authorized_keys)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(Ldap)

set(CMAKE_C_STANDARD 11)

include_directories(${LDAP_INCLUDE_DIR})
add_executable(ldap_authorized_keys main.c config_parser.h config_parser.c drop_privileges.h drop_privileges.c)
target_link_libraries(ldap_authorized_keys ${LDAP_LIBRARIES})