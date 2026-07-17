cmake_minimum_required(VERSION 3.24)
project(missionweaveprotocol_consumer LANGUAGES CXX)

find_package(missionweaveprotocol CONFIG REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE MissionWeaveProtocol::sdk)
