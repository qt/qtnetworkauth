# special case begin
if(NOT TARGET Qt::Test)
    cmake_minimum_required(VERSION 3.15.0)
    project(QtNetworkAuthTests VERSION 6.0.0 LANGUAGES C CXX ASM)
    find_package(Qt6 REQUIRED COMPONENTS BuildInternals Core NetworkAuth Test)
    qt_set_up_standalone_tests_build()
endif()
# special case end

qt_build_tests()

