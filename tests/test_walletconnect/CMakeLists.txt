include_directories(${PROJECT_SOURCE_DIR}/walletconnect)
include_directories(${PROJECT_SOURCE_DIR}/src)

set(HEADER_FILES TestSessionManager.h)
                 
set(SOURCE_FILES main.cpp
                 TestSessionManager.cpp)
                 
add_executable(test_walletconnect ${HEADER_FILES}
                      ${SOURCE_FILES})

target_link_libraries(test_walletconnect PUBLIC walletconnect)
target_link_libraries(test_walletconnect PUBLIC src)

