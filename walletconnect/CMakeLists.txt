include_directories(${PROJECT_SOURCE_DIR}/src)
include_directories(inputhandler)

# add_subdirectory(inputhandler)

set(HEADER_FILES entity/ClientMeta.h
                 entity/SocketMessage.h
                 websocket/easywsclient.h
                 session/ClientSession.h
                 qrcode/qrcodegen.h
                 session/SessionManager.h)
                
#  main.cpp
set(SOURCE_FILES websocket/easywsclient.cpp
                 session/ClientSession.cpp
                 qrcode/qrcodegen.cpp
                 session/SessionManager.cpp)
                 

option(BUILD_SHARED_LIBS ON)
add_library(walletconnect ${HEADER_FILES}
                      ${SOURCE_FILES})

target_link_libraries(walletconnect PUBLIC inputhandler)
target_link_libraries(walletconnect PUBLIC src)

