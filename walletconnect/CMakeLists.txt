include_directories(${PROJECT_SOURCE_DIR}/src)
include_directories(inputhandler)

# add_subdirectory(inputhandler)

set(HEADER_FILES entity/ClientMeta.h
                 entity/SocketMessage.h
                 websocket/easywsclient.h
                 session/ClientSession.h
                 qrcode/qrcodegen.h
                 session/SessionManager.h)
                 
set(SOURCE_FILES main.cpp
                 websocket/easywsclient.cpp
                 session/ClientSession.cpp
                 qrcode/qrcodegen.cpp
                 session/SessionManager.cpp)
                 
add_executable(walletconnect ${HEADER_FILES}
                      ${SOURCE_FILES})

target_link_libraries(walletconnect PUBLIC inputhandler)
target_link_libraries(walletconnect PUBLIC src)

