include_directories(${PROJECT_SOURCE_DIR}/src)
include_directories(inputhandler)

# add_subdirectory(inputhandler)

set(HEADER_FILES entity/ClientMeta.h
                 entity/SocketMessage.h
                 websocket/easywsclient.h
                 ClientSession.h
                 qrcode/qrcodegen.h
                 SessionManager.h)
                 
set(SOURCE_FILES main.cpp
                 websocket/easywsclient.cpp
                 ClientSession.cpp
                 qrcode/qrcodegen.cpp
                 SessionManager.cpp)
                 
add_executable(walletconnect ${HEADER_FILES}
                      ${SOURCE_FILES})

target_link_libraries(walletconnect PUBLIC inputhandler)
target_link_libraries(walletconnect PUBLIC src)

