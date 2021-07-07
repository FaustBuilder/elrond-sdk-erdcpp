#include "inputhandler/ext.h"
#include "commandhandler.h"

int main(int argc, char *argv[])
{
    try
    {
        cli::init();

        ih::ArgHandler argHandler;
        auto result = argHandler.parse(argc, argv);

        cli::handleRequest(result);
    }
    catch (std::exception const &exception)
    {
        std::cerr<< exception.what();
    }

    return 0;
}
