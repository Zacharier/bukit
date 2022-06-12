#include <iostream>

#include "foo.h"
#include "bar.h"

int main(int argc, char* argv[]) {

    foo();
    bar();
    std::cout << "hello, world" << std::endl;
    return 0;
}
