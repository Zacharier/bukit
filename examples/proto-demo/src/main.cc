#include <iostream>

#include "protos/person.pb.h"

int main(int argc, char* argv[]) {
  zb::Person person;
  person.set_name("pb");
  person.set_age(22);
  std::cout << "-----------" << std::endl;
  std::cout << person.name() << person.age() << std::endl;
  return 0;
}
