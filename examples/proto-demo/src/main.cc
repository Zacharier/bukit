#include <iostream>

#include "protos/person.pb.h"
#include "protos/address.pb.h"


int main(int argc, char* argv[]) {
  zb::Person person;
  person.set_name("pb");
  person.set_age(22);
  std::cout << "-----------" << std::endl;
  std::cout << person.name() << person.age() << std::endl;

  zb::Address address;
  address.set_city("newyork");
  address.set_street("street-1");
  std::cout << address.DebugString() << std::endl;
  return 0;
}
