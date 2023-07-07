#include "client.h"

int main(int argc, char * argv[])
{
  client_start("192.168.10.50", 27015, false, false);
  return 0;
}
