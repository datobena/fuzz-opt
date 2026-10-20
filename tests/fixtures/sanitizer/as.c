#include <assert.h>
#include <stdlib.h>
int main(int argc, char **argv) { if (argc > 1 && argv[1][0]=='a') assert(argc == 7); if (argc > 1 && argv[1][0]=='b') abort(); return 0; }
