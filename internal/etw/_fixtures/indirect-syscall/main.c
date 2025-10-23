#include "syscalls.h"

#include <Windows.h>

int main(int argc, char* argv[])
{
    Sw3NtSetContextThread(-1, NULL);
    return 0;
}
