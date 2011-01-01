#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <ctype.h>
#include "PERE.h"

const char Data1[] = "DAT1";
const char Data2[] = "DAT2";

const char file_path[] = "/tmp/in.exe";

static PERE ResourceManager;

int main(int argc, char *argv[])
{
    if (ResourceManager.BeginUpdateResource((char*) file_path, false) != RE_SUCCESS) {
        printf("Cannot open input file\n");
        return 1;
    }

    ResourceManager.UpdateResource(200, "GRANDE", 1, NULL, 11, (PBYTE) &Data1, 4);
    ResourceManager.UpdateResource(100, "FAMILIA", 1, "HOLA!", 13, (PBYTE) &Data1, 4);
    ResourceManager.UpdateResource(100, "TENEMOS", 1, NULL, 13, (PBYTE) &Data2, 4);

    ResourceManager.UpdateResource(100, NULL, 100, "AGUA", 100, (PBYTE) &Data1, 4);
    ResourceManager.UpdateResource(200, NULL, 200, "FUEGO", 200, (PBYTE) &Data2, 4);
    ResourceManager.UpdateResource(RT_RCDATA, NULL, 5, NULL, 3, (PBYTE) &Data2, 4);

    ResourceManager.EndUpdateResource();
    return 0;
}
