#include <stdlib.h>
#include <stdio.h>

#include "sha256.h"

static char const * const COMMON_PASS_LIST = "common_passwords.txt";
static char const * const HASH4 = "pwd4sha256";
static char const * const HASH6 = "pwd6sha256";
static char const * const OUTFILE = "found_pwds.txt";

int main(int argc, char * argv[]){

    BYTE testPass[] = {"ngur"};
    BYTE buf[SHA256_BLOCK_SIZE];

    BYTE hashWords[10][SHA256_BLOCK_SIZE];


    // regular search-version?
    FILE * hashFile;
    hashFile = fopen(HASH4, "rb");

    for (int i = 0; i < 10; i++){
        read(hashWords[i], 32, 1, hashFile);
	printf(hashWords[i]);
	printf("\n");
    }

    FILE * foundPasses;
    foundPasses = fopen(OUTFILE, "w");

    fclose(foundPasses);
    fclose(hashFile);
}

