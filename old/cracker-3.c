/**
 * COMP30023 2019 Assignment 2
 * Code by Nicholas Gurban
 *
 * sha256 implementation by Brad Conte (brad AT bradconte.com)
 * makefile made with assistance from http://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sha256.h"

static char const * const COMMON_PASS_LIST = "common_passwords.txt";
static char const * const HASH4 = "pwd4sha256";
static char const * const HASH6 = "pwd6sha256";
static char const * const OUTFILE = "found_pwds.txt";


int hashComparer(BYTE text[], BYTE targetHash[][]){
    // take in string, hash string, compare to target hash array.
    // initialise SHA256 objects
    BYTE buf[SHA256_BLOCK_SIZE]
    SHA256_CTX ctx;

    // perform hash
    sha256_init(&ctx);
    sha256_update(&ctx, text, strlen(text));
    sha256_final(&ctx, buf);

    // find number of targets to compare
    int j = sizeof(targetHash)/sizeof(targetHash[0]);
    // printf for testing
    printf("%d items compared\n", j);
    // compare hash to targets
    for(int i = 0; i < j; i++){
        if (!memcmp(buf, targetHash[i], SHA256_BLOCK_SIZE)){
            return 1;
        }
    }
    return 0;
}


int main(int argc, char * argv[]){

    BYTE testP4[] = {"ngur"};

    // regular search-version?
    FILE * hashFile;
    hashFile = fopen(HASH4, "rb");

    for (int i = 0; i < 10; i++){
        int j = fread(hashWords[i], 32, 1, hashFile);
        if ( j != 1 ){
            printf("read error\n");
        }
        //printf(hashWords[i]);
        //printf("\n");
    }

    FILE * foundPasses;
    foundPasses = fopen(OUTFILE, "w");

    int k = hashComparer(testP4, hashWords);
    printf("test case pass: %d\n", k);

    fclose(foundPasses);
    fclose(hashFile);
}
