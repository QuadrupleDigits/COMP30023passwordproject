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
static char const * const TESTPASS4 = "ngur";
static char const * const TESTPASS6 = "ngurba";

int main(int argc, char * argv[]){

    BYTE testP4[] = {"ngur"};
    BYTE buf[SHA256_BLOCK_SIZE];
    BYTE hashWords[10][SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;


    // regular search-version?
    FILE * hashFile;
    hashFile = fopen(HASH4, "rb");

    for (int i = 0; i < 10; i++){
        int k = fread(hashWords[i], 32, 1, hashFile);
        if ( k != 1 ){
            printf("read error\n");
        }
        //printf(hashWords[i]);
        //printf("\n");
    }

    sha256_init(&ctx);
    sha256_update(&ctx, testP4, strlen(testP4));
    sha256_final(&ctx, buf);


    FILE * foundPasses;
    foundPasses = fopen(OUTFILE, "w");

    for (int i = 0; i < 10; i++){
        if (!memcmp(buf, hashWords[i], SHA256_BLOCK_SIZE)){
            printf("testPass resolved\n");
            fwrite(testP4, strlen(testP4), 1, foundPasses);
        }
    }


    fclose(foundPasses);
    fclose(hashFile);
}

