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
#include <unistd.h>

#include "sha256.h"

// doesn't like me passing around an array of arrays of bytes, so I'm using an array of structs instead.
struct FinalHashes {
    BYTE hash[SHA256_BLOCK_SIZE];
};


//static char const * const COMMON_PASS_LIST = "common_passwords.txt";
static char const * const HASH4 = "pwd4sha256";
static char const * const HASH6 = "pwd6sha256";
static char const * const OUTFILE = "found_pwds.txt";
static char const * const BRUTELIST = "brute_force_passwords.txt";
static char const * const ALPHABET = "abcdefghijklmnopqrstuvwxyz"
                                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                     "1234567890";
static int alphabetSize = 62;
int outputType = 1;




int hashComparer(BYTE text[], struct FinalHashes targetHash[], int targetSize)
{
    // take in string, hash string, compare to target hash array.
    // initialise SHA256 objects
    BYTE buf[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;

    // perform hash
    sha256_init(&ctx);
    sha256_update(&ctx, text, strlen(text));
    sha256_final(&ctx, buf);

    // find number of targets to compare
    // printf for testing
    // compare hash to targets
    for(int i = 0; i < targetSize; i++)
    {
        if (!memcmp(buf, targetHash[i].hash, SHA256_BLOCK_SIZE)){
            if ( outputType ){
                printf("%s %d\n", text, i + 1);
            }
            return 1;
        }
    }
    return 0;
}

/**
 * using file io to generate and later access brute force.
 * note that this does technically produce a dictionary,
 * and hence should be used with dictionaryAttack.
 * file needs to be previously opened with append ("a"),
 * and closed after operations.
 */
void bruteRecursiveGen(char* str, int index, int maxDepth, FILE * bruteOut)
{
    for (int i = 0; i < alphabetSize; ++i)
    {
        str[index] = ALPHABET[i];
        if (index == maxDepth - 1){
            printf("%s\n", str);
            fprintf(bruteOut, "%s\n", str);
        }
        else{
            bruteRecursiveGen(str, index + 1, maxDepth, bruteOut);
        }
    }
}
void bruteRecursiveInitialise(char* filePath, int maxDepth)
{
    FILE * bruteFile;
    bruteFile = fopen(filePath, "a");
    char strink[maxDepth];
    bzero(strink, 6);
    bruteRecursiveGen(strink, 0, maxDepth, bruteFile);
    fclose(bruteFile);
}

void strConverter(char * str, BYTE * text)
{
    int i = 0;
    while ( str[i] != '\0')
    {
        text[i];
    }
}

/*
void dictionaryAttack(int length, FILE * dictionary, BYTE targetHash[][])
{
    // no reason not to use the Block Size as entry limiter
    char entry[128];
    while ( fgets( entry, sizeof(entry), dictionary) != NULL )
    {

    }
}
*/



int main(int argc, char * argv[])
{
    BYTE testP4[] = {"ngur"};
    BYTE testP6[] = {"ngurba"};
    int i, j;
    // this one opens the Hash File and prepares it
    FILE * hashFile4;
    // Initialise HashWords: hash-4
    hashFile4 = fopen(HASH4, "rb");
    struct FinalHashes hashWords[30];
    // 10 hash-4
    for (i = 0; i < 10; i++)
    {
        j = fread(hashWords[i].hash, 32, 1, hashFile4);
        if ( j != 1 ){
            printf("read error\n");
        }
        //printf(hashWords[i]);
        //printf("\n");
    }
    fclose(hashFile4);
    // Initialise HashWords: hash-6
    FILE * hashFile6;
    hashFile6 = fopen(HASH6, "rb");
    // 20 hash-6
    for (i = 0; i < 20; i++)
    {
        j = fread(hashWords[i + 10].hash, SHA256_BLOCK_SIZE, 1, hashFile6);
        if ( j != 1 ){
            printf("read error\n");
        }
        //printf(hashWords[i]);
        //printf("\n");
    }
    fclose(hashFile6);

    FILE * foundPasses;
    foundPasses = fopen(OUTFILE, "a");

    int k = hashComparer(testP4, hashWords, 30);
    k += hashComparer(testP6, hashWords, 30);
    //printf("test cases passed: %d\n", k);

    fclose(foundPasses);

    //bruteRecursiveInitialise(BRUTELIST, 4);
    /** doing brute-6 makes the VM run out of memory
     * bruteRecursiveInitialise(BRUTELIST, 6);
     */
}
