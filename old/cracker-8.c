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
#include <strings.h>
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
static char const * const SHORTLIST1 = "short_passwords1.txt";
static char const * const SHORTLIST2 = "short_passwords2.txt";
static char const * const SHORTLIST3 = "short_passwords3.txt";
static char const * const SHORTLIST4 = "short_passwords4.txt";
static char const * const SHORTLIST5 = "short_passwords5.txt";
static char const * const BRUTELIST = "brute_force_passwords.txt";
static char const * const ALPHABET = "abcdefghijklmnopqrstuvwxyz"
                                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                     "1234567890";
static int alphabetSize = 62;
int outputType = 1;
int guessNo = -1;



int hashComparer(BYTE text[], struct FinalHashes targetHash[], int targetSize, FILE * outFile)
{
    // implement guess counter
    if (guessNo != 0)
    {
        // subtract guess. will stop resolving guesses when guessNo reaches zero,
        guessNo--;
        // and negative guesses will simply not care.

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
            if (!memcmp(buf, targetHash[i].hash, SHA256_BLOCK_SIZE))
            {
                if ( outputType )
                {
                    printf("%s %d\n", text, i + 1);
                    fprintf(outFile, "%s %d\n", text, i + 1);
                }
                return 1;
            }
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
void bruteRecursiveGen(char* str, int index, int maxDepth, FILE * outFile)
{
    for (int i = 0; i < alphabetSize; ++i)
    {
        str[index] = ALPHABET[i];
        if (index == maxDepth - 1){
            fprintf(, "%s\n", str);
        }
        else{
            bruteRecursiveGen(str, index + 1, maxDepth, outFile);
        }
    }
}
void bruteRecursiveInitialise(char* filePath, int maxDepth, FILE * outFile)
{
    FILE * bruteFile;
    bruteFile = fopen(filePath, "a");
    char strink[maxDepth+1];
    bruteRecursiveGen(strink, 0, maxDepth, outFile);
    fclose(bruteFile);
}

void strConverter(char * str, BYTE * text)
{
    int i = 0;
    //printf("%s\n", str);
    while ( !((str[i] == '\0') || (str[i] == '\n')))
    {
        text[i] = str[i];
        i++;
    }
}


void dictionaryAttack(FILE * dictionary, struct FinalHashes targetHash[], int targetSize, FILE * outFile)
{
    // no reason not to use the Block Size as entry limiter
    char entry[128];
    while (( fgets( entry, sizeof(entry), dictionary) != NULL ) && (guessNo != 0))
    {
        BYTE attempt[SHA256_BLOCK_SIZE];
        strConverter(entry, attempt);
        hashComparer(attempt, targetHash, targetSize, outFile);
    }
}



////////////////////////////////////////////////////////////////////////////////
// Regular Mode: find maximum guesses. Also factors in guess counting.
void regularMode()
{
    // prepare initial hashes
    int i, j;
    struct FinalHashes hashWords[30];
    FILE * hashFile4;
    FILE * hashFile6;
    hashFile4 = fopen(HASH4, "rb");
    hashFile6 = fopen(HASH6, "rb");
    for (i = 0; i < 10; i++)  // 10x hash-4
    {
        j = fread(hashWords[i].hash, 32, 1, hashFile4);
        if ( j != 1 ){
            printf("read error\n");
        }
    }
    for (i = 0; i < 20; i++)  // 20x hash-6
    {
        j = fread(hashWords[i + 10].hash, SHA256_BLOCK_SIZE, 1, hashFile6);
        if ( j != 1 ){
            printf("read error\n");
        }
    }

    fclose(hashFile4);
    fclose(hashFile6);

    FILE * foundPasswords;
    foundPasswords = fopen(OUTFILE, "a");

    /** username test cases work easy
    // first, username test cases
    BYTE testP4[] = {"ngur"};
    BYTE testP6[] = {"ngurba"};
    int k = hashComparer(testP4, hashWords, 30, foundPasswords);
    k += hashComparer(testP6, hashWords, 30, foundPasswords);
    //printf("test cases passed: %d\n", k);
    */

    // get ready for dictionary searches
    // 4-figure hash already initialised
        //bruteRecursiveInitialise(BRUTELIST, 4);
    char * shortlists[5] = {SHORTLIST1, SHORTLIST2, SHORTLIST3, SHORTLIST4, SHORTLIST5};
    for (int i = 0; i < 5; i++)
    {
      FILE * shortDict;
      shortDict = fopen(shortlists[i], "r");
      dictionaryAttack(shortDict, hashWords, 30, foundPasswords);
      fclose(shortDict);
    }


    /**
    FILE * brute4ceDict;
    brute4ceDict = fopen(BRUTELIST, "r");
    dictionaryAttack(brute4ceDict, hashWords, 30, foundPasswords);
    printf("finished dictionary attack\n");
    fclose(brute4ceDict);
    */
    /** doing brute-6 makes the VM run out of memory
    * bruteRecursiveInitialise(BRUTELIST, 6);
    */
    fclose(foundPasswords);
}

////////////////////////////////////////////////////////////////////////////////
// Specific Mode allowing for custom one-to-one type tests
void specificMode(char * pwdFile, char * hashFile)
{
    printf("Specific Mode not yet implemented.\n");
}




////////////////////////////////////////////////////////////////////////////////
// main function provides switchboard to sub-functionalities.
int main(int argc, char * argv[])
{
    if (argc == 1)
    {
        regularMode();
    }
    else if (argc == 2)
    {
        int i = atoi(argv[1]);
        if (i)
        {
            // easier to hard-code guess limits into regular mode.
            guessNo = i;
            regularMode();
        }
        else
        {
            printf("correct use for Limited Guess Mode is: crack <int>\n");
        }
    }
    else if (argc == 3)
    {
        specificMode(argv[1], argv[2]);
    }
    else
    {
        printf("incorrect use of crack\n");
        printf("we take no liability for ill effects of crack\n");
        printf("please use crack responsibly\n");
    }
}
