/**
 * COMP30023 2019 Assignment 2
 * Code by Nicholas Gurban
 *
 * sha256 implementation by Brad Conte (brad AT bradconte.com)
 * makefile made with assistance from:
 * http://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/
 *
 * every time I import this into the VM it chucks a hissy fit
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdbool.h>
#include "sha256.h"

// doesn't like me passing around an array of arrays of bytes,
// so I'm using an array of structs instead.
struct FinalHashes {
    BYTE hash[SHA256_BLOCK_SIZE];
    int found;
};
//static char const * const COMMON_PASS_LIST = "common_passwords.txt";
static char * HASH4 = "pwd4sha256";
static char * HASH6 = "pwd6sha256";
static char * OUTFILE = "found_pwds.txt";
//static char * SHORTLISTFULL = "short_passwords_full.txt";
static char * SHORTLIST1 = "short_passwords1.txt";
static char * SHORTLIST2 = "short_passwords2.txt";
static char * SHORTLIST3 = "short_passwords3.txt";
static char * SHORTLIST4 = "short_passwords4.txt";
static char * SHORTLIST5 = "short_passwords5.txt";
static char * ALPHABET = "abcdefghijklmnopqrstuvwxyz"
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                         "1234567890";
static int alphabetSize = 62;
int outputType = true;
int countGuesses = false;
long long int guessNo = -1;

int hashComparer(BYTE text[], struct FinalHashes targetHash[], int targetSize, FILE * outFile) {
    // implement guess counter
    if (!countGuesses || (countGuesses && (guessNo != 0)))
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
        if (countGuesses)
        {
            // subtract guess. will stop resolving guesses
	    // when guessNo reaches zero, and negative
	    // guesses will simply not care.
            guessNo--;
            printf("%s\n", text);
            return 0;
        }
        //printf("%s\n", text);
        for(int i = 0; i < targetSize; i++)
        {
            if (!memcmp(buf, targetHash[i].hash, SHA256_BLOCK_SIZE))
            {
                if (!targetHash[i].found)
                {
                    printf("%s %d\n", text, i + 1);
                    targetHash[i].found = 1;
                    if ( outputType )
                    {
                        fprintf(outFile, "%s %d\n", text, i + 1);
                    }
                }
                return 1;
            }
        }
    }
    return 0;
}

void strConverter(char * str, BYTE * text) {
    int i = 0;
    int j = strlen(text);
    while ( !((str[i] == '\0') || (str[i] == '\n')))
    {
        text[i] = str[i];
        i++;
    }
    while (i<j)
    {
        text[i] = '\0';
        i++;
    }
}

// nice and simple brute force. estimate 9 hours for full 4 and 6 digit.
void bruteRecursiveGen(char* str, int index, int maxDepth, FILE * outFile, struct FinalHashes targetHash[], int targetSize) {
    for (int i = 0; i < alphabetSize; ++i)
    {
        if (guessNo != 0)
        {
            str[index] = ALPHABET[i];
            if (index == maxDepth - 1)
            {
                str[maxDepth] = '\0';
                BYTE attempt[SHA256_BLOCK_SIZE];
                //printf("%s\n", str);
                strConverter(str, attempt);
                hashComparer(attempt, targetHash, targetSize, outFile);
            }
            else
            {
                //bruteRecursiveGen(str, index, maxDepth, outFile, targetHash, targetSize)
                bruteRecursiveGen(str, index + 1, maxDepth, outFile, targetHash, targetSize);
            }
        }
    }
}

// get the brute force started
void bruteRecursiveInitialise(int maxDepth, FILE * outFile, struct FinalHashes targetHash[], int targetSize) {
    char strink[maxDepth+1];
    //bruteRecursiveGen(str, index, maxDepth, outFile, targetHash, targetSize)
    bruteRecursiveGen(strink, 0, maxDepth, outFile, targetHash, targetSize);
}

// take dictionary file, search passwords for matches.
void dictionaryAttack(FILE * dictionary, struct FinalHashes targetHash[], int targetSize, FILE * outFile) {
    // no reason not to use the Block Size as entry limiter
    char entry [128];
    while (( fgets( entry, sizeof(entry), dictionary) != NULL ) && (guessNo != 0))
    {
        BYTE attempt[SHA256_BLOCK_SIZE];
        strConverter(entry, attempt);
        hashComparer(attempt, targetHash, targetSize, outFile);
    }
}

////////////////////////////////////////////////////////////////////////////////
// Regular Mode: find all possible guesses. Also factors in guess counting.
void regularMode() {
    // prepare initial hashes
    int i, j;
    struct FinalHashes hashWords[30];
    FILE * hashFile4;
    FILE * hashFile6;
    hashFile4 = fopen(HASH4, "rb");
    hashFile6 = fopen(HASH6, "rb");
    for (i = 0; i < 30; i++) // 10x hash-4, 20x hash-6
    {
        if (i < 10)
        {
            j = fread(hashWords[i].hash, SHA256_BLOCK_SIZE, 1, hashFile4);
            if ( j != 1 ){
                printf("read error\n");
            }
        }
        else
        {
            j = fread(hashWords[i].hash, SHA256_BLOCK_SIZE, 1, hashFile6);
            if ( j != 1 ){
              printf("read error\n");
            }
        }
        hashWords[i].found = 0;
    }
    fclose(hashFile4);
    fclose(hashFile6);
    FILE * foundPasswords;
    foundPasswords = fopen(OUTFILE, "a");
    // first, username test cases
    BYTE testP4[] = {"ngur"};
    BYTE testP6[] = {"ngurba"};
    int k = hashComparer(testP4, hashWords, 30, foundPasswords);
    k += hashComparer(testP6, hashWords, 30, foundPasswords);
    //printf("test cases passed: %d\n", k);
    // get ready for dictionary searches
    char * shortlists[5] = {SHORTLIST1, SHORTLIST2, SHORTLIST3, SHORTLIST4, SHORTLIST5};
    for (int i = 0; i < 5; i++)
    {
        FILE * shortDict;
        shortDict = fopen(shortlists[i], "r");
        dictionaryAttack(shortDict, hashWords, 30, foundPasswords);
        fclose(shortDict);
        //printf("sub-dictionary %d finished\n", i);
    }

    // reminder of Initialisation format:
    // bruteRecursiveInitialise(maxDepth, outFile, targetHash, targetSize)
    bruteRecursiveInitialise(4, foundPasswords, hashWords, 30);
    bruteRecursiveInitialise(6, foundPasswords, hashWords, 30);
    fclose(foundPasswords);
}

////////////////////////////////////////////////////////////////////////////////
// Specific Mode allowing for custom one-to-one type tests
void specificMode(char * pwdFile, char * hashFile) {
    // line number counter
    int i = 1, j;
    FILE * pwdVerF;
    FILE * hashVerF;
    pwdVerF = fopen(pwdFile, "r");
    hashVerF = fopen(hashFile, "rb");
    char currPwd [10001];
    char currHash [SHA256_BLOCK_SIZE];
    while ( fgets( currPwd, sizeof(currPwd), pwdVerF) != NULL )
    {
        // get the password
        // we're assuming the files are the same number of lines here
        // one long string so no need for fgets or fseek
        j = fread(currHash, SHA256_BLOCK_SIZE, 1, hashVerF);
        if ( j != 1 ){
            printf("read error\n");
        }
        BYTE attempt[10001];
        strConverter(currPwd, attempt);
        //just do hashing, not calling whole hashComparer at the moment
        BYTE buf[SHA256_BLOCK_SIZE];
        SHA256_CTX ctx;
        // perform & compare hash
        sha256_init(&ctx);
        sha256_update(&ctx, attempt, strlen(attempt));
        sha256_final(&ctx, buf);
        if (!memcmp(buf, currHash, SHA256_BLOCK_SIZE))
        {
            // print to stdout in case of success
            printf("%s %d\n", attempt, i);
        }
        i++;
    }
}
////////////////////////////////////////////////////////////////////////////////
// main function provides switchboard to sub-functionalities.
int main(int argc, char * argv[]) {
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
            countGuesses = true;
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
        outputType = false;
        specificMode(argv[1], argv[2]);
    }
    else
    {
        printf("incorrect use of crack\n");
        printf("we take no liability for ill effects of crack\n");
        printf("please use crack responsibly\n");
    }
}
