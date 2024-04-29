#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define _FILE_OFFSET_BITS 64

static char const * const OLDDICT = "common_passwords.txt";
static char const * const NEWDICT = "short_passwords.txt";

int main(int argc, char * argv[])
{
    FILE * oldDict;
    FILE * newDict;

    oldDict = fopen(OLDDICT, "r");
    newDict = fopen(NEWDICT, "a");

    char line[128];
    char * entry;
    const char space[2] = " ";

    while ( fgets( line, sizeof(line), oldDict) != NULL )
    {
        entry = strtok(line, space);
        while( entry != NULL )
        {
            printf("%s", entry);
            if( (strlen(entry) == 5) || (strlen(entry) == 7) )
            {
                printf("added %s", entry);
                fprintf(newDict, "%s", entry);
            }
            entry = strtok(NULL, space);
        }
    }
    fclose(newDict);
    fclose(oldDict);
}
