/**
 * Diffie-Hellman code for COMP30023_2019_PROJECT-2.
 * Arrangement by Nicholas Gurban
 * socket programming adapted from client.c, as available from week 4 workshops.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

#include <math.h>

static char * SERVERADDRESS = "172.26.37.44";
static char * SERVERPORT = "7800";
static char * USERNAME = "ngurban\n";


// "Primality Testing"
// code from https://stackoverflow.com/questions/8496182/calculating-powa-b-mod-n
long long int modulo(long long int base, long long int exp, long long int mod)
{
    long long int x = 1, y = base;
    while (exp > 0)
    {
        if (exp % 2 == 1)
        {
            x = (x * y) % mod;
        }
        y = (y * y) % mod;
	exp /= 2;
    }
    return x % mod;
}


int main(int argc, char ** argv)
{

    long long int b = atoi(argv[1]);
    long long int g = 15;
    long long int p = 97;

    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent * server;

    char buffer[10001];

    /* Translate host name into peer's IP address ;
     * This is name translation service by the operating system
     */
    server = gethostbyname(SERVERADDRESS);
    portno = atoi(SERVERPORT);

    printf("establishing server connection: %s:%s\n", SERVERADDRESS, SERVERPORT);

    if (server == NULL)
    {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }

    /* Building data structures for socket */
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy(server->h_addr_list[0], (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(portno);

    /* Create TCP socket -- active open
    * Preliminary steps: Setup: creation of active open socket
    */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        perror("ERROR opening socket");
        exit(0);
    }
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("ERROR connecting");
        exit(0);
    }

    // send username
    printf("sending username: %s", USERNAME);
    n = write(sockfd, USERNAME, strlen(USERNAME));
    if (n < 0)
    {
        perror("ERROR writing to socket");
        exit(0);
    }

    // send gbmodp
    long long int gbmodp = modulo(g, b, p);
    bzero(buffer, 10001);
    sprintf(buffer, "%lli\n", gbmodp);
    printf("sending gBmodP\n");
    n = write(sockfd, buffer, strlen(buffer));
    if (n < 0)
    {
        perror("ERROR writing to socket");
        exit(0);
    }

    // listen for gamodp
    printf("listening for gAmodP\n");
    long long int gamodp;
    bzero(buffer, 10001);
    n = read(sockfd, buffer, 10000);
    if (n < 0)
    {
        perror("ERROR reading from socket");
        exit(0);
    }
    gamodp = atoi(buffer);
    printf("gAmodP received\n");

    // decode, send shared secret
    long long int gbamodp = modulo(gamodp, b, p);
    bzero(buffer, 10001);
    sprintf(buffer, "%lli\n", gbamodp);
    printf("sending shared secret\n");
    n = write(sockfd, buffer, strlen(buffer));
    if (n < 0)
    {
        perror("ERROR writing to socket");
        exit(0);
    }

    // listen for status report
    printf("listening for status report\n");
    bzero(buffer, 10001);
    n = read(sockfd, buffer, 10000);
    if (n < 0)
    {
        perror("ERROR reading from socket");
        exit(0);
    }
    printf("%s\n", buffer);

    return 0;
}

