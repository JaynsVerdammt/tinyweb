//
// TODO: Include your module header here
//

#ifndef _TINYWEB_H
#define _TINYWEB_H

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdbool.h>

#define err_print(s)              fprintf(stderr, "ERROR: %s, %s:%d\n", (s), __FILE__, __LINE__)

#define BUFFER_SIZE                      8192
#define DEFAULT_HTML_PAGE      "default.html"


typedef struct prog_options {
    char               *progname;
    char               *root_dir;
    char               *log_filename;
    FILE               *log_fd;
    bool                verbose;
    unsigned short      timeout;
    struct addrinfo    *server_addr;
    int                 server_port;
} prog_options_t;

int get_status();
char* calculate_timestamp();
char* create_HTTP_response_header(int status, const char *filename);
char* parse_HTTP_msg(char buffer[]);
void child_processing(int newsockfd, struct sockaddr_in cli_addr);
void client_connection(int sockfd);
int server_init(int port);
void write_to_logfile(struct sockaddr_in cli_addr, char *path_to_file_relativ, char buffer[], int read_count_bytes);

void error(const char *msg);

#endif

