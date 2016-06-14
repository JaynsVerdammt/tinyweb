/*===================================================================
 * DHBW Ravensburg - Campus Friedrichshafen
 *
 * Vorlesung Verteilte Systeme
 *
 * Author:  Ralf Reutemann
 *
 *===================================================================*/
//
// TODO: Include your module header here
//


#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <netdb.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <getopt.h>

#include "tinyweb.h"
#include "connect_tcp.h"
#include "content.h"

#include "safe_print.h"
#include "sem_print.h"

#include "socket_io.h"


// Must be true for the server accepting clients,
// otherwise, the server will terminate
static volatile sig_atomic_t server_running = false;
prog_options_t my_opt;

#define IS_ROOT_DIR(mode)   (S_ISDIR(mode) && ((S_IROTH || S_IXOTH) & (mode)))
#define PATH_MAX 4096

void error(const char *msg)
{
	perror(msg);
	exit(1);
}

//
// TODO: Include your function header here
//
static void
sig_handler(int sig)
{
	int status;
	pid_t pid;

    switch(sig) {
        case SIGINT:
            // use our own thread-safe implemention of printf
            safe_printf("\n[%d] Server terminated due to keyboard interrupt\n", getpid());
            server_running = false;
            exit(0);
            break;
        case SIGCHLD: // TODO: Reutemann fragen wie aufgerufen und was dahinter steckt
        	while((pid=wait3(&status, WNOHANG, (struct rusage *)0)) > 0)
        		printf("Child finished, pid %d.\n", pid);
        	break;

        default:
            break;
    } /* end switch */
} /* end of sig_handler */


//
// TODO: Include your function header here
//
static void
print_usage(const char *progname)
{
  fprintf(stderr, "Usage: %s options\n", progname);
  // TODO: Print the program options
} /* end of print_usage */


//
// TODO: Include your function header here
//
static int
get_options(int argc, char *argv[], prog_options_t *opt)
{
    int                 c;
    int                 err;
    int                 success = 1;
    char               *p;
    struct addrinfo     hints;

    p = strrchr(argv[0], '/');
    if(p) {
        p++;
    } else {
        p = argv[0];
    } /* end if */

    opt->progname = (char *)malloc(strlen(p) + 1);
    if (opt->progname != NULL) {
        strcpy(opt->progname, p);
    } else {
        err_print("cannot allocate memory");
        return EXIT_FAILURE;
    } /* end if */

    opt->log_filename = NULL;
    opt->root_dir     = NULL;
    opt->server_addr  = NULL;
    opt->verbose      =    0;
    opt->timeout      =  120;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;   /* Allows IPv4 or IPv6 */
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

    while (success) {
        int option_index = 0;
        static struct option long_options[] = {
            { "file",    required_argument, 0, 0 },
            { "port",    required_argument, 0, 0 },
            { "dir",     required_argument, 0, 0 },
            { "verbose", no_argument,       0, 0 },
            { "debug",   no_argument,       0, 0 },
            { NULL,      0, 0, 0 }
        };

        c = getopt_long(argc, argv, "f:p:d:v", long_options, &option_index);
        if (c == -1) break;

        switch(c) {
            case 'f':
                // 'optarg' contains file name
                opt->log_filename = (char *)malloc(strlen(optarg) + 1);
                if (opt->log_filename != NULL) {
                    strcpy(opt->log_filename, optarg);
                } else {
                    err_print("cannot allocate memory");
                    return EXIT_FAILURE;
                } /* end if */
                break;
            case 'p':
                // 'optarg' contains port number
                if((err = getaddrinfo(NULL, optarg, &hints, &opt->server_addr)) != 0) {
                    fprintf(stderr, "Cannot resolve service '%s': %s\n", optarg, gai_strerror(err));
                    return EXIT_FAILURE;
                } /* end if */
                break;
            case 'd':
                // 'optarg contains root directory */
                opt->root_dir = (char *)malloc(strlen(optarg) + 1);
                if (opt->root_dir != NULL) {
                    strcpy(opt->root_dir, optarg);
                } else {
                    err_print("cannot allocate memory");
                    return EXIT_FAILURE;
                } /* end if */
                break;
            case 'v':
                opt->verbose = 1;
                break;
            default:
                success = 0;
        } /* end switch */
    } /* end while */

    // check presence of required program parameters
    success = success && opt->server_addr && opt->root_dir;

    // additional parameters are silently ignored, otherwise check for
    // ((optind < argc) && success)

    return success;
} /* end of get_options */


static void
open_logfile(prog_options_t *opt)
{
    // open logfile or redirect to stdout
    if (opt->log_filename != NULL && strcmp(opt->log_filename, "-") != 0) {
        opt->log_fd = fopen(opt->log_filename, "w");
        if (opt->log_fd == NULL) {
            perror("ERROR: Cannot open logfile");
            exit(EXIT_FAILURE);
        } /* end if */
    } else {
        printf("Note: logging is redirected to stdout.\n");
        opt->log_fd = stdout;
    } /* end if */
} /* end of open_logfile */


static void
check_root_dir(prog_options_t *opt)
{
    struct stat stat_buf;

    // check whether root directory is accessible
    if (stat(opt->root_dir, &stat_buf) < 0) {
        /* root dir cannot be found */
        perror("ERROR: Cannot access root dir");
        exit(EXIT_FAILURE);
    } else if (!IS_ROOT_DIR(stat_buf.st_mode)) {
        err_print("Root dir is not readable or not a directory");
        exit(EXIT_FAILURE);
    } /* end if */
} /* end of check_root_dir */


static void
install_signal_handlers(void)
{
    struct sigaction sa;

    // init signal handler(s)
    // TODO: add other signals
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sig_handler;
    if(sigaction(SIGINT, &sa, NULL) < 0) {
        perror("sigaction(SIGINT)");
        exit(EXIT_FAILURE);
    } /* end if */
} /* end of install_signal_handlers */

int server_init(int port)
{
		int sockfd;
		struct sockaddr_in server_addr;

		// TODO: Error handling if not already done for valid or available Port

		sockfd = socket(AF_INET, SOCK_STREAM, 0);

		if(sockfd < 0)
		{
			error("Error opening socket");
			exit(-1);
		}

		bzero((char *) &server_addr, sizeof(server_addr));

		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = INADDR_ANY;
		server_addr.sin_port = htons(port);

		if(bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
		{
			error("Error on binding\n");
			exit(-1);
		}

		puts("Listen\n");
		listen(sockfd, 5);

		return sockfd;
}


void client_connection(int sockfd)
{
	int newsockfd;
	socklen_t clilen;
	struct sockaddr_in cli_addr;
	pid_t pid;

	clilen = sizeof(cli_addr);
	newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

	printf("Process ID: %i\n", getpid());

	if(newsockfd < 0)
	{
		error("Listen");
	}
	switch (pid = fork())
	{
	case -1: error("Error on fork\n");
		break;
	case 0: child_processing(newsockfd);
		break;
	default: printf("You are in the Fatherprocess: %d\n", getpid());
		break;
	}
}

void child_processing(int newsockfd)
{
	int read_error;
	int file_to_send;
	char buffer[256];
	char *ptr;
	char *path_to_file;
	char response_header;

	printf("You are in the Childprocess: %d\n", getpid());
	bzero(buffer, 256);
	read_error = read(newsockfd, buffer, 255);
	if(read_error < 0)
	{
		error("Error reading from socket");
	}
	path_to_file = parse_HTTP_msg(buffer);
	//printf("%s", path_to_file);
	char actualpath [PATH_MAX];
	//path_to_file = "/home/git/tinyweb/distsys-master/distsys-master/pe/tinyweb/web/index.html";

	ptr = realpath(path_to_file, actualpath);
	printf("Realpath to File: %s\n", ptr);
	if((file_to_send = open(ptr, O_RDWR, S_IWRITE | S_IREAD)) < 0)
		{
			error("Error opening file");
		}
	printf("File to send: %i\n", file_to_send);
	response_header = create_HTTP_response_header(700, ptr);
	send(newsockfd, &response_header, strlen(&response_header), 0);
	if(write_to_socket(file_to_send, buffer, 256, 1) < 0)
	{
		error("Error writing to socket");
	}

	printf("Here is the message: %s\n", buffer);

	if(read_error < 0)
	{
		error("Error writing to socket");
	}
	close(newsockfd);
}

char create_HTTP_response_header(int status, const char *filename)
{
	char response_header[4096];
	char status_text[100] = "HTTP/1.1 %i Partial Content\n";
	char date_text[100] = "DATUM Funktion einbauen\n";
	char server_text[100] = "Server: TinyWeb (Build Jun 12 2014)\n";
	char accept_range_text[100] = "Accept-Ranges: bytes\n";
	char last_modiefied_text[100] = "Last-Modified: Thu, 12 Jun 2014\n";
	char content_type_text[100] = "Content-Type: text/html\n";
	char content_length_text[100] = "Content-Length: 1004\n";
	char content_range_text[100] = "Content-Range: bytes 6764-7767/7768\n";
	char connection_text[100] = "Connection: Close\n\n";

	// time calculating
	time_t t;
	struct tm *ts;

	t = time(NULL);
	ts = localtime(&t);

	//file length calculating
	struct stat buf;
	if(stat(filename, &buf) != 0)
	{
		printf("Error in file length calculating.\n");
	}

	sprintf(status_text, "HTTP/1.1 %i Partial Content\n", 700 ); //TODO: status dynamisch uebergeben
	sprintf(date_text, "Date: %s GMT\n", asctime(ts)); //TODO: Reutemann fragen ob das Format so passt
	//sprintf(server_text, "Server: TinyWeb (Build Jun 12 2014)", ); //TODO: Buildzeit dynamisch einfuegen
	//sprintf(last_modiefied_text, "Last-Modified: Thu, 12 Jun 2014\n", ); //TODO: Dateidatum einfuegen
	sprintf(content_type_text, "Content-Type: %s\n",  get_http_content_type_str(get_http_content_type(filename)));
	sprintf(content_length_text, "Content-Length: %i\n", (int) buf.st_size);
	//sprintf(content_range_text, "\n", ); //TODO: Frage was das ist und wie dynamisch abgefragt wird



	strcat(response_header, status_text);
	strcat(response_header, date_text);
	strcat(response_header, server_text);
	strcat(response_header, accept_range_text);
	strcat(response_header, last_modiefied_text);
	strcat(response_header, content_type_text);
	strcat(response_header, content_length_text);
	strcat(response_header, content_range_text);
	strcat(response_header, connection_text);
	printf("%s", response_header);

	return *response_header;
}

char* parse_HTTP_msg(char buffer[])
{
	char *p;
	char str_GET[] = "GET";
	char str_HEAD[] = "HEAD";
	char *path_to_file;
	p = strtok(buffer, " ");

	if(strcmp(p, str_GET) == 0)
	{
		p = strtok(NULL, " "); // p contains path to file
		for(int n=0; n < strlen(p); ++n)
		{
			p[n] = p[n+1];	//trim / from path
		}

		path_to_file = my_opt.root_dir;
		strcat(path_to_file, p);
		printf("Filepath: %s\n", path_to_file);
		return path_to_file;
	}

	if(strcmp(p, str_HEAD) == 0)
	{
		return 0;//TODO
	}
	return 0;
}


int
main(int argc, char *argv[])
{
	int sockfd;
    int retcode = EXIT_SUCCESS;


    // read program options
    if (get_options(argc, argv, &my_opt) == 0) {
        print_usage(my_opt.progname);
        exit(EXIT_FAILURE);
    } /* end if */

    // set the time zone (TZ) to GMT in order to
    // ignore any other local time zone that would
    // interfere with correct time string parsing
    setenv("TZ", "GMT", 1);
    tzset();
  /*  printf("Server Port: %d\n", my_opt.server_port);
    //printf("Server Address: %d\n", my_opt.server_addr);
    printf("Progname: %s\n", my_opt.progname);
    printf("Root Dir: %s\n", my_opt.root_dir);
    printf("Log File: %s\n", my_opt.log_filename); */

    // do some checks and initialisations...
    open_logfile(&my_opt);
    check_root_dir(&my_opt);
    install_signal_handlers();
    init_logging_semaphore();

    // TODO: start the server and handle clients...

    // here, as an example, show how to interact with the
    // condition set by the signal handler above
    printf("[%d] Starting server '%s'...\n", getpid(), my_opt.progname);
    server_running = true;
 //   prog_options_t *opt = &my_opt;
   // struct sockaddr_in port = (struct sockaddr_in) opt->server_addr->ai_addr;
    //int port = htons(addr_port->sin_port);
    sockfd = server_init(8080);

    while(server_running) {
    	client_connection(sockfd);
        //pause();
    } /* end while */

    printf("[%d] Good Bye...\n", getpid());
    exit(retcode);
} /* end of main */

