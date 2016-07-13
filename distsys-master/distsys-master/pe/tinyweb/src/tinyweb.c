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

#include <tinyweb.h>
#include "connect_tcp.h"
#include "content.h"
#include "http.h"


#include "safe_print.h"
#include "sem_print.h"

#include "socket_io.h"


// Must be true for the server accepting clients,
// otherwise, the server will terminate
static volatile sig_atomic_t server_running = false;
prog_options_t my_opt;
http_status_t status;

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

void set_http_status(http_status_t new_status)
{
	status = new_status;
	printf("Status gesetzt: %i-------\n", http_status_list[status].code);
}

http_status_t get_http_status(void)
{
	return status;
}

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

void write_to_logfile(struct sockaddr_in cli_addr, char *path_to_file_relativ, char buffer[], int read_count_bytes)
{
	FILE *f = fopen("logfile.txt", "a");
	if (f == NULL)
	{
	    printf("Error opening file!\n");
	    exit(1);
	}
   	time_t t;
   	struct tm *ts;

   	t = time(NULL);
   	ts = localtime(&t);

	char *p;
	struct sockaddr_in* pV4Addr = (struct sockaddr_in*)&cli_addr;
	struct in_addr ipAddr = pV4Addr->sin_addr;
	char str[INET_ADDRSTRLEN];
	inet_ntop( AF_INET, &ipAddr, str, INET_ADDRSTRLEN );
	p = strtok(buffer, " ");
	//printf("%s - - [%i/%s/%i:%02i:%02i:%02i +0200] \"%s %s\" %i %s %i\n", str, ts->tm_mday, get_month(ts->tm_mon), ts->tm_year + 1900, ts->tm_hour, ts->tm_min, ts->tm_sec, p, path_to_file_relativ, http_status_list[get_http_status()].code, http_status_list[get_http_status()].text, read_count_bytes);
	fprintf(f, "%s - - [%i/%s/%i:%02i:%02i:%02i +0200] \"%s %s\" %i %s %i\n", str, ts->tm_mday, get_month(ts->tm_mon), ts->tm_year + 1900, ts->tm_hour, ts->tm_min, ts->tm_sec, p, path_to_file_relativ, http_status_list[get_http_status()].code, http_status_list[get_http_status()].text, read_count_bytes);

}

void client_connection(int sockfd)
{
	int newsockfd;
	socklen_t clilen;
	struct sockaddr_in cli_addr;
	pid_t pid;

	//printf("Port in Client Connection: %i\n", sockfd);
	clilen = sizeof(cli_addr);
	newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

	printf("\nProcess ID: %i\n", getpid());

	if(newsockfd < 0)
	{
		error("Listen");
	}
	switch (pid = fork())
	{
	case -1: error("Error on fork\n");
		break;
	case 0: child_processing(newsockfd, cli_addr);
			close(newsockfd);
			printf("[%d] Closing child process!\n\n", getpid());
		break;
	default: close(newsockfd);
		//printf("You are in the Fatherprocess: %d\n", getpid());
		break;
	}
}

void child_processing(int newsockfd, struct sockaddr_in cli_addr)
{
	int read_error;
	int file_to_send = 0;
	char buffer[BUFFER_SIZE];
	char *buffer_for_log;
	char *ptr;
	char *p;
	char *path_to_file_relativ;
	char *response_header;
	char str_GET[] = "GET";
	char str_HEAD[] = "HEAD";

	set_http_status(HTTP_STATUS_OK);
	//printf("You are in the Childprocess: %d\n", getpid());
	bzero(buffer, BUFFER_SIZE);
	read_error = read(newsockfd, buffer, BUFFER_SIZE - 1);
	buffer_for_log = buffer;
	ptr = "";

	if(read_error < 0)
	{
		error("Error reading from socket");
		set_http_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
	}
	path_to_file_relativ = parse_HTTP_msg(buffer);
	//printf("Path to file relativ: %s\n", path_to_file_relativ);
	char actualpath [PATH_MAX];

	p = strtok(buffer, " ");

	ptr = realpath(path_to_file_relativ, actualpath);



	printf("Realpath to File: %s\n", actualpath);
	printf("Ptr: %s\n", ptr);

	if(strcmp(p, str_GET) == 0)
	{
		if( access( actualpath, F_OK ) == -1 )
		{
			printf("NOT FOUND ACCESS GET ");
			set_http_status(HTTP_STATUS_NOT_FOUND);
		}
		//printf("........test.............");
		if((file_to_send = open(actualpath, O_RDWR, S_IWRITE | S_IREAD)) < 0)
			{
			printf("NOT FOUND FILE TO SEND GET ");
				set_http_status(HTTP_STATUS_NOT_FOUND);
				response_header = create_HTTP_response_header(actualpath, buffer);
				send(newsockfd, response_header, strlen(response_header), 0);
				error("Error opening file");
			}
		//printf("File to send: %i\n", file_to_send);
	}

	if(strcmp(p, str_HEAD) == 0)
	{
		struct stat buf;
		int check;
		check = stat(actualpath, &buf);
		if(check < 0)
		{
			printf("NOT FOUND ACCESS HEAD ");
			set_http_status(HTTP_STATUS_NOT_FOUND);
		} else{
			set_http_status(HTTP_STATUS_OK);
		}
	}


	response_header = create_HTTP_response_header(actualpath, buffer);
	send(newsockfd, response_header, strlen(response_header), 0);

	if(strcmp(p, str_GET) == 0)
	{
	int read_count_bytes = read(file_to_send, buffer, BUFFER_SIZE);
	int read_count_bytes_for_log = read_count_bytes;
	while(read_count_bytes > 0)
	{
		if(write_to_socket(newsockfd, buffer, read_count_bytes, 1) < 0)
			{
				error("Error writing to socket");
				set_http_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
			}
		read_count_bytes = read(file_to_send, buffer, BUFFER_SIZE);
		read_count_bytes_for_log += read_count_bytes;

	}
	if(read_count_bytes < 0)
	{
		error("Error reading from socket");
		set_http_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
	}

	//printf("Here is the message: %.*s\n", read_count_bytes, buffer);

	if(read_error < 0)
	{
		error("Error writing to socket");
		set_http_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
	}
	write_to_logfile(cli_addr, path_to_file_relativ, buffer_for_log, read_count_bytes_for_log);
	}
	close(newsockfd);
}

char* create_HTTP_response_header(const char *filename, char buffer[])
{
	//printf("................\n");
	char* response_header = (char*) malloc(BUFFER_SIZE);
	int range_end;
	int range_start = 0;
	int content_length;
	char *ptr;
	char *lineRange = NULL;
	//char *lineModified = NULL;



	if(response_header == NULL)
	{
		error("Error allocating response_header");
	}
	char status_text[100] = "HTTP/1.1 %i Partial Content\r\n";
	char date_text[100] = "DATUM Funktion einbauen\r\n";
	char server_text[100] = "Server: TinyWeb (Build Jun 12 2014)\r\n";
	char accept_range_text[100] = "Accept-Ranges: bytes\r\n";
	char last_modified_text[100] = "Last-Modified: Thu, 12 Jun 2014\r\n";
	char content_type_text[100] = "Content-Type: text/html\r\n";
	char content_length_text[100] = "Content-Length: 1004\r\n";
	char content_range_text[100] = "Content-Range: bytes 6764-7767/7768\r\n";
	char connection_text[100] = "Connection: Close\r\n\r\n";

	//file length calculating
	struct stat buf;
	if(stat(filename, &buf) != 0)
	{
		printf("Error in file length calculating.\n");
	}

   	//set_http_status(HTTP_STATUS_PARTIAL_CONTENT);
   	time_t t;
   	struct tm *ts;

   	t = time(NULL);
   	ts = localtime(&t);

   	struct stat file_Info;





	sprintf(status_text, "HTTP/1.1 %i %s\r\n", http_status_list[get_http_status()].code, http_status_list[get_http_status()].text ); //TODO: status dynamisch uebergeben
	sprintf(date_text, "Date: %s, %i %s %i %02i:%02i:%02i GMT\r\n", get_weekday(ts->tm_wday), ts->tm_mday, get_month(ts->tm_mon), ts->tm_year + 1900, ts->tm_hour, ts->tm_min, ts->tm_sec); //TODO: Reutemann fragen ob das Format so passt
	//sprintf(server_text, "Server: TinyWeb (Build Jun 12 2014)", ); //TODO: Buildzeit dynamisch einfuegen


	ptr = strtok(NULL, "\n");
	while (ptr != NULL) {
		// extract line with the range if existing
		if (strncmp(ptr,"Range",5) == 0) {
			lineRange = ptr;
		}
		else if ((strncmp(ptr,"If-Modified-Since",strlen("If-Modified-Since"))) == 0) {
			//lineModified = ptr;
		}
		ptr = strtok(NULL, "\n");
	}

	if (lineRange != NULL) {
		char *range = malloc(strlen(lineRange)+1);
		if (range == NULL) {
			perror("Malloc():");
		}
		strtok(lineRange,"=");
		range = strtok(NULL,"="); // after "="
		range_start = atoi(strtok(range,"-"));
		range_end = atoi(strtok(NULL,"-"));

		//printf("Start: %i End: %i", range_start, range_end);
	}



		int check;
		check = stat(filename, &file_Info);

		if (check < 0) {
			printf("NOT FOUND ACCESS CHECK ");
			set_http_status(HTTP_STATUS_NOT_FOUND);
		}

	   	// get last modified
		char* last_modified = malloc(32);
	   	struct tm * timeinfo;
	   	timeinfo = localtime(&file_Info.st_mtim.tv_sec);

	   	strftime (last_modified,32,"%a, %d %b %Y %H:%M:%S %Z",timeinfo);

	sprintf(last_modified_text, "Last-Modified: %s\n", last_modified); //TODO: Dateidatum einfuegen
	sprintf(content_type_text, "Content-Type: %s\r\n",  get_http_content_type_str(get_http_content_type(filename)));



	range_end = file_Info.st_size;

	if(range_end < 0)
	{
		error("Error with range");
	}
	else
	{
		content_length = range_end - range_start;
	}

	sprintf(content_length_text, "Content-Length: %i\r\n", content_length);
	sprintf(content_range_text, "Content-Range: bytes %i-%i/%i\n", range_start, range_end, content_length ); //TODO: Frage was das ist und wie dynamisch abgefragt wird

	strcat(response_header, status_text);
	strcat(response_header, date_text);
	strcat(response_header, server_text);
	strcat(response_header, accept_range_text);
	strcat(response_header, last_modified_text);
	strcat(response_header, content_type_text);
	strcat(response_header, content_length_text);
	strcat(response_header, content_range_text);
	strcat(response_header, connection_text);
	printf("\n------------Response-----------------\n%s------------Response-----------------\n", response_header);

	return response_header;
}

char* get_month(int month)
{
	switch(month)
	{
	case 0: return "Jan";
	case 1: return "Feb";
	case 2: return "Mar";
	case 3: return "Apr";
	case 4: return "Mai";
	case 5: return "Jun";
	case 6: return "Jul";
	case 7: return "Aug";
	case 8: return "Sep";
	case 9: return "Okt";
	case 10: return "Nov";
	case 11: return "Dec";
	default: return "Month not found.";
	}
}

char* get_weekday(int weekday)
{
	switch(weekday)
	{
	case 0: return "Sun";
	case 1: return "Mon";
	case 2: return "Tue";
	case 3: return "Wed";
	case 4: return "Thu";
	case 5: return "Fri";
	case 6: return "Sat";
	default: return "Day not found!";
	}
}

char* calculate_timestamp()
{
	time_t t;
	struct tm *ts;

	t = time(NULL);
	ts = localtime(&t);

	return asctime(ts);
}

char* parse_HTTP_msg(char buffer[])
{

	char *p;
	char str_GET[] = "GET";
	char str_HEAD[] = "HEAD";
	char *path_to_file;

	printf("\n---------Request-------------\n%s", buffer);

	p = strtok(buffer, " ");
	//printf("Buffer after strtok: %s\n", buffer);
	prog_options_t *opt = &my_opt;

	if(strcmp(p, str_GET) == 0 || strcmp(p, str_HEAD) == 0)
	{
		p = strtok(NULL, " "); // p contains path to file
		/*for(int n=0; n < strlen(p); ++n)
		{
			p[n] = p[n+1];	//trim / from path
		}*/



		//strlen von opt->root_dir
		int lenStr = strlen(opt->root_dir);
		path_to_file = malloc (lenStr + 24); //Bei + 24 tritt malloc overflow nicht mehr auf
		//Fehlerbehandlung von malloc falls ptr ==0 TODO
		//strcpy ptr, root_dir

		strcpy(path_to_file, opt->root_dir);
		strcat(path_to_file, p);
		return path_to_file;
	}
	else
	{
		set_http_status(HTTP_STATUS_NOT_IMPLEMENTED);
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
    //printf("[%d] Starting server '%s'...\n", getpid(), my_opt.progname);
    server_running = true;
    prog_options_t *opt = &my_opt;
    struct sockaddr_in* struct_port = (struct sockaddr_in*) opt->server_addr->ai_addr;
    sockfd = server_init(ntohs(struct_port->sin_port));

    //printf("Port: %i \n", sockfd);
    while(server_running) {

    	client_connection(sockfd);
        //pause();
    } /* end while */

    printf("[%d] Good Bye...\n", getpid());
    exit(retcode);
} /* end of main */

