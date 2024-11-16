#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <regex.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

/*A structure for connection information.*/
typedef struct {
    int imaps;
    int sock;
    SSL *ssl;
    SSL_CTX *ctx;
} Connection;

/*A structure for CLI arguments.*/
typedef struct {
    char *server;
    char *port;
    int imaps;
    char *cert_file;
    char *cert_addr;
    int new_only;
    int headers_only;
    char *auth_file;
    char *mailbox;
    char *out_dir;
} Args;

void error_exit(char *msg, int code);
char *get_server(int argc, char *argv[]);
int connect_to_imap(char *server, char *port);
int connect_to_imaps(char *server, char *port, char *cert_file, char *cert_addr, SSL_CTX **ctx_out, SSL **ssl_out);
void cleanup_connection(Connection conn);
void parse_auth_file(char *auth_file, char *username, char *password);
void send_imap_message(Connection conn, char *message);
char *receive_imap_message(Connection conn);
int imap_command(int *current_message_count, Connection conn, char *response_p, char *command_format, ...);
void login_to_imap(int *current_message_count, Connection conn, char *username, char *password);
void select_mailbox(int *current_message_count, Connection conn, char *mailbox);
char *search_mails(int *current_message_count, Connection conn, char *search_mails_filter);
char *construct_message(Connection conn, int *current_message_count, char *text);
void handshake(Connection conn);
char *fetch_message(int *current_message_count, Connection conn, int message_id, char *request_type);
int get_message_length(char *fetch_response, int *body_start);
char *get_id_from_header(char *fetch_response);
void logout(int *current_message_count, Connection conn);
int header_id_in_log(char *header_id, FILE *log_file, int *line_index);
Args parse_args(int argc, char *argv[]);

/*A function to print error message and exit.*/
void error_exit(char *msg, int code) {
    if (msg != NULL)
        fprintf(stderr, "%s\n", msg);
    exit(code);
}

/*A function that extracts the server from CLI arguments and implies that the arguments are correct.*/
char *get_server(int argc, char *argv[]){
    int i=1;
    while (i <argc){
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "-c") == 0 ||strcmp(argv[i], "-C") == 0 || strcmp(argv[i], "-b") == 0  || strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "-o") == 0){
            i+=2;
        }
        else if (strcmp(argv[i], "-T") == 0 || strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "-h") == 0){
            i++;
        }
        else{
            return argv[i];
        }
    }
    return NULL;
}

/*A function that connects to an IMAP server using the specified server address and port.*/
int connect_to_imap(char *server, char *port){
    struct addrinfo hints, *res, *p;
    int sock, status;
    struct timeval tv;  

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    /* Resolves the server address and port using getaddrinfo.*/
    if ((status = getaddrinfo(server, port, &hints, &res)) != 0) {
        char error_str[256];
        snprintf(error_str, sizeof(error_str), "Getaddrinfo error: %s", gai_strerror(status));
        error_exit(error_str, EXIT_FAILURE);
    }
    /* Loop through the resolved address list and attempts to connect.*/
    for (p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == -1) {
            continue;
        }
        /*Set a 5-second timeout for sending and receiving operations.*/
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
        
        /*Closes the socket and tries the next address if failed to connect.*/
        if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock);
            continue;
        }
        break;
    }

    freeaddrinfo(res);

    
    /*If no address was able to connect, exits with an error.*/
    if (p == NULL) {
        error_exit("Failed to connect to server.", EXIT_FAILURE);
    }

    return sock;
}

/*A function that establishes a secure connection to an IMAP server using SSL/TLS.*/
int connect_to_imaps(char *server, char *port, char *cert_file, char *cert_addr, SSL_CTX **ctx_out, SSL **ssl_out) {
    /* Initialize the OpenSSL library.*/
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    /*Creates a new SSL/TLS client context.*/
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        error_exit("Failed to create SSL context.", EXIT_FAILURE);
    }
    
    /* Sets default paths for trusted CA certificates. */
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        error_exit("Failed to set default verify paths.", EXIT_FAILURE);
    }

    /* Loads the provided certificate file or directory for server verification. */
    if (!SSL_CTX_load_verify_locations(ctx, (cert_file == NULL ? NULL : cert_file), cert_addr)) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        error_exit("Failed to load certificate.", EXIT_FAILURE);
    }

    /* Establishes an unencrypted IMAP connection first.*/
    int sock = connect_to_imap(server, port);
    if (sock < 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        error_exit("Failed to establish IMAP connection.", EXIT_FAILURE);
    }

    /*Binds the SSL structure to the socket file descriptor.*/
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        error_exit("SSL connection failed.", EXIT_FAILURE);
    }
    *ctx_out = ctx;
    *ssl_out = ssl;
    return sock;
}

/* Cleans up the connection by closing the socket and freeing SSL/TLS resources if needed. */
void cleanup_connection(Connection conn) {
    if (conn.imaps){
        SSL_shutdown(conn.ssl);
        SSL_free(conn.ssl);
        SSL_CTX_free(conn.ctx);
        ERR_free_strings();
        EVP_cleanup();
    }
    close(conn.sock);
}

/* Gets username and password from authentication file. */
void parse_auth_file(char *auth_file, char *username, char *password) {
    FILE *file = fopen(auth_file, "r");
    if (!file) {
        error_exit("Failed to open auth file.", EXIT_FAILURE);
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "username", 8) == 0) {
            sscanf(line, "username = %s", username);
        } else if (strncmp(line, "password", 8) == 0) {
            sscanf(line, "password = %s", password);
        }
    }
    fclose(file);
}

/* Sends an IMAP message to the server through an established connection.*/
void send_imap_message(Connection conn, char *message) {
    if (conn.imaps){
        /* Sends the message securely using SSL_write. */
        if (SSL_write(conn.ssl, message, strlen(message)) <= 0) {
            cleanup_connection(conn);
            free(message);
            error_exit("Failed to send IMAP message through SSL.", EXIT_FAILURE);
        }
    }
    else{
        /* Sends the message over an unencrypted socket connection. */
        if (send(conn.sock, message, strlen(message), 0) == -1) {
            cleanup_connection(conn);
            free(message);
            error_exit("Failed to send IMAP message.", EXIT_FAILURE);
        }
    }
}

/*A function that receives a message from the server.*/
char *receive_imap_message(Connection conn){
    size_t buffer_size = 100000;
    char buffer[buffer_size];
    /* Allocates memory for the full response*/
    char *response = calloc(10000000, 1);
    if (response == NULL) {
        cleanup_connection(conn);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    int received;
    /*If the connection is using IMAP.*/
    if (conn.imaps){
        /* Reads data in a loop until a complete message is received.*/
        while ((received = SSL_read(conn.ssl, buffer, buffer_size)) > 0) {
            /* Null-terminates the buffer. */
            buffer[received] = '\0'; 
            /* Appends received data to the response. */
            strcat(response, buffer); 
            /* Checks for end of message indicated by "\r\n" and exits the loop.*/
            if (strstr(response, "\r\n")) { 
                break;
            }
        }
    }
    /*If the connection is  unencrypted.*/
    else{
        while ((received = recv(conn.sock, buffer, buffer_size, 0)) > 0) {
            buffer[received] = '\0';
            strcat(response, buffer);
            if (strstr(response, "\r\n")) {
                break;
            }
        }
    }
    /* Checks if an error is encountered. */
    if (received < 0) {
        cleanup_connection(conn);
        free(response);
        error_exit("Failed to receive response.", EXIT_FAILURE);
    }
    /* Checks if the connection was closed by the server. */
    else if (received == 0) {
        cleanup_connection(conn);
        free(response);
        error_exit("Connection closed by peer.", EXIT_FAILURE);
    }
    return response;
}

/* The function formats the command string, constructs an IMAP message with the current message count,
 sends it over the connection, and processes the server's response (checks the response status).*/
int imap_command(int *current_message_count, Connection conn, char *response_p, char *command_format, ...) {
    char *text = calloc(4096, 1);
    if (text == NULL) {
        cleanup_connection(conn);
        free(response_p);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }

    va_list args;
    va_start(args, command_format);
    vsnprintf(text, 4096, command_format, args);
    va_end(args);

    /*Consructs message with the count. */
    char *message = construct_message(conn, current_message_count, text);
    free(text);
    
    /* Sends the IMAP message to the server. */
    send_imap_message(conn, message);
    free(message);

    /* Receives the response from the server.*/
    char *response = receive_imap_message(conn);
    int received_ID;

    strcpy(response_p, response);

    /* Tokenizes the response to process it line by line.*/
    char *line = strtok(response, "\n");

    while (line != NULL) {
        /* Checks for a successful "OK" response with a matching message count ID. */
        if (sscanf(line, "A%d OK", &received_ID) > 0) {
            if (received_ID == *current_message_count) {
                free(response);
                (*current_message_count)++;
                return 0;
            }
        }
        /* Checks for a "BAD" or "NO" response with a matching message count ID.*/
        else if (sscanf(line, "A%d BAD", &received_ID) > 0 || sscanf(line, "A%d NO", &received_ID) > 0) {
            if (received_ID == *current_message_count) {
                free(response);
                (*current_message_count)++;
                return 1;
            }
        }

        line = strtok(NULL, "\n");
    }

    free(response);
    (*current_message_count)++;
    return 1;

}

/*A function that sends a LOGIN command with a username and password. */
void login_to_imap(int *current_message_count, Connection conn, char *username, char *password) {
    char *response = calloc(16384, 1);
    if (response == NULL) {
        cleanup_connection(conn);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    if (imap_command(current_message_count, conn, response, "LOGIN %s %s", username, password) == 1){
        free(response);
        cleanup_connection(conn);
        error_exit("Failed to login.", EXIT_FAILURE);
    }
    free(response);
}

/*A function that sends a SELECT command with a specified mailbox. */
void select_mailbox(int *current_message_count, Connection conn, char *mailbox){
    char *response = calloc(16384, 1);
    if (response == NULL) {
        cleanup_connection(conn);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    if (imap_command(current_message_count, conn, response, "SELECT %s", mailbox) == 1){
        free(response);
        cleanup_connection(conn);
        error_exit("Failed to select the mailbox.", EXIT_FAILURE);
    }
    free(response);
}

/*A function that sends a SEARCH command with or without a filtering for new mails. */
char *search_mails(int *current_message_count, Connection conn, char *search_mails_filter){
    char *response = calloc(16384, 1);
    if (response == NULL) {
        cleanup_connection(conn);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    char *response_body = calloc(16384, 1);
    if (response_body == NULL) {
        cleanup_connection(conn);
        free(response);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    if (imap_command(current_message_count, conn, response, "SEARCH %s", search_mails_filter) == 1){
        free(response);
        free(response_body);
        cleanup_connection(conn);
        error_exit("Failed to search mails.", EXIT_FAILURE);
    }

    /*This part extracts the body of the search response and cuts out the response status.*/
    int last_index = strlen(response) - 2;
    
    while (last_index > 0 && response[last_index] != '\n') {
        last_index--;
    }
    strncpy(response_body, response, last_index);
    free(response);
    return response_body;
}

/*Formats the message to be correctly sent to the server.*/
char *construct_message(Connection conn, int *current_message_count, char *text){
    char *message = calloc(4096, 1);
    if (message == NULL) {
        cleanup_connection(conn);
        free(text);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    snprintf(message, 4096, "A%d %s\r\n", *current_message_count, text);
    return message;
}

/*A function that gets the greeting from the server after connection.*/
void handshake(Connection conn) {
    char *greeting;
    if (conn.imaps)
        greeting = receive_imap_message(conn);
    else
        greeting = receive_imap_message(conn);
    if (strstr(greeting, "OK")) {
        free(greeting);
    } else {
        free(greeting);
        cleanup_connection(conn);
        error_exit("Failed to get the server greeting.", EXIT_FAILURE);
    }
}

/* Fetches an email message from the IMAP server, the function constructs an IMAP "FETCH" command, sends it to the server, 
and receives the full response, which may span multiple server responses. The function dynamically reallocates memory for large messages.*/
char *fetch_message(int *current_message_count, Connection conn, int message_id, char *request_type) {
    size_t fetch_size = 10000000;
    char *full_fetch_response = calloc(fetch_size, 1);
    if (full_fetch_response == NULL) {
        cleanup_connection(conn);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    char *text = calloc(4096, 1);
    if (text == NULL) {
        free(full_fetch_response);
        cleanup_connection(conn);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    /* Formats the FETCH command string with the message ID and request type. */
    snprintf(text, 4096, "FETCH %d %s", message_id, request_type);
    char *message = construct_message(conn, current_message_count, text);
    free(text);
    /*Sends a command.*/
    send_imap_message(conn, message);
    free(message);
    int success = 0;
    /*Continue receiving the server's response until the fetch is completed.*/
    while (!success) {
        char *response = receive_imap_message(conn);
        int received_ID;
        
        size_t current_length = strlen(full_fetch_response);
        size_t response_length = strlen(response);

        /*If the total size exceeds the current buffer, doubles the buffer size.*/
        if (current_length + response_length >= fetch_size) {
            fetch_size *= 2;
            char *new_full_fetch_response = realloc(full_fetch_response, fetch_size);
            if (new_full_fetch_response == NULL) {
                free(full_fetch_response);
                free(response);
                cleanup_connection(conn);
                error_exit("Failed to reallocate memory.", EXIT_FAILURE);
            }
            full_fetch_response = new_full_fetch_response;
        }

        /*Appends the received response to the full fetch response.*/
        strcat(full_fetch_response, response);
        
        char *line = strtok(response, "\n");
        /*Process each line of the response to check if the fetch is completed or failed.*/
        while (line != NULL) {
            /* Checks for a successful "OK" response with a matching message count ID. */
            if (sscanf(line, "A%d OK FETCH completed", &received_ID) > 0) {
                if (received_ID == *current_message_count) {
                    success = 1;
                    break;
                }
            }
            /* Checks for a "BAD" or "NO" response with a matching message count ID.*/
            else if(sscanf(line, "A%d NO", &received_ID) > 0 || sscanf(line, "A%d BAD", &received_ID) > 0){
                free(response);
                free(full_fetch_response);
                error_exit("Failed to fetch mails.", EXIT_FAILURE);
            }

            line = strtok(NULL, "\n");
        }
        free(response);
    }

    (*current_message_count)++;
    return full_fetch_response;
}

/* Extracts the length of the message body from the FETCH response by searching for a pattern "{message_length}".*/
int get_message_length(char *fetch_response, int *body_start) {
    regex_t regex;
    regmatch_t match[1];
    /*Regex pattern.*/
    char pattern[] = "\\{([0-9]+)\\}";
    char result[40];
    /*Searches for the first newline.*/
    char *newline_pos = strchr(fetch_response, '\n');
    int index = newline_pos - fetch_response;
    char first_line[index + 1];
    /*Stores the start of the message body to a pointer.*/
    if (body_start != NULL) {
        *body_start = index + 1;
    }
    /*Copies the first line into a separate string.*/
    strncpy(first_line, fetch_response, index);
    first_line[index] = '\0';

    /*Compiles the regex pattern.*/
    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        error_exit("Failed to compile regex.", EXIT_FAILURE);
    }
    /* Executes the regex on the substring to search for the {number} pattern. */
    if (regexec(&regex, first_line, 1, match, 0) == 0) {
        int len = match[0].rm_eo - match[0].rm_so;
        strncpy(result, first_line + match[0].rm_so + 1, len - 1);
        result[len] = '\0';

        int message_length = atoi(result);
        regfree(&regex);
        return message_length;
    } else {
        regfree(&regex);
        error_exit("Failed to get message length.", EXIT_FAILURE);
    }
    return 0;
}

/*Extracts the Message-ID from the fetch response.*/
char *get_id_from_header(char *fetch_response) {
    regex_t regex;
    regmatch_t match[2];
    /* Regex pattern to match the Message-ID inside angle brackets.*/
    char *pattern = "<([^>]+)>";
    /* Looks for the "Message-ID" or "Message-Id" field line in the response*/
    char *message_id_line = strstr(fetch_response, "Message-ID:");
    if (!message_id_line) {
        message_id_line = strstr(fetch_response, "Message-Id:");
    }
    if (!message_id_line) {
        error_exit("Failed to extract message ID line.", EXIT_FAILURE);
    }

    /*Compiles the regex pattern.*/
    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        error_exit("Failed to compile regex.", EXIT_FAILURE);
    }

    /*Executes the regex on the substring to search for the <number> pattern. */
    if (regexec(&regex, message_id_line, 2, match, 0) == 0) {
        int len = match[1].rm_eo - match[1].rm_so;
        char *message_id = (char *)malloc(len + 1);
        strncpy(message_id, message_id_line + match[1].rm_so, len);
        message_id[len] = '\0';
        regfree(&regex);
        return message_id;
    } else {
        regfree(&regex);
        error_exit("Failed to extract message ID.", EXIT_FAILURE);
    }
    return NULL;
}

/*A function that sends a LOGOUT command.*/
void logout(int *current_message_count, Connection conn){
    char *response = calloc(16384, 1);
    if (response == NULL) {
        cleanup_connection(conn);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    if (imap_command(current_message_count, conn, response, "LOGOUT") == 1){
        free(response);
        cleanup_connection(conn);
        error_exit("Failed to logout.", EXIT_FAILURE);
    }
    free(response);
}

/*A function that searches for a message ID in the log file to avoid the duplicates.*/
int header_id_in_log(char *header_id, FILE *log_file, int *line_index) {
    char line[4096];
    int line_count = 0;
    rewind(log_file); 
    while (fgets(line, sizeof(line), log_file)) {
        line[strcspn(line, "\n")] = 0; 
        if (strcmp(line, header_id) == 0) {
            *line_index = line_count;
            return 1;
        }
        line_count++;
    }
    *line_index = line_count;
    return 0;
}

/*A function that parses CLI arguments using getopt.*/
Args parse_args(int argc, char *argv[]){
    Args args;

    args.server = NULL;
    args.port = NULL;
    args.imaps = 0;
    args.cert_file = NULL;
    args.cert_addr = "/etc/ssl/certs";
    args.new_only = 0;
    args.headers_only = 0;
    args.auth_file = NULL;
    args.mailbox = "INBOX";
    args.out_dir = NULL;
    
    int opt;

    /*Gets the server name.*/
    if (!(args.server = get_server(argc, argv))) {
        error_exit("Missing server or IP address argument.", EXIT_FAILURE);
    }

    while ((opt = getopt(argc, argv, "p:Tc:C:nhb:a:o:")) != -1) {
        switch (opt) {
            case 'p':
                args.port = optarg;
                break;
            case 'T':
                args.imaps = 1;
                break;
            case 'c':
                args.cert_file = optarg;
                break;
            case 'C':
                args.cert_addr = optarg;
                break;
            case 'n':
                args.new_only = 1;
                break;
            case 'h':
                args.headers_only = 1;
                break;
            case 'a':
                args.auth_file = optarg;
                break;
            case 'b':
                args.mailbox = optarg;
                break;
            case 'o':
                args.out_dir = optarg;
                break;
            default:
                error_exit("Usage: imapcl server [-p port] [-T [-c certfile] [-C certaddr]] [-n] [-h] -a auth_file [-b MAILBOX] -o out_dir.", EXIT_FAILURE);
        }
    }

    /*Checks for the required arguments.*/
    if (!args.auth_file || !args.out_dir) {
        error_exit("Missing required argument -a auth_file or -o out_dir.", EXIT_FAILURE);
    }
    
    if (argc < 6) {
        error_exit("Usage: imapcl server [-p port] [-T [-c certfile] [-C certaddr]] [-n] [-h] -a auth_file [-b MAILBOX] -o out_dir.", EXIT_FAILURE);
    }

    /*Sets the default port.*/
    if (!args.port){
        args.port = args.imaps ? "993" : "143";
    }
    return args;

}

int main(int argc, char *argv[]) {
    /*Parses arguments and stores them in the 'args' structure.*/
    Args args = parse_args(argc, argv); 

    char username[256];
    char password[256];

    /*Parses an authentication file.*/
    parse_auth_file(args.auth_file, username, password);
    int current_message_count = 0;

    Connection conn;
    conn.sock = 0;
    conn.ssl = NULL;
    conn.ctx = NULL;
    conn.imaps = args.imaps;

    /*Connects to the server.*/
    if (conn.imaps) {
        conn.sock = connect_to_imaps(args.server, args.port, args.cert_file, args.cert_addr, &conn.ctx, &conn.ssl);
        if (!conn.sock) {
            error_exit("Failed to establish IMAPS connection.", EXIT_FAILURE);
        }
    } else {
        conn.sock = connect_to_imap(args.server, args.port);
        if (conn.sock < 0) {
            error_exit("Failed to establish IMAP connection.", EXIT_FAILURE);
        }
    }

    /*Handshake, login, select mailbox commands.*/
    handshake(conn);
    login_to_imap(&current_message_count, conn, username, password);
    select_mailbox(&current_message_count, conn, args.mailbox);
    
    /*Specifies the mails filter for SEARCH based on the CLI argument and searches for mails.*/
    char *search_mails_filter = "ALL";
    if (args.new_only)
        search_mails_filter = "UNSEEN";
    char *messages_ids = search_mails(&current_message_count, conn, search_mails_filter);

    int fetch_count = 0, download_count = 0;
    int download_flag = 0;
    char request_type[1024];
    char log_file_path[1024];

    /*Specifies the request type for FETCH(full message or headers only) based on the CLI argument, 
    determines the log file path (separate files for headers and full messages).*/
    if (args.headers_only){
        strcpy(request_type, "BODY.PEEK[HEADER]");
        snprintf(log_file_path, sizeof(log_file_path), "%s/log_h.txt", args.out_dir);
    }
    else{
        strcpy(request_type, "BODY.PEEK[]");
        snprintf(log_file_path, sizeof(log_file_path), "%s/log.txt", args.out_dir);
    }

    char *current_position = messages_ids;
    char *next_space = NULL;

    /* Opens the log file to keep track of downloaded message IDs.*/
    FILE *log_file = fopen(log_file_path, "a+");
    if (log_file == NULL) {
        free(messages_ids);
        cleanup_connection(conn);
        error_exit("Failed to open a file.", EXIT_FAILURE);
    }

    /*Loop through each message ID and fetch the corresponding message.*/
    while ((next_space = strstr(current_position, " ")) != NULL) {
        *next_space = '\0';
        int message_id = atoi(current_position);

        if (message_id > 0) {
            /*Fetches the message.*/
            char *full_fetch_response = fetch_message(&current_message_count, conn, message_id, request_type);
            char *header_id = get_id_from_header(full_fetch_response);
            fetch_count++;
            /* Determines the length of the message body and copies the message.*/
            int body_start, line_index;
            int length = get_message_length(full_fetch_response, &body_start);
            char *message = strndup(full_fetch_response + body_start, length);

            /*Checks if the message ID is already in the log file to avoid downloading it twice.*/
            if (!header_id_in_log(header_id, log_file, &line_index)){
                fprintf(log_file, "%s\n", header_id);
                download_flag = 1;
            }
            if (download_flag){
                char mail_file_path[1024];
                /* Creates the mail file name based on whether it's headers only or full message.*/
                if (args.headers_only)
                    snprintf(mail_file_path, sizeof(mail_file_path), "%s/%d_h.txt", args.out_dir, line_index);
                else
                    snprintf(mail_file_path, sizeof(mail_file_path), "%s/%d.txt", args.out_dir, line_index);
                /* Opens the file to write the message content.*/
                FILE *mail_file = fopen(mail_file_path, "w");

                if (mail_file == NULL) {
                    free(header_id);
                    free(message);
                    free(full_fetch_response);        
                    fclose(log_file);
                    free(messages_ids);
                    cleanup_connection(conn);
                    error_exit("Failed to open a file.", EXIT_FAILURE);
                }
                fprintf(mail_file, "%s", message);
                fclose(mail_file);
                download_count++;
            }
            free(header_id);
            free(message);
            free(full_fetch_response);
        }
        download_flag = 0;
        current_position = next_space + 1;
    }

    /*Fetches the last message.*/
    if (*current_position != '\0') {
        int message_id = atoi(current_position);
        if (message_id > 0) {
            char *full_fetch_response = fetch_message(&current_message_count, conn, message_id, request_type);
            char *header_id = get_id_from_header(full_fetch_response);
            fetch_count++;
            int body_start, line_index;
            int length = get_message_length(full_fetch_response, &body_start);
            char *message = strndup(full_fetch_response + body_start, length);
            if (!header_id_in_log(header_id, log_file, &line_index)){
                fprintf(log_file, "%s\n", header_id);
                download_flag = 1;
            }

            if (download_flag){
                char mail_file_path[1024];
                if (args.headers_only)
                    snprintf(mail_file_path, sizeof(mail_file_path), "%s/%d_h.txt", args.out_dir, line_index);
                else
                    snprintf(mail_file_path, sizeof(mail_file_path), "%s/%d.txt", args.out_dir, line_index);
                FILE *mail_file = fopen(mail_file_path, "w");

                if (mail_file == NULL) {
                    free(header_id);
                    free(message);
                    free(full_fetch_response);        
                    fclose(log_file);
                    free(messages_ids);
                    cleanup_connection(conn);
                    error_exit("Failed to open a file.", EXIT_FAILURE);
                }
                fprintf(mail_file, "%s", message);
                fclose(mail_file);
                download_count++;
            }
            free(header_id);
            free(message);
            free(full_fetch_response);
        }
        download_flag = 0;
    }

    if (!fetch_count) {
        fprintf(stderr, "No messages to fetch.\n");
        return EXIT_SUCCESS;
    }

    printf("%d messages were downloaded from the '%s' mailbox.\n", download_count, args.mailbox);

    /*Logout.*/
    logout(&current_message_count, conn);

    fclose(log_file);
    free(messages_ids);
    cleanup_connection(conn);
    return EXIT_SUCCESS;
}
