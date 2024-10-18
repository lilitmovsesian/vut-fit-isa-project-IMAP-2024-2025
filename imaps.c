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

char *construct_message(SSL *ssl, int *current_message_count, char *text);

void error_exit(char *msg, int code) {
    if (msg != NULL)
        fprintf(stderr, "%s\n", msg);
    exit(code);
}

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
}

int connect_to_imap(char *server, char *port){
    struct addrinfo hints, *res, *p;
    int sock, status;
    struct timeval tv;  

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(server, port, &hints, &res)) != 0) {
        char error_str[256];
        snprintf(error_str, sizeof(error_str), "Getaddrinfo error: %s", gai_strerror(status));
        error_exit(error_str, EXIT_FAILURE);
    }

    for (p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == -1) {
            continue;
        }

        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));

        if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock);
            continue;
        }
        break;
    }

    freeaddrinfo(res);

    if (p == NULL) {
        error_exit("Failed to connect to server.", EXIT_FAILURE);
    }

    return sock;
}


SSL *connect_to_imaps(char *server, char *port, char *cert_file, char *cert_addr) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        error_exit("Failed to create SSL context.", EXIT_FAILURE);
    }
    
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        SSL_CTX_free(ctx);
        error_exit("Failed to set default verify paths", EXIT_FAILURE);
    }

    if (!SSL_CTX_load_verify_locations(ctx, (cert_file == NULL ? NULL : cert_file), cert_addr)) {
        SSL_CTX_free(ctx);
         error_exit("Failed to load certificate", EXIT_FAILURE);
    }

    int sock = connect_to_imap(server, port);
    
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        error_exit("SSL connection failed.", EXIT_FAILURE);
    }

    printf("Connected to IMAPS server with encryption.\n");
    return ssl;
}

/*void cleanup_ssl(SSL *ssl, SSL_CTX *ctx, int sock) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    ERR_free_strings();
    EVP_cleanup();
}*/

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

void send_imap_message_ssl(SSL *ssl, char *message) {
    if (SSL_write(ssl, message, strlen(message)) <= 0) {
        SSL_shutdown(ssl);
        error_exit("Failed to send IMAP message through SSL.", EXIT_FAILURE);
    }
}

char *receive_imap_message_ssl(SSL *ssl) {
    size_t buffer_size = 100000;
    char buffer[buffer_size];
    char *response = calloc(10000000, 1);
    if (response == NULL) {
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    int received;
    
    while ((received = SSL_read(ssl, buffer, buffer_size)) > 0) {
        buffer[received] = '\0';
        strcat(response, buffer);
        if (strstr(response, "\r\n")) {
            break;
        }
    }
    if (received <= 0) {
        SSL_shutdown(ssl);
        error_exit("Failed to receive response.", EXIT_FAILURE);
    }
    return response;
}

int imap_command(int *current_message_count, SSL *ssl, char *response_p, char *command_format, ...) {

    char *text = calloc(4096, 1);
    if (text == NULL) {
        SSL_shutdown(ssl);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }

    va_list args;
    va_start(args, command_format);
    vsnprintf(text, 4096, command_format, args);
    va_end(args);

    char *message = construct_message(ssl, current_message_count, text);
    free(text);
    send_imap_message_ssl(ssl, message);
    free(message);
    char *response = receive_imap_message_ssl(ssl);
    printf("RESPONSE %s\n", response);
    int received_ID;

    strcpy(response_p, response);

    char *line = strtok(response, "\n");

    while (line != NULL) {
        if (sscanf(line, "A%d OK", &received_ID) > 0) {
            if (received_ID == *current_message_count) {
                free(response);
                (*current_message_count)++;
                return 0;
            }
        }
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

void login_to_imap(int *current_message_count, SSL *ssl, char *username, char *password) {
    char *response = calloc(16384, 1);
    if (response == NULL) {
        SSL_shutdown(ssl);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    if (imap_command(current_message_count, ssl, response, "LOGIN %s %s", username, password) == 1){
        free(response);
        SSL_shutdown(ssl);
        error_exit("Failed to login.", EXIT_FAILURE);
    }
    free(response);
}

void select_mailbox(int *current_message_count, SSL *ssl, char *mailbox){
    char *response = calloc(16384, 1);
    if (response == NULL) {
        SSL_shutdown(ssl);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    if (imap_command(current_message_count, ssl, response, "SELECT %s", mailbox) == 1){
        free(response);
        SSL_shutdown(ssl);
        error_exit("Failed to select the mailbox.", EXIT_FAILURE);
    }
    free(response);
}

char *search_mails(int *current_message_count, SSL *ssl, char *search_mails_filter){
    char *response = calloc(16384, 1);
    char *response_body = calloc(16384, 1);
    if (response == NULL || response_body == NULL) {
        SSL_shutdown(ssl);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    if (imap_command(current_message_count, ssl, response, "SEARCH %s", search_mails_filter) == 1){
        free(response);
        free(response_body);
        SSL_shutdown(ssl);
        error_exit("Failed to search mails.", EXIT_FAILURE);
    }
    int last_index = strlen(response) - 2;
    
    while (last_index > 0 && response[last_index] != '\n') {
        last_index--;
    }
    strncpy(response_body, response, last_index);
    free(response);
    return response_body;
}

char *construct_message(SSL *ssl, int *current_message_count, char *text){
    char *message = calloc(4096, 1);
    if (message == NULL) {
        SSL_shutdown(ssl);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    snprintf(message, 4096, "A%d %s\r\n", *current_message_count, text);
    return message;
}

void handshake(SSL *ssl) {
    char *greeting = receive_imap_message_ssl(ssl);
    if (strstr(greeting, "OK")) {
        free(greeting);
    } else {
        free(greeting);
        SSL_shutdown(ssl);
        error_exit("Failed to get the server greeting.", EXIT_FAILURE);
    }
}

char *fetch_message(int *current_message_count, SSL *ssl, int message_id, char *request_type) {
    size_t fetch_size = 10000000;
    char *full_fetch_response = calloc(fetch_size, 1);
    if (full_fetch_response == NULL) {
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    char *text = calloc(4096, 1);
    if (text == NULL) {
        free(full_fetch_response);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    snprintf(text, 4096, "FETCH %d %s", message_id, request_type);
    char *message = construct_message(ssl, current_message_count, text);
    free(text);
    send_imap_message_ssl(ssl, message);
    free(message);
    int success = 0;
    while (!success) {
        char *response = receive_imap_message_ssl(ssl);
        int received_ID;
        
        size_t current_length = strlen(full_fetch_response);
        size_t response_length = strlen(response);

        if (current_length + response_length >= fetch_size) {
            fetch_size *= 2;
            char *new_full_fetch_response = realloc(full_fetch_response, fetch_size);
            if (new_full_fetch_response == NULL) {
                free(full_fetch_response);
                free(response);
                SSL_shutdown(ssl);
                error_exit("Failed to reallocate memory.", EXIT_FAILURE);
            }
            full_fetch_response = new_full_fetch_response;
        }

        strcat(full_fetch_response, response);
        
        char *line = strtok(response, "\n");

        while (line != NULL) {
            if (sscanf(line, "A%d OK FETCH completed", &received_ID) > 0) {
                if (received_ID == *current_message_count) {
                    free(response);
                    success = 1;
                }
            }
            else if(sscanf(line, "A%d NO", &received_ID) > 0 || sscanf(line, "A%d BAD", &received_ID) > 0){
                error_exit("Failed to fetch mails.", EXIT_FAILURE);
            }

            line = strtok(NULL, "\n");
        }
    }

    (*current_message_count)++;

    return full_fetch_response;
}

int get_message_length(char *fetch_response, int *body_start) {
    regex_t regex;
    regmatch_t match[1];
    char pattern[] = "\\{([0-9]+)\\}";
    char result[40];
    char *newline_pos = strchr(fetch_response, '\n');
    int index = newline_pos - fetch_response;
    char substring[index + 1];
    if (body_start != NULL) {
            *body_start = index + 1;
        }
    strncpy(substring, fetch_response, index);
    substring[index] = '\0';
    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        error_exit("Failed to compile regex.", EXIT_FAILURE);
    }

    if (regexec(&regex, substring, 1, match, 0) == 0) {
        int len = match[0].rm_eo - match[0].rm_so;
        strncpy(result, substring + match[0].rm_so + 1, len - 1);
        result[len] = '\0';

        int message_length = atoi(result);
        regfree(&regex);
        return message_length;
    } else {
        regfree(&regex);
        error_exit("Failed to get message length.", EXIT_FAILURE);
    }
}



char *get_id_from_header(char *fetch_response) {
    regex_t regex;
    regmatch_t match[2];
    char *pattern = "<([^>]+)>";
    char *message_id_line = strstr(fetch_response, "Message-ID:");
    if (!message_id_line) {
        message_id_line = strstr(fetch_response, "Message-Id:");
    }
    if (!message_id_line) {
        error_exit("Failed to extract message ID line.", EXIT_FAILURE);
    }

    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        error_exit("Failed to compile regex.", EXIT_FAILURE);
    }

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
}

int logout(int *current_message_count, SSL *ssl){
    char *response = calloc(16384, 1);
    if (response == NULL) {
        SSL_shutdown(ssl);
        error_exit("Failed to allocate memory.", EXIT_FAILURE);
    }
    if (imap_command(current_message_count, ssl, response, "LOGOUT") == 1){
        free(response);
        SSL_shutdown(ssl);
        error_exit("Failed to logout.", EXIT_FAILURE);
    }
    free(response);
}

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

int main(int argc, char *argv[]) {
    int opt;
    char *server = NULL;
    char *port = NULL;
    int imaps = 0;
    char *cert_file = NULL;
    char *cert_addr = "/etc/ssl/certs";
    int new_only = 0;
    int headers_only = 0;
    char *auth_file = NULL;
    char *mailbox = "INBOX";
    char *out_dir = NULL;

    if (!(server = get_server(argc, argv))) {
        error_exit("Missing server or IP address argument.", EXIT_FAILURE);
    }

    while ((opt = getopt(argc, argv, "p:Tc:C:nhb:a:o:")) != -1) {
        switch (opt) {
            case 'p':
                port = optarg;
                break;
            case 'T':
                imaps = 1;
                break;
            case 'c':
                cert_file = optarg;
                break;
            case 'C':
                cert_addr = optarg;
                break;
            case 'n':
                new_only = 1;
                break;
            case 'h':
                headers_only = 1;
                break;
            case 'a':
                auth_file = optarg;
                break;
            case 'b':
                mailbox = optarg;
                break;
            case 'o':
                out_dir = optarg;
                break;
            default:
                error_exit("Usage: imapcl server [-p port] [-T [-c certfile] [-C certaddr]] [-n] [-h] -a auth_file [-b MAILBOX] -o out_dir.", EXIT_FAILURE);
        }
    }

    if (!auth_file || !out_dir) {
        error_exit("Missing required argument -a auth_file or -o out_dir.", EXIT_FAILURE);
    }
    
    if (argc < 6) {
        error_exit("Usage: imapcl server [-p port] [-T [-c certfile] [-C certaddr]] [-n] [-h] -a auth_file [-b MAILBOX] -o out_dir.", EXIT_FAILURE);
    }

    if (!port){
        port = imaps ? "993" : "143";
    }

//TODO remove everything from the main func :) and 1 file
//TODO make MAKE with a correct filename
//TODO REFACTOR 1 func = 1 action!!!!!!!!
//TODO args to struct
//TODO valgrind

//TODO imaps
//TODO normal buf size
//TODO documentation
//TODO comments

    char username[256];
    char password[256];

    parse_auth_file(auth_file, username, password);
    int current_message_count = 0;
    
    SSL *ssl = connect_to_imaps(server, port, cert_file, cert_addr);
    handshake(ssl);
    login_to_imap(&current_message_count, ssl, username, password);
    select_mailbox(&current_message_count, ssl, mailbox);
    char *search_mails_filter = "ALL";
    if (new_only)
        search_mails_filter = "UNSEEN";
    char *messages_ids = search_mails(&current_message_count, ssl, search_mails_filter);

    int fetch_count = 0, download_count = 0;
    int download_flag = 0;
    char request_type[1024];
    char log_file_path[1024];

    if (headers_only){
        strcpy(request_type, "BODY.PEEK[HEADER]");
        snprintf(log_file_path, sizeof(log_file_path), "%s/log_h.txt", out_dir);
    }
    else{
        strcpy(request_type, "BODY.PEEK[]");
        snprintf(log_file_path, sizeof(log_file_path), "%s/log.txt", out_dir);
    }

    char *current_position = messages_ids;
    char *next_space = NULL;


    FILE *log_file = fopen(log_file_path, "a+");
    if (log_file == NULL) {
        error_exit("Failed to open a file.", EXIT_FAILURE);
    }

    while ((next_space = strstr(current_position, " ")) != NULL) {
        *next_space = '\0';
        int message_id = atoi(current_position);

        if (message_id > 0) {
            char *full_fetch_response = fetch_message(&current_message_count, ssl, message_id, request_type);
            char *header_id = get_id_from_header(full_fetch_response);
            printf("ID %sID\n", header_id);
            fetch_count++;
            int body_start, line_index;
            int length = get_message_length(full_fetch_response, &body_start);
            printf("LENGTH %dLENGTH\n", length);
            char *message = strndup(full_fetch_response + body_start, length);
            printf("MES START %s MES END \n", message);

            if (!header_id_in_log(header_id, log_file, &line_index)){
                fprintf(log_file, "%s\n", header_id);
                download_flag = 1;
            }
            printf("LINE %d LINE END \n", line_index);

            if (download_flag){
                char mail_file_path[1024];
                if (headers_only)
                    snprintf(mail_file_path, sizeof(mail_file_path), "%s/%d_h.txt", out_dir, line_index);
                else
                    snprintf(mail_file_path, sizeof(mail_file_path), "%s/%d.txt", out_dir, line_index);
                FILE *mail_file = fopen(mail_file_path, "w");

                if (mail_file == NULL) {
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

    if (*current_position != '\0') {
        int message_id = atoi(current_position);
        if (message_id > 0) {
            char *full_fetch_response = fetch_message(&current_message_count, ssl, message_id, request_type);
            char *header_id = get_id_from_header(full_fetch_response);
            printf("ID %sID\n", header_id);
            fetch_count++;
            int body_start, line_index;
            int length = get_message_length(full_fetch_response, &body_start);
            printf("LENGTH %dLENGTH\n", length);
            char *message = strndup(full_fetch_response + body_start, length);
            printf("MES START %s MES END \n", message);

            if (!header_id_in_log(header_id, log_file, &line_index)){
                fprintf(log_file, "%s\n", header_id);
                download_flag = 1;
            }
            printf("LINE %d LINE END \n", line_index);

            if (download_flag){
                char mail_file_path[1024];
                if (headers_only)
                    snprintf(mail_file_path, sizeof(mail_file_path), "%s/%d_h.txt", out_dir, line_index);
                else
                    snprintf(mail_file_path, sizeof(mail_file_path), "%s/%d.txt", out_dir, line_index);
                FILE *mail_file = fopen(mail_file_path, "w");

                if (mail_file == NULL) {
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

    printf("%d messages were downloaded from the '%s' mailbox.\n", download_count, mailbox);

    logout(&current_message_count, ssl);

    fclose(log_file);
    free(messages_ids);
    SSL_shutdown(ssl);
    return EXIT_SUCCESS;
}
