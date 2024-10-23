# ISA_IMAP_Client_with_TLS_Support

## Author: Lilit Movsesian 
 
## Overview
The `imapcl` program allows reading electronic mail using the IMAP4rev1 protocol (RFC 3501). The program downloads messages stored on the server and saves them in the RFC 5322 format in a specified directory (each message separately) and outputs the number of downloaded messages to standard output. Additional parameters can modify its functionality.

## Compilation
The program comprises a `Makefile` and the source file `imapcl.c`. To compile the program, run:

    make

To clean up the generated files, use:

    make clean

## Usage
The application can be started with the following command:

    imapcl server [-p port] [-T [-c certfile] [-C certaddr]] [-n] [-h] -a auth_file [-b MAILBOX] -o out_dir

Parameters:

    server (mandatory): The name of the server (IP address or domain name) of the desired resource.

    -p port (optional): Specifies the port number on the server.

    -T: Enables encryption (IMAPS). If this parameter is not provided, the unencrypted version of the protocol will be used.

    -c certfile (optional): The certificate file used to verify the validity of the SSL/TLS certificate presented by the server.

    -C certaddr (optional): Specifies the directory where certificates should be searched for. The default value is /etc/ssl/certs.

    -n: Processes only new messages.

    -h: Downloads only the headers of the messages.

    -a auth_file (mandatory): Refers to the authentication file, which is formatted as follows:

        username = name
        password = secret

    -b mailbox (optional): Specifies the name of the mailbox to work with on the server. The default value is INBOX.

    -o out_dir (mandatory): Specifies the output directory where the program should save the downloaded messages.

## Error Handling
In case of an error, the program terminates with a unified error code and prints error description to stderr.

## Output
- The standard output will display the total number of downloaded messages or "No message to download" text.
- In the specified directory, the new files will be created, corresponding to the downloaded messages.