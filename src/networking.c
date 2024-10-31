#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./networking.h"
#include "./sha256.h"

char server_ip[IP_LEN];
char server_port[PORT_LEN];
char my_ip[IP_LEN];
char my_port[PORT_LEN];

int c;

/*
 * Gets a sha256 hash of specified data, sourcedata. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_data_sha(const char* sourcedata, hashdata_t hash, uint32_t data_size, 
    int hash_size)
{
  SHA256_CTX shactx;
  unsigned char shabuffer[hash_size];
  sha256_init(&shactx);
  sha256_update(&shactx, sourcedata, data_size);
  sha256_final(&shactx, shabuffer);

  for (int i=0; i<hash_size; i++)
  {
    hash[i] = shabuffer[i];
  }
}

/*
 * Gets a sha256 hash of specified data file, sourcefile. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_file_sha(const char* sourcefile, hashdata_t hash, int size)
{
    int casc_file_size;

    FILE* fp = fopen(sourcefile, "rb");
    if (fp == 0)
    {
        printf("Failed to open source: %s\n", sourcefile);
        return;
    }

    fseek(fp, 0L, SEEK_END);
    casc_file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    char buffer[casc_file_size];
    fread(buffer, casc_file_size, 1, fp);
    fclose(fp);

    get_data_sha(buffer, hash, casc_file_size, size);
}

/*
 * Combine a password and salt together and hash the result to form the 
 * 'signature'. The result should be written to the 'hash' variable. Note that 
 * as handed out, this function is never called. You will need to decide where 
 * it is sensible to do so.
 */
void get_signature(char* password, char* salt, hashdata_t hash) {
    strcat(password, salt);
    get_data_sha(password, hash, strlen(password), SHA256_HASH_SIZE);
}

void generate_random_salt(char* salt, size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < length; i++) {
        int key = rand() % (int)(sizeof(charset) - 1);
        salt[i] = charset[key];
    }
    salt[length] = '\0';
}

void save_salt(const char* username, const char* salt) {
    FILE* file = fopen("user_salts.txt", "a");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open file for saving salt\n");
        return;
    }
    fprintf(file, "%s:%s\n", username, salt);
    fclose(file);
}

int load_salt(const char* username, char* salt, size_t length) {
    FILE* file = fopen("user_salts.txt", "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open file for loading salt\n");
        return 0;
    }

    char line[128];
    while (fgets(line, sizeof(line), file)) {
        char saved_username[USERNAME_LEN];
        char saved_salt[SALT_LEN];
        sscanf(line, "%[^:]:%s", saved_username, saved_salt);
        if (strcmp(saved_username, username) == 0) {
            strncpy(salt, saved_salt, length);
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

void read_response(int clientfd) {
    char response[1024];
    ssize_t n = compsys_helper_readn(clientfd, response, sizeof(response));
    if (n <= 0) {
        fprintf(stderr, "Error: Unable to read response from server\n");
        return;
    }

    uint32_t response_length = ntohl(*(uint32_t *)(response));
   
    char response_data[response_length + 1];
    memcpy(response_data, response + 80, response_length);
    response_data[response_length] = '\0';
    printf("Got response: %s\n", response_data);
}

/*
 * Register a new user with a server by sending the username and signature to 
 * the server
 */
void register_user(char* username, char* password, char* salt, int clientfd) {
    printf("salt: %s\n", salt);
    hashdata_t hash;
    get_signature(password, salt, hash);
    
    RequestHeader_t header;
    strncpy(header.username, username, USERNAME_LEN);
    memcpy(header.salted_and_hashed, hash, SHA256_HASH_SIZE);
    header.length = 0;

    Request_t request;
    request.header = header;
    memset(request.payload, 0, PATH_LEN);

    // Send request to server
    if (compsys_helper_writen(clientfd, &request, sizeof(request)) != sizeof(request)) {
        fprintf(stderr, "Error sending request to server\n");
        return;
    }
    
    read_response(clientfd);
}

/*
 * Get a file from the server by sending the username and signature, along with
 * a file path. Note that this function should be able to deal with both small 
 * and large files. 
 */
void get_file(char* username, char* password, char* salt, char* to_get, int clientfd) {
    printf("salt: %s\n", salt);
    hashdata_t hash;
    get_signature(password, salt, hash);

    RequestHeader_t header;
    strncpy(header.username, username, USERNAME_LEN);
    memcpy(header.salted_and_hashed, hash, SHA256_HASH_SIZE);
    header.length = htonl(strlen(to_get));

    Request_t request;
    request.header = header;
    strncpy(request.payload, to_get, PATH_LEN);

    if (compsys_helper_writen(clientfd, &request, sizeof(request)) != sizeof(request)) {
        fprintf(stderr, "Error sending request to server\n");
        return;
    }

    char response[1024];
    ssize_t n = compsys_helper_readn(clientfd, response, sizeof(response));
    if (n <= 0) {
        fprintf(stderr, "Error: Unable to read response from server\n");
        return;
    }

    uint32_t response_length = ntohl(*(uint32_t *)(response));

    char response_data[response_length + 1];
    memcpy(response_data, response + 80, response_length);
    response_data[response_length] = '\0';

    FILE *file = fopen(to_get, "wb");
    if (!file) {
        fprintf(stderr, "Error: Unable to open file %s for writing\n", to_get);
        return;
    }
    fwrite(response_data, 1, response_length, file);
    fclose(file);

    printf("File %s received and written successfully\n", to_get);

    close(clientfd);
}

int main(int argc, char **argv)
{
    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    srand(time(NULL));

    // Read in configuration options. Should include a client_directory, 
    // client_ip, client_port, server_ip, and server_port
    char buffer[128];
    fprintf(stderr, "Got config path at: %s\n", argv[1]);
    FILE* fp = fopen(argv[1], "r");
    while (fgets(buffer, 128, fp)) {
        if (starts_with(buffer, CLIENT_IP)) {
            memcpy(my_ip, &buffer[strlen(CLIENT_IP)], 
                strcspn(buffer, "\r\n")-strlen(CLIENT_IP));
            if (!is_valid_ip(my_ip)) {
                fprintf(stderr, ">> Invalid client IP: %s\n", my_ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, CLIENT_PORT)) {
            memcpy(my_port, &buffer[strlen(CLIENT_PORT)], 
                strcspn(buffer, "\r\n")-strlen(CLIENT_PORT));
            if (!is_valid_port(my_port)) {
                fprintf(stderr, ">> Invalid client port: %s\n", my_port);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, SERVER_IP)) {
            memcpy(server_ip, &buffer[strlen(SERVER_IP)], 
                strcspn(buffer, "\r\n")-strlen(SERVER_IP));
            if (!is_valid_ip(server_ip)) {
                fprintf(stderr, ">> Invalid server IP: %s\n", server_ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, SERVER_PORT)) {
            memcpy(server_port, &buffer[strlen(SERVER_PORT)], 
                strcspn(buffer, "\r\n")-strlen(SERVER_PORT));
            if (!is_valid_port(server_port)) {
                fprintf(stderr, ">> Invalid server port: %s\n", server_port);
                exit(EXIT_FAILURE);
            }
        }        
    }
    fclose(fp);

    fprintf(stdout, "Client at: %s:%s\n", my_ip, my_port);
    fprintf(stdout, "Server at: %s:%s\n", server_ip, server_port);

    // Connect to the server
    int clientfd = compsys_helper_open_clientfd(server_ip, server_port);
    if (clientfd < 0) {
        fprintf(stderr, "Error opening client connection\n");
        return 1;
    }

    char username[USERNAME_LEN];
    char password[PASSWORD_LEN];
    char user_salt[SALT_LEN];
    
    fprintf(stdout, "Enter a username to proceed: ");
    scanf("%16s", username);
    while ((c = getchar()) != '\n' && c != EOF);
    // Clean up username string as otherwise some extra chars can sneak in.
    for (int i=strlen(username); i<USERNAME_LEN; i++)
    {
        username[i] = '\0';
    }
 
    fprintf(stdout, "Enter your password to proceed: ");
    scanf("%16s", password);
    while ((c = getchar()) != '\n' && c != EOF);
    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(password); i<PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }

    // Note that a random salt should be used, but you may find it easier to
    // repeatedly test the same user credentials by using the hard coded value
    // below instead, and commenting out this randomly generating section.

    // for (int i=0; i<SALT_LEN; i++)
    // {
    //     user_salt[i] = 'a' + (random() % 26);
    // }
    // user_salt[SALT_LEN] = '\0';

    // strncpy(user_salt, 
    //    "0123456789012345678901234567890123456789012345678901234567890123\0", 
    //    SALT_LEN+1);

    // fprintf(stdout, "Using salt: %s\n", user_salt);

    // The following function calls have been added as a structure to a 
    // potential solution demonstrating the core functionality. Feel free to 
    // add, remove or otherwise edit. Note that if you are creating a system 
    // for user-interaction the following lines will almost certainly need to 
    // be removed/altered.

    // Register the given user. As handed out, this line will run every time 
    // this client starts, and so should be removed if user interaction is 
    // added

    if (!load_salt(username, user_salt, SALT_LEN)) {
        generate_random_salt(user_salt, SALT_LEN);
        save_salt(username, user_salt);
    }

    register_user(username, password, user_salt, clientfd);

    // Reconnect to the server for the file request
    clientfd = compsys_helper_open_clientfd(server_ip, server_port);
    if (clientfd < 0) {
        fprintf(stderr, "Error: Unable to connect to server\n");
        exit(EXIT_FAILURE);
    }

    if (!load_salt(username, user_salt, SALT_LEN)) {
        generate_random_salt(user_salt, SALT_LEN);
        save_salt(username, user_salt);
    }



    get_file(username, password, user_salt, "tiny.txt", clientfd);


    // Retrieve the larger file, that requires support for blocked messages. As
    // handed out, this line will run every time this client starts, and so 
    // should be removed if user interaction is added

    // get_file(username, password, user_salt, "hamlet.txt", clientfd);

    close(clientfd);
    exit(EXIT_SUCCESS);
}