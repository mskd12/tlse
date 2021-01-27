#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#ifdef _WIN32
    #include <winsock2.h>
    #define socklen_t int
    #define sleep(x)    Sleep(x*1000)
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netdb.h> 
#endif
#include "../tlse.c"

void error(char *msg) {
    perror(msg);
    exit(0);
}

/*
// Use this version with DTLS (preserving message boundary)
int send_pending_udp(int client_sock, struct TLSContext *context, struct sockaddr_in *clientaddr, socklen_t socket_len) {
    unsigned int out_buffer_len = 0;
    unsigned int offset = 0;
    int send_res = 0;
    const unsigned char *out_buffer;
    do {
        out_buffer = tls_get_message(context, &out_buffer_len, offset);
        if (out_buffer) {
            send_res += sendto(client_sock, out_buffer, out_buffer_len, 0, (struct sockaddr *)clientaddr, socket_len);
            offset += out_buffer_len;
        }
    } while (out_buffer);
    tls_buffer_clear(context);
    return send_res;
}
*/

void hex64_to_bytes(char in[64], char val[32]) {
    const char *pos = in;

    for (size_t count = 0; count < 32; count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2;
    }
}

int send_pending(int client_sock, struct TLSContext *context) {
    unsigned int out_buffer_len = 0;
    const unsigned char *out_buffer = tls_get_write_buffer(context, &out_buffer_len);
    unsigned int out_buffer_index = 0;
    int send_res = 0;
    while ((out_buffer) && (out_buffer_len > 0)) {
        int res = send(client_sock, (char *)&out_buffer[out_buffer_index], out_buffer_len, 0);
        if (res <= 0) {
            send_res = res;
            break;
        }
        out_buffer_len -= res;
        out_buffer_index += res;
    }
    tls_buffer_clear(context);
    return send_res;
}

int validate_certificate(struct TLSContext *context, struct TLSCertificate **certificate_chain, int len) {
    int i;
    if (certificate_chain) {
        for (i = 0; i < len; i++) {
            struct TLSCertificate *certificate = certificate_chain[i];
            // check certificate ...
        }
    }
    //return certificate_expired;
    //return certificate_revoked;
    //return certificate_unknown;
    return no_error;
}

int main(int argc, char *argv[]) {
    // clock_t start = clock();
    struct timespec t_begin, t_mid1, t_mid2, t_end;
    clock_gettime(CLOCK_MONOTONIC_RAW, &t_begin);
    struct TLSContext *context = tls_create_context(0, TLS_V12);
    // the next line is needed only if you want to serialize the connection context or kTLS is used
    tls_make_exportable(context, 1);

    int sockfd, portno, n;
    //tls_print_certificate("testcert/server.certificate");
    //tls_print_certificate("000.certificate");
    //exit(0);
    struct sockaddr_in serv_addr;
    struct hostent *server;

    char buffer[256];
    // char *ref_argv[] = {"", "google.com", "443"};
    if (argc < 3 || strlen(argv[3]) != 64) {
        // argv = ref_argv;
       fprintf(stderr,"usage %s hostname port nonce\n", argv[0]);
       exit(0);
    }
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");
    server = gethostbyname(argv[1]);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy((char *)&serv_addr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);
    serv_addr.sin_port = htons(portno);
    clock_gettime(CLOCK_MONOTONIC_RAW, &t_mid1);
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");

    char client_random[32];
    hex64_to_bytes(argv[3], client_random);
    // memset(client_random, '\xab', 32);
    my_tls_client_connect(context, client_random);
    send_pending(sockfd, context);
    unsigned char client_message[0xFFFF];
    int read_size;
    int sent = 0;
    clock_gettime(CLOCK_MONOTONIC_RAW, &t_mid2);
    while ((read_size = recv(sockfd, client_message, sizeof(client_message) , 0)) > 0) {
        tls_consume_stream(context, client_message, read_size, validate_certificate);
        send_pending(sockfd, context);
    }
    clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);

    double time_1 = (t_mid1.tv_sec - t_begin.tv_sec) * 1000 + 
                            (double) (t_mid1.tv_nsec - t_begin.tv_nsec) / 1000000;

    double time_2 = (t_mid2.tv_sec - t_mid1.tv_sec) * 1000 + 
                            (double) (t_mid2.tv_nsec - t_mid1.tv_nsec) / 1000000;

    double time_3 = (t_end.tv_sec - t_mid2.tv_sec) * 1000 + 
                            (double) (t_end.tv_nsec - t_mid2.tv_nsec) / 1000000;

    double time_elapsed = (t_end.tv_sec - t_begin.tv_sec) * 1000 + 
                            (double) (t_end.tv_nsec - t_begin.tv_nsec) / 1000000;
    printf("(startup)%f + (connect)%f + (tls)%f = %f milliseconds elapsed\n", time_1, time_2, time_3, time_elapsed);
    return 0;
}
