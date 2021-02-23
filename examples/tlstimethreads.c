#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#include "../tlse.c"

#define MAX_TCP_CONN 100

int count = 0;
pthread_mutex_t count_mutex[MAX_TCP_CONN];
pthread_cond_t count_threshold_cv[MAX_TCP_CONN];
int socketfds[MAX_TCP_CONN];

char* host;
double t_rt1 = 0;
pthread_mutex_t measurement_mutex;
struct sockaddr_in serv_addr;

char client_random[32];

struct TLSContext* context[MAX_TCP_CONN];

void hostinit() {
  struct hostent *server = gethostbyname(host);
  if (server == NULL) {
      fprintf(stderr,"ERROR, no such host\n");
      exit(0);
  }

  memset((char *) &serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  memcpy((char *)&serv_addr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);
  serv_addr.sin_port = htons(443);
}

void error(char *msg) {
    perror(msg);
    exit(0);
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

int open_socket() {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) 
      error("ERROR opening socket");

  if (connect(sockfd, (struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
      error("ERROR connecting");

  return sockfd;
}

unsigned char client_message[0xFFFF];
void establish_tls(int sockfd, int index) {
  my_tls_client_connect(context[index], client_random);
  send_pending(sockfd, context[index]); // Send CLIENT_HELLO
  int read_size;
  while ((read_size = recv(sockfd, client_message, sizeof(client_message) , 0)) > 0) {
#ifdef DEBUG
    printf("New read\n");
#endif
    int st = tls_consume_stream(context[index], client_message, read_size, NULL);
#ifdef DEBUG
    printf("Read over %d\n", st);
#endif

    if (st == TLS_DROP)
        break;
    send_pending(sockfd, context[index]);
  }
}

void *runner(void *t) 
{
  int i;
  long my_id = (long)t;

  struct timespec t_begin, t_end;
  clock_gettime(CLOCK_MONOTONIC_RAW, &t_begin);
  int sockfd = open_socket();
  clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);

  double time_elapsed = ((t_end.tv_sec - t_begin.tv_sec) * 1000 + 
                          (double) (t_end.tv_nsec - t_begin.tv_nsec) / 1000000);

  pthread_mutex_lock(&measurement_mutex);
  t_rt1 += time_elapsed;
  pthread_mutex_unlock(&measurement_mutex);

  pthread_mutex_lock(&count_mutex[my_id]);
  printf("do_tls(): thread %ld. Socket opened. Going into wait...\n", my_id);
  pthread_cond_wait(&count_threshold_cv[my_id], &count_mutex[my_id]);
  printf("do_tls(): thread %ld. Woken up...\n", my_id);
  pthread_mutex_unlock(&count_mutex[my_id]);

  establish_tls(sockfd, my_id);
  socketfds[my_id] = sockfd; // defer closing to later
  // close(sockfd);

  pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
  int i, rc; 
  pthread_t threads[MAX_TCP_CONN];
  pthread_attr_t attr;

  if (argc < 2) {
    fprintf(stderr,"usage %s hostname runs\n", argv[0]);
    exit(0);
  }

  host = argv[1];
  int runs = atoi(argv[2]);
  if ( runs > MAX_TCP_CONN ) {
    fprintf(stderr, "Increase MAX_TCP_CONN\n");
    exit(0);
  }

  /* Initialize mutex, condition variable objects and TLS objects, do host translation */
  hostinit();
  memset(client_random, '\x12', 32);
  for (i = 0; i < runs; i++) {
    pthread_mutex_init(&count_mutex[i], NULL);
    pthread_cond_init (&count_threshold_cv[i], NULL);
    context[i] = tls_create_context(0, TLS_V12);
  }
  pthread_mutex_init(&measurement_mutex, NULL);

  /* For portability, explicitly create threads in a joinable state */
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
  for (i = 0; i < runs; i++) {
    long j = i;
    pthread_create(&threads[i], &attr, runner, (void *)j);
  }

  sleep(1); // Wait till all connections are up

  struct timespec t_begin, t_end;
  clock_gettime(CLOCK_MONOTONIC_RAW, &t_begin);
  /* Now wake up threads one after another */
  for (i = 0; i < runs; i++) {
    pthread_mutex_lock(&count_mutex[i]);
    pthread_cond_signal(&count_threshold_cv[i]);
    pthread_mutex_unlock(&count_mutex[i]);

    // Wait until the thread is over.
    pthread_join(threads[i], NULL);
  }
  clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);

  double time_elapsed = ((t_end.tv_sec - t_begin.tv_sec) * 1000 + 
                          (double) (t_end.tv_nsec - t_begin.tv_nsec) / 1000000);
  printf ("Main(): Waited and joined with %d threads. Done. (TCP Ping vs TLS Ping): (%f %f)\n", runs, t_rt1 / runs, time_elapsed / runs);

  /* Clean up and exit */
  pthread_attr_destroy(&attr);
  for (i = 0; i < runs; i++) {
    close(socketfds[i]);
    pthread_mutex_destroy(&count_mutex[i]);
    pthread_cond_destroy(&count_threshold_cv[i]);
  }
  pthread_exit (NULL);

}

