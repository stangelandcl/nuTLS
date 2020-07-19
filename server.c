#include "nutls.c"

#include <unistd.h>

static char identity_str[0xFF] = {0};

unsigned long read_from_file(const char *fname, void *buf, size_t max_len) {
  FILE *f = fopen(fname, "rb");
  if (f) {
    unsigned long size = fread(buf, 1, max_len - 1, f);
    if (size > 0)
      ((unsigned char *)buf)[size] = 0;
    else
      ((unsigned char *)buf)[0] = 0;
    fclose(f);
    return size;
  }
  return 0;
}

void load_keys(struct TLSContext *context, char *fname, char *priv_fname) {
  unsigned char buf[0xFFFF];
  unsigned char buf2[0xFFFF];
  unsigned long size = read_from_file(fname, buf, 0xFFFF);
  unsigned long size2 = read_from_file(priv_fname, buf2, 0xFFFF);
  if (size > 0) {
    if (context) {
      tls_load_certificates(context, buf, size);
      tls_load_private_key(context, buf2, size2);
    }
  }
}

int send_pending(int client_sock, struct TLSContext *context) {
  unsigned int out_buffer_len = 0;
  const unsigned char *out_buffer =
      tls_get_write_buffer(context, &out_buffer_len);
  unsigned int out_buffer_index = 0;
  int send_res = 0;
  while ((out_buffer) && (out_buffer_len > 0)) {
    ssize_t res = send(client_sock, (char *)&out_buffer[out_buffer_index],
                       out_buffer_len, 0);
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

// verify signature
int verify_signature(struct TLSContext *context,
                     struct TLSCertificate **certificate_chain, int len) {
  if (len) {
    struct TLSCertificate *cert = certificate_chain[0];
    if (cert) {
      snprintf(identity_str, sizeof(identity_str), "%s, %s(%s) (issued by: %s)",
               cert->subject, cert->entity, cert->location,
               cert->issuer_entity);
      fprintf(stderr, "Verified: %s\n", identity_str);
    }
  }
  return no_error;
}

int main(int argc, char *argv[]) {
  int socket_desc, client_sock;
  ssize_t read_size;
  socklen_t c;
  struct sockaddr_in server, client;
  unsigned char client_message[0xFFFF];

  signal(SIGPIPE, SIG_IGN);

  socket_desc = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_desc == -1) {
    printf("Could not create socket");
    return 0;
  }

  int port = 2000;
  if (argc > 1) {
    port = atoi(argv[1]);
    if (port <= 0) port = 2000;
  }
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons(port);

  int enable = 1;
  setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

  if (bind(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0) {
    perror("bind failed. Error");
    return 1;
  }

  listen(socket_desc, 3);

  c = sizeof(struct sockaddr_in);

  struct TLSContext *server_context = tls_create_context(1, TLS_V13);
  // load keys
  load_keys(server_context, "./fullchain.pem", "./privkey.pem");

  while (1) {
    identity_str[0] = 0;

    client_sock = accept(socket_desc, (struct sockaddr *)&client, &c);
    if (client_sock < 0) {
      perror("accept failed");
      return 1;
    }

    struct TLSContext *context = tls_accept(server_context);

    fprintf(stderr, "Client connected\n");
    while ((read_size = recv(client_sock, client_message,
                             sizeof(client_message), 0)) > 0) {
      if (tls_consume_stream(context, client_message, read_size,
                             verify_signature) > 0)
        break;
    }

    send_pending(client_sock, context);

    if (read_size > 0) {
      fprintf(stderr, "USED CIPHER: %s\n", tls_cipher_name(context));

      while ((read_size = recv(client_sock, client_message,
                               sizeof(client_message), 0)) > 0) {
        if (tls_consume_stream(context, client_message, read_size,
                               verify_signature) < 0) {
          fprintf(stderr, "Error in stream consume\n");
          break;
        }
        send_pending(client_sock, context);
        if (tls_established(context) == 1) {
          unsigned char read_buffer[0xFFFF];
          int readSize =
              tls_read(context, read_buffer, sizeof(read_buffer) - 1);
          if (readSize > 0) {
            read_buffer[readSize] = 0;

            char sni[0xFF];
            sni[0] = 0;
            if (context->sni) snprintf(sni, 0xFF, "%s", context->sni);

            // ugly inefficient code ... don't write like me
            char send_buffer[0xF000];
            char send_buffer_with_header[0xF000];
            char out_buffer[0xFFF];
            int tls_version = -1;
            switch (context->version) {
              case TLS_V12:
                tls_version = 2;
                break;
              case TLS_V13:
                tls_version = 3;
                break;
            }
            snprintf(
                send_buffer, sizeof(send_buffer),
                "Hello world from TLS 1.%i (used chipher is: %s), SNI: "
                "%s\r\nYour identity is: %s\r\n\r\nCertificate: "
                "%s\r\n\r\nBelow is the received header:\r\n%s",
                tls_version, tls_cipher_name(context), sni, identity_str,
                tls_certificate_to_string(server_context->certificates[0],
                                          out_buffer, sizeof(out_buffer)),
                read_buffer);
            unsigned long content_length = strlen(send_buffer);
            snprintf(send_buffer_with_header, sizeof(send_buffer),
                     "HTTP/1.1 200 OK\r\n"
                     "Connection: close\r\n"
                     "Content-type: text/plain\r\n"
                     "Strict-Transport-Security: max-age=63072000;\r\n"
                     "Content-length: %lu\r\n\r\n%s",
                     content_length, send_buffer);
            tls_write(context, (unsigned char *)send_buffer_with_header,
                      strlen(send_buffer_with_header));
            tls_close_notify(context);
            send_pending(client_sock, context);
            break;
          }
        }
      }
    }
    shutdown(client_sock, SHUT_RDWR);
    close(client_sock);
    tls_destroy_context(context);
  }
}
