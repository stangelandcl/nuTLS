#include <netdb.h>
#include <stdio.h>
#include "nutls.c"

void error(char *msg) {
  perror(msg);
  exit(0);
}

ssize_t send_pending(int client_sock, struct TLSContext *context) {
  unsigned int out_buffer_len = 0;
  const unsigned char *out_buffer =
      tls_get_write_buffer(context, &out_buffer_len);
  unsigned int out_buffer_index = 0;
    ssize_t send_res = 0;
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

// NOTE: TLS1.2 only. Chain validation will fail with TLS1.2 and servers that
// send
//       ECDSA signatures (like Cloudflare) see[1]. We need to detect this
//       specific failure mode and return an error suggesting TLS1.3 instead.
//
//       [1] https://github.com/eduardsui/tlse/issues/53

int validate_certificate(struct TLSContext *context,
                         struct TLSCertificate **certificate_chain, int len) {
  int i;
  int err;
  if (certificate_chain) {
    for (i = 0; i < len; i++) {
      struct TLSCertificate *certificate = certificate_chain[i];
      // check validity date
      err = tls_certificate_is_valid(certificate);
      if (err) {
        fprintf(stderr, "Certificate invalid\n");
        return err;
      }
      // check certificate in certificate->bytes of length certificate->len
      // the certificate is in ASN.1 DER format
    }
  }
  // check if chain is valid
  err = tls_certificate_chain_is_valid(certificate_chain, len);
  if (err) {
    fprintf(stderr, "Certificate chain invalid\n");
    // return err;
  }

  const char *sni = tls_sni(context);
  if ((len > 0) && (sni)) {
    err = tls_certificate_valid_subject(certificate_chain[0], sni);
    if (err) {
      fprintf(stderr, "Certificate subject invalid\n");
      return err;
    }
  }

  // Perform certificate validation agains ROOT CA
  err = tls_certificate_chain_is_valid_root(context, certificate_chain, len);
  if (err) {
    fprintf(stderr, "Certificate chain root invalid\n");
    return err;
  }

  fprintf(stderr, "Certificate OK\n");

  // return certificate_expired;
  // return certificate_revoked;
  // return certificate_unknown;
  return no_error;
}

int SSL_CTX_root_ca(struct TLSContext *context, const char *pem_filename) {
  if (!context) return TLS_GENERIC_ERROR;

  int count = TLS_GENERIC_ERROR;
  FILE *f = fopen(pem_filename, "rb");
  if (f) {
    fseek(f, 0, SEEK_END);
    size_t size = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size) {
      unsigned char *buf = (unsigned char *)TLS_MALLOC(size + 1);
      if (buf) {
        buf[size] = 1;
        if (fread(buf, 1, size, f) == size) {
          count = tls_load_root_certificates(context, buf, size);
        }
        TLS_FREE(buf);
      }
    }
    fclose(f);
  }
  return count;
}

int main(int argc, char *argv[]) {
  int sockfd;
  uint16_t portno;

  struct sockaddr_in serv_addr;
  struct hostent *server;

  char *ref_argv[] = {"", "google.com", "443"};
  char *req_file = "/";

  if (argc < 4)
    fprintf(stderr, "Usage: %s host=google.com port=443 requested_file=/\n\n",
            argv[0]);

  if (argc < 2) argv = ref_argv;

  if (argc <= 2)
    portno = 443;
  else
    portno = atoi(argv[2]);

  if (argc >= 3) req_file = argv[3];

  char msg[] = "GET %s HTTP/1.1\r\nHost: %s:%i\r\nConnection: close\r\n\r\n";
  char msg_buffer[0xFF];
  snprintf(msg_buffer, sizeof(msg_buffer), msg, req_file, argv[1], portno);

  signal(SIGPIPE, SIG_IGN);
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) error("ERROR opening socket");
  server = gethostbyname(argv[1]);
  if (server == NULL) {
    fprintf(stderr, "ERROR, no such host\n");
    exit(0);
  }
  memset((char *)&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  memcpy((char *)&serv_addr.sin_addr.s_addr, server->h_addr,
         (size_t) server->h_length);
  serv_addr.sin_port = htons(portno);
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    error("ERROR connecting");

  struct TLSContext *context = tls_create_context(0, TLS_V12);

  // NOTE: load verifications certs
  if (context->version == TLS_V12) {
    int res = SSL_CTX_root_ca(context, "./ca-certificates.pem");
    fprintf(stderr, "Loaded %i certificates\n", res);
  }

  // set sni
  tls_sni_set(context, argv[1]);

  tls_client_connect(context);

  send_pending(sockfd, context);
  unsigned char client_message[0xFFFF];
  ssize_t read_size;
  int sent = 0;

  while ((read_size = recv(sockfd, client_message, sizeof(client_message), 0)) >
         0) {
    tls_consume_stream(context, client_message, read_size,
                       validate_certificate);

    send_pending(sockfd, context);
    if (tls_established(context)) {
      if (!sent) {
        tls_write(context, (unsigned char *)msg_buffer, strlen(msg_buffer));
        send_pending(sockfd, context);
        sent = 1;
      }

      unsigned char read_buffer[0xFFFF];
        size_t readSize = tls_read(context, read_buffer, 0xFFFF - 1);
      if (readSize > 0) fwrite(read_buffer, readSize, 1, stdout);
    }
  }
  return 0;
}
