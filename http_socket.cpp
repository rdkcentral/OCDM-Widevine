// Copyright 2018 Google LLC. All Rights Reserved. This file and proprietary
// source code may only be used and distributed under the Widevine Master
// License Agreement.

#include "http_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <mutex>

#ifdef _WIN32
#  include "winsock2.h"
#  include "ws2tcpip.h"
#  define ERROR_ASYNC_COMPLETE WSAEWOULDBLOCK
#else
#  include <netdb.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  define ERROR_ASYNC_COMPLETE EINPROGRESS
#endif

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

//#include "log.h"
#include "platform.h"

namespace wvcdm {

namespace {

// Number of attempts to identify an Internet host and a service should the
// host's nameserver be temporarily unavailable.  See getaddrinfo(3) for
// more info.
constexpr size_t kMaxNameserverAttempts = 2;

// Helper function to tokenize a string.  This makes it easier to avoid silly
// parsing bugs that creep in easily when each part of the string is parsed
// with its own piece of code.
bool Tokenize(const std::string& source, const std::string& delim,
              const size_t offset, std::string* substring_output,
              size_t* next_offset) {
  size_t start_of_delim = source.find(delim, offset);
  if (start_of_delim == std::string::npos) {
    return false;
  }
  substring_output->assign(source, offset, start_of_delim - offset);
  *next_offset = start_of_delim + delim.size();
  return true;
}

SSL_CTX* InitSslContext() {
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  const SSL_METHOD* method = TLS_client_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (!ctx) fprintf(stderr,"\n\nfailed to create SSL context");
  SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
  int ret = SSL_CTX_set_cipher_list(
      ctx, "ALL:!RC4-MD5:!RC4-SHA:!ECDHE-ECDSA-RC4-SHA:!ECDHE-RSA-RC4-SHA");
  if (0 == ret) fprintf(stderr,"\n\nerror disabling vulnerable ciphers");
  return ctx;
}

static int LogBoringSslError(const char* message, size_t length,
                             void* /* user_data */) {
  fprintf(stderr,"\n\n  BoringSSL Error: %s", message);
  return length;
}

bool IsRetryableSslError(int ssl_error) {
  return ssl_error != SSL_ERROR_ZERO_RETURN && ssl_error != SSL_ERROR_SYSCALL &&
         ssl_error != SSL_ERROR_SSL;
}

// Ensures that the SSL library is only initialized once.
void InitSslLibrary() {
  static bool ssl_initialized = false;
  static std::mutex ssl_init_mutex;
  std::lock_guard<std::mutex> guard(ssl_init_mutex);
  if (!ssl_initialized) {
    SSL_library_init();
    ssl_initialized = true;
  }
}

#if 0
// unused, may be useful for debugging SSL-related issues.
void ShowServerCertificate(const SSL* ssl) {
  // gets the server certificate
  X509* cert = SSL_get_peer_certificate(ssl);
  if (cert) {
    char* line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    LOGV("server certificate:");
    LOGV("subject: %s", line);
    free(line);
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    LOGV("issuer: %s", line);
    free(line);
    X509_free(cert);
  } else {
    LOGE("Failed to get server certificate");
  }
}
#endif

// Wait for a socket to be ready for reading or writing.
// Establishing a connection counts as "ready for write".
// Returns false on select error or timeout.
// Returns true when the socket is ready.
bool SocketWait(int fd, bool for_read, int timeout_in_ms) {
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(fd, &fds);

  struct timeval tv;
  tv.tv_sec = timeout_in_ms / 1000;
  tv.tv_usec = (timeout_in_ms % 1000) * 1000;

  fd_set* read_fds = nullptr;
  fd_set* write_fds = nullptr;
  if (for_read) {
    read_fds = &fds;
  } else {
    write_fds = &fds;
  }

  int ret = select(fd + 1, read_fds, write_fds, nullptr, &tv);
  if (ret == 0) {
    fprintf(stderr,"\n\nsocket timed out");
    return false;
  } else if (ret == -1) {
    fprintf(stderr,"\n\nselect failed, errno = %d", errno);
    return false;
  }

  // socket ready.
  return true;
}

int GetError() {
#ifdef _WIN32
  return WSAGetLastError();
#else
  return errno;
#endif
}

void ClearError() {
#ifdef _WIN32
  WSASetLastError(0);
#else
  errno = 0;
#endif
}

const char* GetErrorString() {
#ifdef _WIN32
  static char buffer[2048];
  const int flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
  const int code = WSAGetLastError();
  if (!FormatMessage(flags, nullptr, code, 0, buffer, sizeof(buffer), nullptr))
    return "Unknown error";
  return buffer;
#else
  return strerror(errno);
#endif
}

}  // namespace

// Parses the URL and extracts all relevant information.
// static
bool HttpSocket::ParseUrl(const std::string& url, std::string* scheme,
                          bool* secure_connect, std::string* domain_name,
                          std::string* port, std::string* path) {
  size_t offset = 0;

  if (!Tokenize(url, "://", offset, scheme, &offset)) {
    fprintf(stderr,"\n\nInvalid URL, scheme not found: %s", url.c_str());
    return false;
  }

  // If the scheme is http or https, set secure_connect and port accordingly.
  // Otherwise, consider the scheme unsupported and fail.
  if (*scheme == "http") {
    *secure_connect = false;
    port->assign("80");
  } else if (*scheme == "https") {
    *secure_connect = true;
    port->assign("443");
  } else {
    fprintf(stderr,"\n\nInvalid URL, scheme not supported: %s", url.c_str());
    return false;
  }

  if (!Tokenize(url, "/", offset, domain_name, &offset)) {
    // The rest of the URL belongs to the domain name.
    domain_name->assign(url, offset, std::string::npos);
    // No explicit path after the domain name.
    path->assign("/");
  } else {
    // The rest of the URL, including the preceding slash, belongs to the path.
    path->assign(url, offset - 1, std::string::npos);
  }

  // The domain name may optionally contain a port which overrides the default.
  std::string domain_name_without_port;
  size_t port_offset;
  if (Tokenize(*domain_name, ":", 0, &domain_name_without_port, &port_offset)) {
    port->assign(domain_name->c_str() + port_offset);
    int port_num = atoi(port->c_str());
    if (port_num <= 0 || port_num >= 65536) {
      fprintf(stderr,"\n\nInvalid URL, port not valid: %s", url.c_str());
      return false;
    }
    domain_name->assign(domain_name_without_port);
  }

  return true;
}

HttpSocket::HttpSocket(const std::string& url)
    : socket_fd_(-1), ssl_(nullptr), ssl_ctx_(nullptr) {
  valid_url_ = ParseUrl(url, &scheme_, &secure_connect_, &domain_name_, &port_,
                        &resource_path_);
  InitSslLibrary();
}

HttpSocket::~HttpSocket() { CloseSocket(); }

void HttpSocket::CloseSocket() {
  if (socket_fd_ != -1) {
#ifdef _WIN32
    closesocket(socket_fd_);
#else
    close(socket_fd_);
#endif
    socket_fd_ = -1;
  }
  if (ssl_) {
    SSL_free(ssl_);
    ssl_ = nullptr;
  }
  if (ssl_ctx_) {
    SSL_CTX_free(ssl_ctx_);
    ssl_ctx_ = nullptr;
  }
}

bool HttpSocket::Connect(int timeout_in_ms) {
  if (!valid_url_) {
    fprintf(stderr,"\n\nURL is invalid");
    return false;
  }

  if (socket_fd_ != -1) {
    fprintf(stderr,"\n\nSocket already connected");
    return false;
  }

#ifdef _WIN32
  static bool initialized = false;
  if (!initialized) {
    WSADATA ignored_data;
    int err = WSAStartup(MAKEWORD(2, 2), &ignored_data);
    if (err != 0) {
      fprintf(stderr,"\n\nError in WSAStartup: %d", err);
      return false;
    }
    initialized = true;
  }
#endif

  // lookup the server IP
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
  struct addrinfo* addr_info = nullptr;

  int ret = EAI_AGAIN;
  for (size_t attempt = 1;
       attempt <= kMaxNameserverAttempts && ret == EAI_AGAIN; ++attempt) {
    if (attempt > 1) {
      fprintf(stderr,"\n\nNameserver is temporarily unavailable, waiting to try again: \nattempt = %zu", attempt);
      sleep(1);
    }
    ret = getaddrinfo(domain_name_.c_str(), port_.c_str(), &hints, &addr_info);
  }

  if (ret != 0) {
    if (ret == EAI_SYSTEM) {
      // EAI_SYSTEM implies an underlying system issue. Error is
      // specified by |errno|.
      fprintf(stderr,"\n\ngetaddrinfo failed due to system error: errno = %d", GetError());
    } else {
      // Error is specified by return value.
      fprintf(stderr,"\n\ngetaddrinfo failed: ret = %d", ret);
    }
    return false;
  }

  // Open a socket.
  socket_fd_ = socket(addr_info->ai_family, addr_info->ai_socktype,
                      addr_info->ai_protocol);
  if (socket_fd_ < 0) {
    fprintf(stderr,"\n\nCannot open socket: errno = %d", GetError());
    return false;
  }

  // Set the socket in non-blocking mode.
#ifdef _WIN32
  u_long mode = 1;  // Non-blocking mode.
  if (ioctlsocket(socket_fd_, FIONBIO, &mode) != 0) {
    fprintf(stderr,"\n\nioctlsocket error, wsa error = %d", WSAGetLastError());
    CloseSocket();
    return false;
  }
#else
  const int original_flags = fcntl(socket_fd_, F_GETFL, 0);
  if (original_flags == -1) {
    fprintf(stderr,"\n\nfcntl error, errno = %d", errno);
    CloseSocket();
    return false;
  }
  if (fcntl(socket_fd_, F_SETFL, original_flags | O_NONBLOCK) == -1) {
    fprintf(stderr,"\n\nfcntl error, errno = %d", errno);
    CloseSocket();
    return false;
  }
#endif

  // connect to the server
  ret = connect(socket_fd_, addr_info->ai_addr, addr_info->ai_addrlen);
  freeaddrinfo(addr_info);
  addr_info = nullptr;

  if (ret == 0) {
    // Connected right away.
  } else {
    if (GetError() != ERROR_ASYNC_COMPLETE) {
      // failed right away.
      fprintf(stderr,"\n\ncannot connect to %s, errno = %d", domain_name_.c_str(),
           GetError());
      CloseSocket();
      return false;
    } else {
      // in progress.  block until timeout expired or connection established.
      if (!SocketWait(socket_fd_, /* for_read */ false, timeout_in_ms)) {
        fprintf(stderr,"\n\ncannot connect to %s", domain_name_.c_str());
        CloseSocket();
        return false;
      }
    }
  }

  // set up SSL if needed
  if (secure_connect_) {
    ssl_ctx_ = InitSslContext();
    if (!ssl_ctx_) {
      CloseSocket();
      return false;
    }

    ssl_ = SSL_new(ssl_ctx_);
    if (!ssl_) {
      fprintf(stderr,"\n\nfailed SSL_new");
      CloseSocket();
      return false;
    }

    // |BIO_NOCLOSE| prevents closing the socket from being closed when
    // the BIO is freed.
    BIO* a_bio = BIO_new_socket(socket_fd_, BIO_NOCLOSE);
    if (!a_bio) {
      fprintf(stderr,"\n\nBIO_new_socket error");
      CloseSocket();
      return false;
    }

    SSL_set_bio(ssl_, a_bio, a_bio);
    do {
      ret = SSL_connect(ssl_);
      if (ret != 1) {
        int ssl_err = SSL_get_error(ssl_, ret);
        if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
          char buf[256];
          fprintf(stderr,"\n\nSSL_connect error: %s", ERR_error_string(ERR_get_error(), buf));
          CloseSocket();
          return false;
        }
        const bool for_read = (ssl_err == SSL_ERROR_WANT_READ);
        if (!SocketWait(socket_fd_, for_read, timeout_in_ms)) {
          fprintf(stderr,"\n\nCannot connect securely to %s", domain_name_.c_str());
          CloseSocket();
          return false;
        }
      }
    } while (ret != 1);
  }

  return true;
}

// Returns -1 for error, number of bytes read for success.
// The timeout here only applies to the span between packets of data, for the
// sake of simplicity.
int HttpSocket::Read(char* data, int len, int timeout_in_ms) {
  int total_read = 0;
  int to_read = len;

  if (socket_fd_ == -1) {
    fprintf(stderr,"\n\nSocket to %s not open.  Cannot read.", domain_name_.c_str());
    return -1;
  }
  while (to_read > 0) {
    if (!SocketWait(socket_fd_, /* for_read */ true, timeout_in_ms)) {
      fprintf(stderr,"\n\nunable to read from %s", domain_name_.c_str());
      return -1;
    }

    ClearError();  // Reset errors, as we will depend on its value shortly.
    int read;
    if (secure_connect_) {
      read = SSL_read(ssl_, data, to_read);
    } else {
      read = recv(socket_fd_, data, to_read, 0);
    }

    if (read > 0) {
      to_read -= read;
      data += read;
      total_read += read;
    } else if (secure_connect_) {
      // Secure read error
      int ssl_error = SSL_get_error(ssl_, read);

      if (ssl_error == SSL_ERROR_ZERO_RETURN ||
          (ssl_error == SSL_ERROR_SYSCALL && GetError() == 0)) {
        // The connection has been closed.  No more data.
        break;
      } else if (IsRetryableSslError(ssl_error)) {
        sleep(1);
        // After sleeping, fall through to iterate the loop again and retry.
      } else {
        // Unrecoverable error. Log and abort.
        fprintf(stderr,"\n\nSSL_read returned %d, LibSSL Error = %d", read, ssl_error);
        if (ssl_error == SSL_ERROR_SYSCALL) {
          fprintf(stderr,"\n\n  errno = %d = %s", GetError(), GetErrorString());
        }
        ERR_print_errors_cb(LogBoringSslError, nullptr);
        return -1;
      }
    } else {
      // Non-secure read error
      if (read == 0) {
        // The connection has been closed.  No more data.
        break;
      } else {
        // Log the error received
        fprintf(stderr,"\n\nrecv returned %d, errno = %d = %s", read, GetError(),
             GetErrorString());
        return -1;
      }
    }
  }

  return total_read;
}

// Returns -1 for error, number of bytes written for success.
// The timeout here only applies to the span between packets of data, for the
// sake of simplicity.
int HttpSocket::Write(const char* data, int len, int timeout_in_ms) {
  int total_sent = 0;
  int to_send = len;

  if (socket_fd_ == -1) {
    fprintf(stderr,"\n\nSocket to %s not open. Cannot write.", domain_name_.c_str());
    return -1;
  }
  while (to_send > 0) {
    int sent;
    if (secure_connect_)
      sent = SSL_write(ssl_, data, to_send);
    else
      sent = send(socket_fd_, data, to_send, 0);

    if (sent > 0) {
      to_send -= sent;
      data += sent;
      total_sent += sent;
    } else if (sent == 0) {
      // We filled up the pipe.  Wait for room to write.
      if (!SocketWait(socket_fd_, /* for_read */ false, timeout_in_ms)) {
        fprintf(stderr,"\n\nunable to write to %s", domain_name_.c_str());
        return -1;
      }
    } else {
      fprintf(stderr,"\n\nsend returned %d, errno = %d", sent, GetError());
      return -1;
    }
  }

  return total_sent;
}

}  // namespace wvcdm
