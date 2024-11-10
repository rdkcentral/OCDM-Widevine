// Copyright 2018 Google LLC. All Rights Reserved. This file and proprietary
// source code may only be used and distributed under the Widevine Master
// License Agreement.

#include "url_request.h"

#include <errno.h>
#include <sstream>

#include "http_socket.h"
//#include "log.h"
#include "string_conversions.h"

//#define DEBUG

#define ENT_WV std::cout << "[RDK_LOG]Entering " << __FILE__ << " " << __FUNCTION__ << "  :" << __LINE__ <<endl
#define EXT_WV std::cout << "[RDK_LOG]Exiting " << __FILE__ << " " << __FUNCTION__ << "  :" << __LINE__ <<endl
using namespace std;

namespace wvcdm {

namespace {

const int kMaxConnectAttempts = 3;
const int kReadBufferSize = 1024;
const int kConnectTimeoutMs = 15000;
const int kWriteTimeoutMs = 12000;
const int kReadTimeoutMs = 12000;

const std::string kGoogleHeaderUpper("X-Google");
const std::string kGoogleHeaderLower("x-google");
const std::string kCrLf("\r\n");

// Concatenate all chunks into one blob and returns the response with
// header information.
void ConcatenateChunkedResponse(const std::string http_response,
                                std::string* modified_response) {
#if defined(DEBUG)
  ENT_WV;
#endif
  if (http_response.empty()) return;

  modified_response->clear();
  const std::string kChunkedTag = "Transfer-Encoding: chunked\r\n\r\n";
  size_t chunked_tag_pos = http_response.find(kChunkedTag);
  if (std::string::npos != chunked_tag_pos) {
    // processes chunked encoding
    size_t chunk_size = 0;
    size_t chunk_size_pos = chunked_tag_pos + kChunkedTag.size();
    sscanf(&http_response[chunk_size_pos], "%zx", &chunk_size);
    if (chunk_size > http_response.size()) {
      // precaution, in case we misread chunk size
      fprintf(stderr,"\n\n[RDK_LOG] invalid chunk size %u", chunk_size);
      return;
    }

    // Search for chunks in the following format:
    // header
    // chunk size\r\n  <-- chunk_size_pos @ beginning of chunk size
    // chunk data\r\n  <-- chunk_pos @ beginning of chunk data
    // chunk size\r\n
    // chunk data\r\n
    // 0\r\n
    size_t chunk_pos = http_response.find(kCrLf, chunk_size_pos);
    modified_response->assign(http_response, 0, chunk_size_pos);

    while ((chunk_size > 0) && (std::string::npos != chunk_pos)) {
      chunk_pos += kCrLf.size();
      modified_response->append(http_response, chunk_pos, chunk_size);

      // Search for next chunk
      chunk_size_pos = chunk_pos + chunk_size + kCrLf.size();
      sscanf(&http_response[chunk_size_pos], "%zx", &chunk_size);
      if (chunk_size > http_response.size()) {
        // precaution, in case we misread chunk size
        fprintf(stderr,"\n\n[RDK_LOG] invalid chunk size %u", chunk_size);
        break;
      }
      chunk_pos = http_response.find(kCrLf, chunk_size_pos);
    }
  } else {
    // Response is not chunked encoded
    modified_response->assign(http_response);
  }
#if defined(DEBUG)
  EXT_WV;
#endif
}

}  // namespace

UrlRequest::UrlRequest(const std::string& url)
    : is_connected_(false), socket_(url) {
#if defined(DEBUG)
  ENT_WV;
#endif
  Reconnect();
#if defined(DEBUG)
  EXT_WV;
#endif
}

UrlRequest::~UrlRequest() {}

void UrlRequest::Reconnect() {
#if defined(DEBUG)
  ENT_WV;
#endif
  for(uint32_t i = 0; i < kMaxConnectAttempts && !is_connected_; ++i) {
    socket_.CloseSocket();
    if (socket_.Connect(kConnectTimeoutMs)) {
      is_connected_ = true;
    } else {
      fprintf(stderr,"\n\n[RDK_LOG] Failed to connect:  url = %s,  port = %d,  attempt = %u",
           socket_.domain_name().c_str(), socket_.port(), i);
    }
  }
#if defined(DEBUG)
  EXT_WV;
#endif
}

bool UrlRequest::GetResponse(std::string* message) {
#if defined(DEBUG)
  ENT_WV;
#endif
  std::string response;

  // Keep reading until end of stream (0 bytes read) or timeout.  Partial
  // buffers worth of data can and do happen, especially with OpenSSL in
  // non-blocking mode.
  while (true) {
    char read_buffer[kReadBufferSize];
    const int bytes = socket_.Read(read_buffer, sizeof(read_buffer), kReadTimeoutMs);
    if (bytes > 0) {
      response.append(read_buffer, bytes);
    } else if (bytes < 0) {
      fprintf(stderr,"\n\n[RDK_LOG]read error, errno = %d", errno);
      return false;
    } else {
      // end of stream.
      break;
    }
  }

  ConcatenateChunkedResponse(response, message);
#if defined(DEBUG)
  fprintf(stderr,"\n\n[RDK_LOG] HTTP response from %s://%s:%d%s: (%zu): %s", socket_.scheme().c_str(),
       socket_.domain_name().c_str(), socket_.port(),
       socket_.resource_path().c_str(), message->size(), message->c_str());
  EXT_WV;
#endif
  return true;
}

// static
int UrlRequest::GetStatusCode(const std::string& response) {
#if defined(DEBUG)
  ENT_WV;
#endif
  const std::string kHttpVersion("HTTP/1.1 ");

  int status_code = -1;
  size_t pos = response.find(kHttpVersion);
  if (pos != std::string::npos) {
    pos += kHttpVersion.size();
    sscanf(response.substr(pos).c_str(), "%d", &status_code);
  }
#if defined(DEBUG)
  EXT_WV;
#endif
  return status_code;
}

// static
bool UrlRequest::GetDebugHeaderFields(
    const std::string& response, std::map<std::string, std::string>* fields) {
  if (fields == nullptr) return false;
  fields->clear();

  const auto find_next = [&](size_t pos) -> size_t {
    // Some of Google's HTTPS return header fields in lower case,
    // this lambda will check for both and return the position that
    // that is next or npos if none are found.
    const size_t lower_pos = response.find(kGoogleHeaderLower, pos + 1);
    const size_t upper_pos = response.find(kGoogleHeaderUpper, pos + 1);
    if (lower_pos == std::string::npos) return upper_pos;
    if (upper_pos == std::string::npos || lower_pos < upper_pos)
      return lower_pos;
    return upper_pos;
  };

  // Search is relatively simple, and may pick up additional matches within
  // the body of the request.  This is not anticiapted for the limited use
  // cases of parsing provisioning/license/renewal responses.
  for (size_t key_pos = find_next(0); key_pos != std::string::npos;
       key_pos = find_next(key_pos)) {
    const size_t end_key_pos = response.find(":", key_pos);
    const size_t end_value_pos = response.find(kCrLf, key_pos);
    // Skip if the colon cannot be found.  Technically possible to find
    // "X-Google" inside the value of a nother header field.
    if (end_key_pos == std::string::npos || end_value_pos == std::string::npos)
      continue;
    const size_t value_pos = end_key_pos + 2;
    if (end_value_pos < value_pos) continue;
    const std::string key = response.substr(key_pos, end_key_pos - key_pos);
    const std::string value =
        response.substr(value_pos, end_value_pos - value_pos);
    fields->insert({key, value});
  }
  return !fields->empty();
}

bool UrlRequest::PostRequestWithPath(const std::string& path,
                                     const std::string& data) {
#if defined(DEBUG)
  ENT_WV;
#endif
  std::string request;

  request.append("POST ");
  request.append(path);
  request.append(" HTTP/1.1\r\n");

  request.append("Host: ");
  request.append(socket_.domain_name());
  request.append("\r\n");

  request.append("Connection: close\r\n");
  request.append("User-Agent: Widevine CDM v1.0\r\n");

  // buffer to store length of data as a string
  char data_size_buffer[32] = {0};
  snprintf(data_size_buffer, sizeof(data_size_buffer), "%zu", data.size());

  request.append("Content-Length: ");
  request.append(data_size_buffer);  // appends size of data
  request.append("\r\n");

  request.append("\r\n");  // empty line to terminate headers

  request.append(data);

  const int ret = socket_.Write(request.c_str(), request.size(), kWriteTimeoutMs);
#if defined(DEBUG)
  fprintf(stderr,"\n\n[RDK_LOG] HTTP request: (%zu): %s", request.size(), b2a_hex(request).c_str());
  EXT_WV;
#endif
  return ret != -1;
}

bool UrlRequest::PostRequest(const std::string& data) {
#if defined(DEBUG)
  ENT_WV;
  EXT_WV;
#endif
  return PostRequestWithPath(socket_.resource_path(), data);
}

bool UrlRequest::PostCertRequestInQueryString(const std::string& data) {
#if defined(DEBUG)
  ENT_WV;
#endif
  std::string path = socket_.resource_path();
  path.append((path.find('?') == std::string::npos) ? "?" : "&");
  path.append("signedRequest=");
  path.append(data);
#if defined(DEBUG)
  EXT_WV;
#endif
  return PostRequestWithPath(path, "");
}

}  // namespace wvcdm
