// Copyright 2018 Google LLC. All Rights Reserved. This file and proprietary
// source code may only be used and distributed under the Widevine Master
// License Agreement.

#ifndef CDM_TEST_URL_REQUEST_H_
#define CDM_TEST_URL_REQUEST_H_

#include <map>
#include <string>

#include "disallow_copy_and_assign.h"
#include "http_socket.h"

namespace wvcdm {

// Provides simple HTTP request and response service.
// Only POST request method is implemented.
class UrlRequest {
 public:
  explicit UrlRequest(const std::string& url);
  ~UrlRequest();

  bool is_connected() const { return is_connected_; }
  void Reconnect();

  bool PostRequest(const std::string& data);
  bool PostCertRequestInQueryString(const std::string& data);

  bool GetResponse(std::string* message);
  static int GetStatusCode(const std::string& response);

  static bool GetDebugHeaderFields(
      const std::string& response,
      std::map<std::string, std::string>* header_fields);

 private:
  bool PostRequestWithPath(const std::string& path, const std::string& data);

  bool is_connected_;
  HttpSocket socket_;

  CORE_DISALLOW_COPY_AND_ASSIGN(UrlRequest);
};

}  // namespace wvcdm

#endif  // CDM_TEST_URL_REQUEST_H_
