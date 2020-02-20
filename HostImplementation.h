/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WIDEVINE_HOST_IMPLEMENTATION_H
#define WIDEVINE_HOST_IMPLEMENTATION_H

#include "cdm.h"
#include "override.h"

#include <core/core.h>

namespace CDMi {

class HostImplementation : 
  public widevine::Cdm::IStorage,
  public widevine::Cdm::IClock,
  public widevine::Cdm::ITimer {

private:
  HostImplementation(HostImplementation&) = delete;
  HostImplementation& operator= (HostImplementation&) = delete;

  typedef std::map<std::string, std::string> StorageMap;

  class Timer {
  public:
    Timer() : _client(nullptr), _context(nullptr) {
    }
    Timer(IClient* client, void* context) : _client(client), _context(context) {
      ASSERT(client != nullptr);
    }
    Timer(const Timer& copy) : _client(copy._client), _context(copy._context) {
    }
    ~Timer () {
    }

    Timer& operator= (const Timer& RHS) {
      _client = RHS._client;
      _context = RHS._context;
      return (*this);
    }

  public:
    inline bool operator== (const Timer& RHS) const {
      return (_client == RHS._client);
    }
    inline bool operator!= (const Timer& RHS) const {
      return (_client != RHS._client);
    }
    inline uint64_t Timed (const uint64_t /* scheduledTime */) {
      _client->onTimerExpired(_context);
      return(0); // No need to reschedule.
    }

  private:
    IClient* _client;
    void* _context;
  };

public:
  HostImplementation();
  ~HostImplementation ();

public:
  //
  // Add methods for testing purpose. No real-life functionality.
  void Reset();
  int NumTimers() const;
  inline void SaveProvisioningInformation() { 
    _saveDeviceCert = true; 
  }
 
  // widevine::Cdm::IStorage implementation
  // ---------------------------------------------------------------------------
  virtual bool read(const std::string& name, std::string* data) OVERRIDE;
  virtual bool write(const std::string& name, const std::string& data) OVERRIDE;
  virtual bool exists(const std::string& name) OVERRIDE;
  virtual bool remove(const std::string& name) OVERRIDE;
  virtual int32_t size(const std::string& name) OVERRIDE;
  virtual bool list(std::vector<std::string>* names) OVERRIDE;

  // widevine::Cdm::IClock implementation
  // ---------------------------------------------------------------------------
  virtual int64_t now() OVERRIDE;

  // widevine::Cdm::ITimer implementation
  // ---------------------------------------------------------------------------
  virtual void setTimeout(int64_t delay_ms, IClient* client, void* context) OVERRIDE;
  virtual void cancel(IClient* client) OVERRIDE;

private:
  bool _saveDeviceCert;
  WPEFramework::Core::TimerType<Timer> _timer;
  StorageMap _files;
};

} // namespace CDMi

#endif  // WIDEVINE_HOST_IMPLEMENTATION_H
