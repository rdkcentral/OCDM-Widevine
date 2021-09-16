/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 Metrological
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

#pragma once

#include "Module.h"
#include "cdm.h"
#include <core/core.h>

namespace CDMi {

class HostImplementation : 
  public widevine::Cdm::IStorage,
  public widevine::Cdm::IClock,
  public widevine::Cdm::ITimer {

private:

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

  HostImplementation(HostImplementation&) = delete;
  HostImplementation& operator= (HostImplementation&) = delete;

  HostImplementation();
  ~HostImplementation() override;

public:

  // note this method is not thread safe regarding simultanious widevine::Cdm::IStorage callbacks, make sure they cannot be not active when calling this
  void PreloadFile(const std::string& filename, std::string&& filecontent );

  //
  // widevine::Cdm::IStorage implementation
  // ---------------------------------------------------------------------------
  virtual bool read(const std::string& name, std::string* data) override;
  virtual bool write(const std::string& name, const std::string& data) override;
  virtual bool exists(const std::string& name) override;
  virtual bool remove(const std::string& name) override;
  virtual int32_t size(const std::string& name) override;
  virtual bool list(std::vector<std::string>* names) override;

  // widevine::Cdm::IClock implementation
  // ---------------------------------------------------------------------------
  virtual int64_t now() override;

  // widevine::Cdm::ITimer implementation
  // ---------------------------------------------------------------------------
  virtual void setTimeout(int64_t delay_ms, IClient* client, void* context) override;
  virtual void cancel(IClient* client) override;

private:
  WPEFramework::Core::TimerType<Timer> _timer;
  StorageMap _files;
};

} // namespace CDMi
