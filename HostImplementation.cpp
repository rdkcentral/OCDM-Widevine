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

#include "HostImplementation.h"

using namespace widevine;
using namespace WPEFramework;

namespace CDMi {

HostImplementation::HostImplementation() 
  : widevine::Cdm::IStorage()
  , widevine::Cdm::IClock()
  , widevine::Cdm::ITimer()
  , _timer(Core::Thread::DefaultStackSize(),  _T("widevine"))
  , _files() {
}

HostImplementation::~HostImplementation() {
}

void HostImplementation::PreloadFile(const std::string& filename, std::string&& filecontent ) {
  _files.emplace(filename, filecontent);
}

// widevine::Cdm::IStorage implementation
// ---------------------------------------------------------------------------
/* virtual */ bool HostImplementation::read(const std::string& name, std::string* data) {
  StorageMap::iterator it = _files.find(name);
  bool ok = it != _files.end();
  TRACE(Trace::Information, (_T("read file: %s: %s"), name.c_str(), ok ? "ok" : "fail"));
  if (!ok) return false;
  *data = it->second;
  return true;
}

/* virtual */ bool HostImplementation::write(const std::string& name, const std::string& data) {
  TRACE(Trace::Information, (_T("write file: %s"), name.c_str()));
  _files[name] = data;
  return true;
}

/* virtual */ bool HostImplementation::exists(const std::string& name) {
  StorageMap::iterator it = _files.find(name);
  bool ok = it != _files.end();
  TRACE(Trace::Information, (_T("exists? %s: %s"), name.c_str(), ok ? "true" : "false"));
  return ok;
}

/* virtual */ bool HostImplementation::remove(const std::string& name) {
  TRACE(Trace::Information, (_T("remove: %s"), name.c_str()));
  if (name.empty()) {
    // If no name, delete all files (see DeviceFiles::DeleteAllFiles())
    _files.clear();
  } else {
    _files.erase(name);
  }
  return true;
}

/* virtual */ int32_t HostImplementation::size(const std::string& name) {
  StorageMap::iterator it = _files.find(name);
  if (it == _files.end()) return -1;
  return it->second.size();
}

/* virtual */ bool HostImplementation::list(std::vector<std::string>* names) {
  names->clear();
  for (StorageMap::iterator it = _files.begin(); it != _files.end(); it++) {
      names->push_back(it->first);
  }
  return true;
}

// widevine::Cdm::IClock implementation
// ---------------------------------------------------------------------------
/* virtual */ int64_t HostImplementation::now() {
  return static_cast<int64_t>(Core::Time::Now().Ticks() / Core::Time::TicksPerMillisecond); // Ticks -> MilliSeconds
}

// widevine::Cdm::ITimer implementation
// ---------------------------------------------------------------------------
/* virtual */ void HostImplementation::setTimeout(int64_t delay_ms, IClient* client, void* context) {

  ASSERT ((delay_ms > 0) && (delay_ms < 0xFFFFFFFF));

  Core::Time timeOut = Core::Time::Now().Add(delay_ms);

  _timer.Schedule(timeOut.Ticks(), Timer(client, context));
}

/* virtual */ void HostImplementation::cancel(IClient* client) {
  _timer.Revoke(Timer(client, nullptr));
}

} // namespace CDMi
