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

#include "HostImplementation.h"

using namespace widevine;
using namespace WPEFramework;

namespace {
  const std::string kCertificateFilename = "cert.bin";
}  // namespace

namespace CDMi {

HostImplementation::HostImplementation() 
  : _saveDeviceCert(false)
  , _timer(Core::Thread::DefaultStackSize(),  _T("widevine"))
  , _files() {
  Reset();
}

HostImplementation::~HostImplementation() {
}

void HostImplementation::Reset() {

  _saveDeviceCert = false;

  _files.clear();
  _files[kCertificateFilename.c_str()] = std::string(reinterpret_cast<const char*>(kDeviceCert), kDeviceCertSize);
}

int HostImplementation::NumTimers() const { 
 return static_cast<int>(_timer.Pending()); 
}

// widevine::Cdm::IStorage implementation
// ---------------------------------------------------------------------------
/* virtual */ bool HostImplementation::read(const std::string& name, std::string* data) {
  StorageMap::iterator it = _files.find(name);
  bool ok = it != _files.end();
  TRACE_L1("read file: %s: %s", name.c_str(), ok ? "ok" : "fail");
  if (!ok) return false;
  *data = it->second;
  return true;
}

/* virtual */ bool HostImplementation::write(const std::string& name, const std::string& data) {
  TRACE_L1("write file: %s", name.c_str());
  _files[name] = data;
  if (_saveDeviceCert && kCertificateFilename.compare(name) == 0) {
    _saveDeviceCert = false;
  }
  return true;
}

/* virtual */ bool HostImplementation::exists(const std::string& name) {
  StorageMap::iterator it = _files.find(name);
  bool ok = it != _files.end();
  TRACE_L1("exists? %s: %s", name.c_str(), ok ? "true" : "false");
  return ok;
}

/* virtual */ bool HostImplementation::remove(const std::string& name) {
  TRACE_L1("remove: %s", name.c_str());
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
