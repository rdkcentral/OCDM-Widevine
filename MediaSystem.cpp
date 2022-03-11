/*
 * Copyright 2016-2017 TATA ELXSI
 * Copyright 2016-2017 Metrological
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "Module.h"

#include "MediaSession.h"
#include "HostImplementation.h"

#include <assert.h>
#include <iostream>
#include <sstream>
#include <sys/utsname.h>

#include <core/core.h>
#include <plugins/Types.h>

using namespace WPEFramework;

namespace CDMi {
static constexpr const TCHAR ControllerCallsign[] = _T("Controller");

class ControllerLink : public RPC::SmartInterfaceType<PluginHost::IShell> {
private:
    using BaseClass = RPC::SmartInterfaceType<PluginHost::IShell>;

public:
    ControllerLink()
        : BaseClass()
{
        BaseClass::Open(RPC::CommunicationTimeOut, BaseClass::Connector(), ControllerCallsign);
    }
    ~ControllerLink() override
    {
        BaseClass::Close(Core::infinite);
    }

    static ControllerLink& Instance()
    {
        static ControllerLink instance;
        return instance;
    }

    PluginHost::ISubSystem* SubSystem()
    {
        return Interface()->SubSystems();
    }
};

class WideVine : public IMediaKeys, public widevine::Cdm::IEventListener
{
private:
    WideVine (const WideVine&) = delete;
    WideVine& operator= (const WideVine&) = delete;

    static constexpr char _certificateFilename[] = {"cert.bin"};

    typedef std::map<std::string, MediaKeySession*> SessionMap;

    class Config : public Core::JSON::Container {
    public:
        Config(const Config&) = delete;
        Config& operator=(const Config&) = delete;
        Config()
            : Core::JSON::Container()
            , Certificate()
            , Keybox()
            , Product()
            , Company()
            , Model()
            , Device()
            , StorageLocation()
        {
            Add(_T("certificate"), &Certificate);
            Add(_T("keybox"), &Keybox);
            Add(_T("product"), &Product);
            Add(_T("company"), &Company);
            Add(_T("model"), &Model);
            Add(_T("device"), &Device);
            Add(_T("storagelocation"), &StorageLocation);
        }
        ~Config()
        {
        }

    public:
        Core::JSON::String Certificate;
        Core::JSON::String Keybox;
        Core::JSON::String Product;
        Core::JSON::String Company;
        Core::JSON::String Model;
        Core::JSON::String Device;
        Core::JSON::String StorageLocation;
    };

public:
    WideVine()
        : _adminLock()
        , _cdm(nullptr)
        , _host()
        , _sessions() {
    }
    virtual ~WideVine() {
        _adminLock.Lock();

        SessionMap::iterator index (_sessions.begin());

        while  (index != _sessions.end()) {
            delete index->second;
            index++;
        }

        _sessions.clear();

        _adminLock.Unlock();

        if (_cdm != nullptr) {
            delete _cdm;
        }
    }

    void Initialize(const WPEFramework::PluginHost::IShell * shell VARIABLE_IS_NOT_USED, const std::string& configline)
    {
        widevine::Cdm::ClientInfo client_info;

        Config config;
        config.FromString(configline);

        if (config.Product.IsSet() == true) {
            client_info.product_name = config.Product.Value();
        } else {
            client_info.product_name = "WPEFramework";
        }

        if (config.Company.IsSet() == true) {
            client_info.company_name = config.Company.Value();
        } else {
            client_info.company_name = "www.metrological.com";
        }

        if (config.Model.IsSet() == true) {
            client_info.model_name = config.Model.Value();
        } else {
            client_info.model_name = "reference";
        }

#if defined(__linux__)
        if (config.Device.IsSet() == true) {
            client_info.device_name = config.Device.Value();
        } else {
            client_info.device_name = "Linux";
        }
        {
            struct utsname name;
            if (!uname(&name)) {
                client_info.arch_name = name.machine;
            }
        }
#else
        client_info.device_name = "Unknown";
#endif
        client_info.build_info = __DATE__;

        if (config.Keybox.IsSet() == true) {
            Core::SystemInfo::SetEnvironment("WIDEVINE_KEYBOX_PATH", config.Keybox.Value().c_str());
        }

        if (config.StorageLocation.IsSet() == true) {
            Core::SystemInfo::SetEnvironment("WIDEVINE_STORAGE_PATH", config.StorageLocation.Value().c_str());
        }

        if ((config.Certificate.IsSet() == true) && (config.Certificate.Value().empty() == false)) {
            PluginHost::ISubSystem* subsystem = ControllerLink::Instance().SubSystem();

            ASSERT(subsystem != nullptr);

            string storage;

            if ((subsystem != nullptr) && (config.Certificate.Value()[0] != '/')) {
                const PluginHost::ISubSystem::IProvisioning* provisioning(subsystem->Get<PluginHost::ISubSystem::IProvisioning>());
                
                if (provisioning != nullptr) {
                    storage = provisioning->Storage();
                    provisioning->Release();
                }
                subsystem->Release();
            }

            TRACE_L1(_T("loading certificate is set to: \'%s\'\n"), string(storage + config.Certificate.Value()).c_str());

            Core::DataElementFile dataBuffer(storage + config.Certificate.Value(), Core::File::USER_READ);

            if(dataBuffer.IsValid() == false) {
                TRACE_L1(_T("Failed to open %s"), config.Certificate.Value().c_str());
            } else {
                _host.PreloadFile(_certificateFilename,  std::string(reinterpret_cast<const char*>(dataBuffer.Buffer()), dataBuffer.Size()));
            }
        }

        if (widevine::Cdm::kSuccess == widevine::Cdm::initialize(
                widevine::Cdm::kNoSecureOutput, client_info, &_host,
                &_host, &_host, static_cast<widevine::Cdm::LogLevel>(0))) {
            _cdm = widevine::Cdm::create(this, &_host, false);
        }
    }

    virtual CDMi_RESULT CreateMediaKeySession(
        const string& /* keySystem */,
        int32_t licenseType,
        const char *f_pwszInitDataType,
        const uint8_t *f_pbInitData,
        uint32_t f_cbInitData,
        const uint8_t *f_pbCDMData,
        uint32_t f_cbCDMData,
        IMediaKeySession **f_ppiMediaKeySession) {

        CDMi_RESULT dr = CDMi_S_FALSE;
        *f_ppiMediaKeySession = nullptr;

        MediaKeySession* mediaKeySession = new MediaKeySession(_cdm, licenseType);

        dr = mediaKeySession->Init(licenseType,
            f_pwszInitDataType,
            f_pbInitData,
            f_cbInitData,
            f_pbCDMData,
            f_cbCDMData);


        if (dr != CDMi_SUCCESS) {
            delete mediaKeySession;
        }
        else {
            std::string sessionId (mediaKeySession->GetSessionId());
            _sessions.insert(std::pair<std::string, MediaKeySession*>(sessionId, mediaKeySession));
            *f_ppiMediaKeySession = mediaKeySession;
        }

        return dr;
    }

    virtual CDMi_RESULT SetServerCertificate(
        const uint8_t *f_pbServerCertificate,
        uint32_t f_cbServerCertificate) {

        CDMi_RESULT dr = CDMi_S_FALSE;

        std::string serverCertificate(reinterpret_cast<const char*>(f_pbServerCertificate), f_cbServerCertificate);
        if (widevine::Cdm::kSuccess == _cdm->setServiceCertificate(widevine::Cdm::kAllServices, serverCertificate)) {
            dr = CDMi_SUCCESS;
        }
        return dr;
    }

    virtual CDMi_RESULT DestroyMediaKeySession(
        IMediaKeySession *f_piMediaKeySession) {

        std::string sessionId (f_piMediaKeySession->GetSessionId());

        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(sessionId));

        if (index != _sessions.end()) {
            _sessions.erase(index);
        }

        _adminLock.Unlock();

        delete f_piMediaKeySession;

        return CDMi_SUCCESS;
    }

    virtual void onMessage(const std::string& session_id,
        widevine::Cdm::MessageType f_messageType,
        const std::string& f_message) {

        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(session_id));

        if (index != _sessions.end()) index->second->onMessage(f_messageType, f_message);

        _adminLock.Unlock();
    }

    virtual void onKeyStatusesChange(const std::string& /*session_id*/, bool /*has_new_usable_key*/) {
    }

    virtual void onRemoveComplete(const std::string& session_id) {

        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(session_id));

        if (index != _sessions.end()) index->second->onRemoveComplete();

        _adminLock.Unlock();
    }

    // Called when a deferred action has completed.
    virtual void onDeferredComplete(const std::string& session_id, widevine::Cdm::Status result) {

        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(session_id));

        if (index != _sessions.end()) index->second->onDeferredComplete(result);

        _adminLock.Unlock();
    }

    // Called when the CDM requires a new device certificate
    virtual void onDirectIndividualizationRequest(const std::string& session_id, const std::string& request) {

        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(session_id));

        if (index != _sessions.end()) index->second->onDirectIndividualizationRequest(request);

        _adminLock.Unlock();
    }

private:
    WPEFramework::Core::CriticalSection _adminLock;
    widevine::Cdm* _cdm;
    HostImplementation _host;
    SessionMap _sessions;
};

constexpr char WideVine::_certificateFilename[];

static SystemFactoryType<WideVine> g_instance({"video/webm", "video/mp4", "audio/webm", "audio/mp4"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
