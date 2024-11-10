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

//#define DEBUG

using namespace std;
#define ENT_WV std::cout << "[RDK_LOG]Entering " << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << endl
#define EXT_WV std::cout << "[RDK_LOG]Exiting " << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << endl

using namespace WPEFramework;

namespace CDMi {

std::string ReadFromPropertiesFile(const char* prefix, size_t prefix_len) {
    FILE* properties = fopen("/etc/device.properties", "r");
    if (!properties) {
        return "";
    }

    char* buffer = nullptr;
    size_t size = 0;
    char* out_value = nullptr;

    while (getline(&buffer, &size, properties) != -1) {
        if (strncmp(prefix, buffer, prefix_len) == 0) {
            char* remainder = buffer + prefix_len;
            size_t remainder_length = strlen(remainder);
            if (remainder_length > 1) {
                // trim the newline character
                for(int i = remainder_length - 1; i >= 0 && !std::isalnum(remainder[i]); --i)
                    remainder[i] = '\0';
                free(buffer);
                fclose(properties);
                return remainder;
            }
        }
    }

    free(buffer);
    fclose(properties);
    return "";
}

class WideVine : public IMediaKeys, public widevine::Cdm::IEventListener, public IMediaSystemMetrics
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
        {
            Add(_T("certificate"), &Certificate);
            Add(_T("keybox"), &Keybox);
            Add(_T("product"), &Product);
            Add(_T("company"), &Company);
            Add(_T("model"), &Model);
            Add(_T("device"), &Device);
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
    };

public:
    WideVine()
        : _adminLock()
        , _cdm(nullptr)
        , _host()
        , _sessions() {
    }
    virtual ~WideVine() {
#if defined(DEBUG)
	ENT_WV;
#endif
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
#if defined(DEBUG)
	EXT_WV;
#endif
    }

    void Initialize(const WPEFramework::PluginHost::IShell * shell, const std::string& configline)
    {
#if defined(DEBUG)
	ENT_WV;
#endif
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
	    const char kPrefixStr[] = "OPERATOR_NAME=";
            const size_t kPrefixStrLength = sizeof(kPrefixStr) / sizeof(kPrefixStr[0]) - 1;
            client_info.company_name = ReadFromPropertiesFile(kPrefixStr, kPrefixStrLength);
        }

        if (config.Model.IsSet() == true) {
            client_info.model_name = config.Model.Value();
        } else {
	    const char kPrefixStr[] = "MODEL_NUM=";
            const size_t kPrefixStrLength = sizeof(kPrefixStr) / sizeof(kPrefixStr[0]) - 1;
            client_info.model_name = ReadFromPropertiesFile(kPrefixStr, kPrefixStrLength);
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
	const char kPrefixStr[] = "DEVICE_NAME=";
        const size_t kPrefixStrLength = sizeof(kPrefixStr) / sizeof(kPrefixStr[0]) - 1;
        client_info.device_name = ReadFromPropertiesFile(kPrefixStr, kPrefixStrLength);
#endif
        client_info.build_info = __DATE__;

        if (config.Keybox.IsSet() == true) {
            Core::SystemInfo::SetEnvironment("WIDEVINE_KEYBOX_PATH", config.Keybox.Value().c_str());
        }

        if (config.Certificate.IsSet() == true) {
            Core::DataElementFile dataBuffer(config.Certificate.Value(), Core::File::USER_READ);

            if(dataBuffer.IsValid() == false) {
                TRACE_L1(_T("Failed to open %s"), config.Certificate.Value().c_str());
            } else {
                _host.PreloadFile(_certificateFilename,  std::string(reinterpret_cast<const char*>(dataBuffer.Buffer()), dataBuffer.Size()));
            }
        }

        if (widevine::Cdm::kSuccess == widevine::Cdm::initialize(
                widevine::Cdm::kOpaqueHandle, client_info, &_host,
                &_host, &_host, static_cast<widevine::Cdm::LogLevel>(0))) {
            _cdm = widevine::Cdm::create(this, &_host, false);
#if defined(DEBUG)
	    cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] widevine cdm version is: " << _cdm->version << endl;
#endif
        }

        const char kPrefixStr[] = "COBALT_CERT_SCOPE=";
        const size_t kPrefixStrLength = sizeof(kPrefixStr) / sizeof(kPrefixStr[0]) - 1;
        if (widevine::Cdm::kSuccess == _cdm->setAppParameter("youtube_cert_scope", ReadFromPropertiesFile(kPrefixStr, kPrefixStrLength))) {
#if defined(DEBUG)
	    cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] setAppParameter youtube_cert_scope SUCCESS..!" << endl;
#endif
        }
        else {
        cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] setAppParameter youtube_cert_scope failed..!" << endl;
	}

#if defined(DEBUG)
	EXT_WV;
#endif
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

#if defined(DEBUG)
	ENT_WV;
#endif

        CDMi_RESULT dr = CDMi_S_FALSE;
        *f_ppiMediaKeySession = nullptr;

#if defined(DEBUG)
	cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] creating a mediaKeySession with\tcdm: " << _cdm << "\tlicenseType: " << licenseType << endl;
#endif
        MediaKeySession* mediaKeySession = new MediaKeySession(_cdm, licenseType);

        dr = mediaKeySession->Init(licenseType,
            f_pwszInitDataType,
            f_pbInitData,
            f_cbInitData,
            f_pbCDMData,
            f_cbCDMData);


        if (dr != CDMi_SUCCESS) {
#if defined(DEBUG)
	    cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] as result of mediaKeySession->Init() is not success, deleting mediaKeySession" << endl;
#endif
            delete mediaKeySession;
        }
        else {
            std::string sessionId (mediaKeySession->GetSessionId());
#if defined(DEBUG)
	    cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] mediaKeySession->Init is SUCCESS and value of sessionId: " << sessionId.c_str() << endl;
#endif
            _sessions.insert(std::pair<std::string, MediaKeySession*>(sessionId, mediaKeySession));
            *f_ppiMediaKeySession = mediaKeySession;
        }

#if defined(DEBUG)
	cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] result: " << dr << endl;
	EXT_WV;
#endif
        return dr;
    }

    virtual CDMi_RESULT SetServerCertificate(
        const uint8_t *f_pbServerCertificate,
        uint32_t f_cbServerCertificate) {

#if defined(DEBUG)
	ENT_WV;
#endif
        CDMi_RESULT dr = CDMi_S_FALSE;

        std::string serverCertificate(reinterpret_cast<const char*>(f_pbServerCertificate), f_cbServerCertificate);
        if (widevine::Cdm::kSuccess == _cdm->setServiceCertificate(widevine::Cdm::ServiceRole::kAllServices, serverCertificate)) {
            dr = CDMi_SUCCESS;
#if defined(DEBUG)
	    cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] setServiceCertificate SUCCESS..!" << endl;
#endif
        }

#if defined(DEBUG)
	cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] result: " << dr << endl;
	EXT_WV;
#endif
        return dr;
    }

    virtual CDMi_RESULT Metrics(uint32_t& bufferLength, uint8_t buffer[]) const {

        CDMi_RESULT dr = CDMi_S_FALSE;

        std::string metrics;
        uint8_t* data;

        if (widevine::Cdm::kSuccess == _cdm->getMetrics(&metrics)) {

            dr = CDMi_SUCCESS;

            bufferLength = metrics.size();

            data = reinterpret_cast<uint8_t*>(const_cast<char*>(metrics.data()));
            buffer = data;

#if defined(DEBUG)

            cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] GetMetrics SUCCESS..!" <<endl;

#endif

        }

        return dr;

    }

    virtual CDMi_RESULT DestroyMediaKeySession(
        IMediaKeySession *f_piMediaKeySession) {

#if defined(DEBUG)
	ENT_WV;
#endif
        std::string sessionId (f_piMediaKeySession->GetSessionId());

        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(sessionId));

        if (index != _sessions.end()) {
            _sessions.erase(index);
        }

        _adminLock.Unlock();

#if defined(DEBUG)
	cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] deleting MediaKeySession..!" << endl;
#endif
        delete f_piMediaKeySession;

#if defined(DEBUG)
	EXT_WV;
#endif
        return CDMi_SUCCESS;
    }

    virtual void onMessage(const std::string& session_id,
        widevine::Cdm::MessageType f_messageType,
        const std::string& f_message) {

        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(session_id));

        if (index != _sessions.end()) { 
 	    index->second->onMessage(f_messageType, f_message);
	}

        _adminLock.Unlock();

    }

    virtual void onKeyStatusesChange(const std::string& session_id, bool has_new_usable_key) {
#if defined(DEBUG)
	ENT_WV;
	EXT_WV;
#endif
    }

    virtual void onRemoveComplete(const std::string& session_id) {

#if defined(DEBUG)
	ENT_WV;
#endif
        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(session_id));

        if (index != _sessions.end()) {
	    index->second->onRemoveComplete();
	}

        _adminLock.Unlock();
#if defined(DEBUG)
	EXT_WV;
#endif
    }

    // Called when a deferred action has completed.
    virtual void onDeferredComplete(const std::string& session_id, widevine::Cdm::Status result) {

        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(session_id));

        if (index != _sessions.end()) { 
	    index->second->onDeferredComplete(result);
	}

        _adminLock.Unlock();
    }

    // Called when the CDM requires a new device certificate
    virtual void onDirectIndividualizationRequest(const std::string& session_id, const std::string& request) {

#if defined(DEBUG)
	ENT_WV;
#endif
        _adminLock.Lock();

        SessionMap::iterator index (_sessions.find(session_id));

        if (index != _sessions.end()) {
	    index->second->onDirectIndividualizationRequest(request);
	}

#if defined(DEBUG)
	EXT_WV;
#endif
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

#if defined(DEBUG)
    ENT_WV;
    EXT_WV;
#endif
    return (&CDMi::g_instance); 
}
