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

#include "cdmi.h"
#include "MediaSession.h"

#include <assert.h>
#include <iostream>
#include <sstream>
#include <sys/utsname.h>

namespace CDMi {

class WideVine : public IMediaKeys, public Cdm::IEventListener
{
private:
    WideVine (const WideVine&) = delete;
    WideVine& operator= (const WideVine&) = delete;

public:
    WideVine()
        : _cdm(nullptr)
        , _wvHost(nullptr)
        , _mediaKeySession(nullptr) {

        Cdm::ClientInfo client_info;

        // Set client info that denotes this as the test suite:
        client_info.product_name = "CE cdm box";
        client_info.company_name = "www";
        client_info.model_name = "www";

    #if defined(__linux__)
        client_info.device_name = "Linux";
        {
            struct utsname name;
            if (!uname(&name)) {
                client_info.arch_name = name.machine;
            }
        }
#else
        client_info.device_name = "unknown";
#endif
        client_info.build_info = __DATE__;
        _wvHost = new WVHost();

        Cdm::DeviceCertificateRequest cert_request;

        if (Cdm::kSuccess == Cdm::initialize(
                Cdm::kNoSecureOutput, client_info, _wvHost, _wvHost, _wvHost, &cert_request,
                static_cast<Cdm::LogLevel>(0))) {
            _cdm = Cdm::create(static_cast<Cdm::IEventListener*> (this), true);
        }
    }
    virtual ~WideVine() {
        assert (_mediaKeySession == nullptr);

        if (_mediaKeySession != nullptr) {
            delete _mediaKeySession;
        }

        if (_cdm != nullptr) {
            delete _cdm;
        }
        delete _wvHost;
    }

    virtual CDMi_RESULT CreateMediaKeySession(
        int32_t licenseType,
        const char *f_pwszInitDataType,
        const uint8_t *f_pbInitData,
        uint32_t f_cbInitData,
        const uint8_t *f_pbCDMData,
        uint32_t f_cbCDMData,
        IMediaKeySession **f_ppiMediaKeySession) {

        CDMi_RESULT dr = CDMi_S_FALSE;
        *f_ppiMediaKeySession = nullptr;

        _mediaKeySession = new MediaKeySession(_cdm, licenseType);

        dr = _mediaKeySession->Init(licenseType,
            f_pwszInitDataType,
            f_pbInitData,
            f_cbInitData,
            f_pbCDMData,
            f_cbCDMData);


        if (dr != CDMi_SUCCESS) {
            delete _mediaKeySession;
            _mediaKeySession = nullptr;
        }
        else {
            *f_ppiMediaKeySession = _mediaKeySession;
        }

        return dr;
    }

    virtual CDMi_RESULT SetServerCertificate(
        const uint8_t *f_pbServerCertificate,
        uint32_t f_cbServerCertificate) {

        CDMi_RESULT dr = CDMi_S_FALSE;

        std::string serverCertificate(reinterpret_cast<const char*>(f_pbServerCertificate), f_cbServerCertificate);
        if (Cdm::kSuccess == _cdm->setServerCertificate(serverCertificate)) {
            dr = CDMi_SUCCESS;
        }
        return dr;
    }

    virtual CDMi_RESULT DestroyMediaKeySession(
        IMediaKeySession *f_piMediaKeySession) {

        assert (_mediaKeySession == f_piMediaKeySession);

        delete f_piMediaKeySession;

        _mediaKeySession  = nullptr;

        return CDMi_SUCCESS;
    }

    virtual void onMessage(const std::string& f_sessionId,
        Cdm::MessageType f_messageType,
        const std::string& f_message) {

        if (_mediaKeySession) _mediaKeySession->onMessage(f_sessionId, f_messageType, f_message);
    }

    virtual void onKeyStatusesChange(const std::string& f_sessionId) {
        if (_mediaKeySession) _mediaKeySession->onKeyStatusesChange(f_sessionId);
    }

    virtual void onRemoveComplete(const std::string& f_sessionId) {
        if (_mediaKeySession) _mediaKeySession->onRemoveComplete(f_sessionId);
    }

private:
    Cdm* _cdm;
    WVHost* _wvHost;
    MediaKeySession* _mediaKeySession;
};

static SystemFactoryType<WideVine> g_instance({"video/webm", "video/mp4", "audio/webm", "audio/mp4"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
