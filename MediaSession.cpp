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
#include "Policy.h"

#include <assert.h>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <sstream>
#include <string>
#include <string.h>
#include <sys/utsname.h>

#include <core/core.h>

#include <arpa/inet.h>

#include <curl/curl.h>

#define NYI_KEYSYSTEM "keysystem-placeholder"

//#define DEBUG

using namespace std;
#define ENT_WV std::cout << "[RDK_LOG:Entering " << __FILE__ << "(" << __LINE__ << "):" << __FUNCTION__ << "]" << endl
#define EXT_WV std::cout << "[RDK_LOG:Exiting " << __FILE__ << "(" << __LINE__ << "):" << __FUNCTION__ << "]" << endl

namespace CDMi {

// Staging Provisioning Server
const std::string kCpStagingProvisioningServerUrl =
    "https://staging-www.sandbox.googleapis.com/"
    "certificateprovisioning/v1/devicecertificates/create"
    "?key=AIzaSyB-5OLKTx2iU5mko18DfdwK5611JIjbUhE";

// URL for Google Provisioning Server.
// The provisioning server supplies the certificate that is needed
// to communicate with the License Server.
const std::string kProvisioningServerUrl =
    "https://www.googleapis.com/"
    "certificateprovisioning/v1/devicecertificates/create"
    "?key=AIzaSyB-5OLKTx2iU5mko18DfdwK5611JIjbUhE";

#if defined WIDEVINE_DEFAULT_SERVER_CERTIFICATE_SUPPORTED
// NOTE: Provider ID = widevine.com
const std::string kCpProductionServiceCertificate = wvcdm::a2bs_hex(
    "0ab9020803121051434fe2a44c763bcc2c826a2d6ef9a718f7d793d005228e02"
    "3082010a02820101009e27088659dbd9126bc6ed594caf652b0eaab82abb9862"
    "ada1ee6d2cb5247e94b28973fef5a3e11b57d0b0872c930f351b5694354a8c77"
    "ed4ee69834d2630372b5331c5710f38bdbb1ec3024cfadb2a8ac94d977d391b7"
    "d87c20c5c046e9801a9bffaf49a36a9ee6c5163eff5cdb63bfc750cf4a218618"
    "984e485e23a10f08587ec5d990e9ab0de71460dfc334925f3fb9b55761c61e28"
    "8398c387a0925b6e4dcaa1b36228d9feff7e789ba6e5ef6cf3d97e6ae05525db"
    "38f826e829e9b8764c9e2c44530efe6943df4e048c3c5900ca2042c5235dc80d"
    "443789e734bf8e59a55804030061ed48e7d139b521fbf35524b3000b3e2f6de0"
    "001f5eeb99e9ec635f02030100013a0c7769646576696e652e636f6d12800332"
    "2c2f3fedc47f8b7ba88a135a355466e378ed56a6fc29ce21f0cafc7fb253b073"
    "c55bed253d8650735417aad02afaefbe8d5687902b56a164490d83d590947515"
    "68860e7200994d322b5de07f82ef98204348a6c2c9619092340eb87df26f63bf"
    "56c191dc069b80119eb3060d771afaaeb2d30b9da399ef8a41d16f45fd121e09"
    "a0c5144da8f8eb46652c727225537ad65e2a6a55799909bbfb5f45b5775a1d1e"
    "ac4e06116c57adfa9ce0672f19b70b876f88e8b9fbc4f96ccc500c676cfb173c"
    "b6f52601573e2e45af1d9d2a17ef1487348c05cfc6d638ec2cae3fadb655e943"
    "1330a75d2ceeaa54803e371425111e20248b334a3a50c8eca683c448b8ac402c"
    "76e6f76e2751fbefb669f05703cec8c64cf7a62908d5fb870375eb0cc96c508e"
    "26e0c050f3fd3ebe68cef9903ef6405b25fc6e31f93559fcff05657662b3653a"
    "8598ed5751b38694419242a875d9e00d5a5832933024b934859ec8be78adccbb"
    "1ec7127ae9afeef9c5cd2e15bd3048e8ce652f7d8c5d595a0323238c598a28");
#endif /* defined WIDEVINE_DEFAULT_SERVER_CERTIFICATE_SUPPORTED */

static std::string msgBuffer;
static size_t curl_writeback(void *ptr, size_t size, size_t nmemb, void *stream)
{
    msgBuffer.append((char*)ptr, size * nmemb);
    return size * nmemb;
}

static void sendPostRequest(std::string& request, std::string& response);

static void sendPostRequest(std::string& request,
std::string& response)
{
    std::string server_url = kProvisioningServerUrl;

    response.clear();

    msgBuffer.clear();
    server_url += "&signedRequest=";
    server_url += request;
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, server_url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, 0);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writeback);
        res = curl_easy_perform(curl);
        response = msgBuffer;
        curl_easy_cleanup(curl);
    } else {
    }

}

WPEFramework::Core::CriticalSection g_lock;

MediaKeySession::MediaKeySession(widevine::Cdm *cdm, int32_t licenseType)
    : m_cdm(cdm)
    , m_CDMData("")
    , m_initData("")
    , m_initDataType(widevine::Cdm::kCenc)
    , m_licenseType((widevine::Cdm::SessionType)licenseType)
    , m_sessionId("")
    , m_StreamType(Unknown)
#if defined(USE_SVP)
    , m_pSVPContext(NULL)
    , m_rpcID(0)
#endif
{
#if defined(DEBUG)  
  ENT_WV;
  cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tGoing to createSession with licenseType: " << m_licenseType << " and sessionId: " << m_sessionId.c_str() << endl;
#endif

  switch ((LicenseType)licenseType) {
  case PersistentUsageRecord:
    m_licenseType = widevine::Cdm::kPersistentUsageRecord;
    break;
  case PersistentLicense:
    m_licenseType = widevine::Cdm::kPersistentLicense;
    break;
  default:
    m_licenseType = widevine::Cdm::kTemporary;
    break;
  }

  widevine::Cdm::Status status =  m_cdm->createSession(m_licenseType, &m_sessionId);

#if defined(DEBUG)
  cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tCreated Session with licenseType: " << m_licenseType << "  and sessionId: " << m_sessionId.c_str() << "  and status is " << status << endl;
#endif


  //TODO: This will be moved to MediaSystem 
  // Below steps are to done for provisioning when you get the return error "kNeedsDeviceCertificate" (101)
  // from cdm->createSession() function call
  if(status == 101) {
#if defined(DEBUG)
        cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "Session creation failed with error \"kNeedsDeviceCertificate\" (101)" << endl;
#endif

#if defined WIDEVINE_DEFAULT_SERVER_CERTIFICATE_SUPPORTED
        status = cdm->setServiceCertificate(widevine::Cdm::ServiceRole::kProvisioningService, kCpProductionServiceCertificate);
#if defined(DEBUG)
        cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tResult of setServiceCertificate() is: " <<  status << endl;
#endif
#endif /* defined WIDEVINE_DEFAULT_SERVER_CERTIFICATE_SUPPORTED */

        // Generate a provisioning request.
        std::string request_;
        status = cdm->getProvisioningRequest(&request_);
#if defined(DEBUG)
        cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tResult of getProvisioningRequest() is: " <<  status << endl;
#endif

        // Getting the provisioning response.
        std::string response_;
        sendPostRequest(request_, response_);

        // Handles a provisioning response and provisions the device.
        status = cdm->handleProvisioningResponse(response_);
#if defined(DEBUG)
        cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tResult of handleProvisioningResponse() is: " <<  status << endl;
#endif

        //Calling createSession.
        status = m_cdm->createSession(m_licenseType, &m_sessionId);
#if defined(DEBUG)
        cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tResult of createSession() is: " <<  status << endl;
#endif
  }

  ::memset(m_IV, 0 , sizeof(m_IV));;
 
#ifdef USE_SVP
  cout << "Initializing SVP context for client side" << endl;
  gst_svp_ext_get_context(&m_pSVPContext, Client, m_rpcID);
#endif

#ifdef USE_SVP
  m_stSecureBuffInfo.bCreateSecureMemRegion = true;
  m_stSecureBuffInfo.SecureMemRegionSize = 512 * 1024;

  if( 0 != svp_allocate_secure_buffers(m_pSVPContext, (void**)&m_stSecureBuffInfo, nullptr, nullptr, m_stSecureBuffInfo.SecureMemRegionSize))
  {
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tsecure memory, allocate failed " << endl;
#endif
  }
#endif

#if defined(DEBUG) 
  EXT_WV;
#endif
}

MediaKeySession::~MediaKeySession(void) {
  Close();
#ifdef USE_SVP
  gst_svp_ext_free_context(m_pSVPContext);
#endif
}


void MediaKeySession::Run(const IMediaKeySessionCallback *f_piMediaKeySessionCallback) {

#if defined(DEBUG)
  ENT_WV;
#endif

  if (f_piMediaKeySessionCallback) {
    m_piCallback = const_cast<IMediaKeySessionCallback*>(f_piMediaKeySessionCallback);

#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tCalling generateRequest() with \tSessionId: " << m_sessionId.c_str() << "\tInitDataType: " << m_initDataType << "\tInitData: " << m_initData << endl;
#endif

    widevine::Cdm::Status status = m_cdm->generateRequest(m_sessionId, m_initDataType, m_initData);

#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tStatus of generateRequest: " << status << endl;
#endif

    if (widevine::Cdm::kSuccess != status) {
       printf("generateRequest failed\n");
       m_piCallback->OnError(0, CDMi_S_FALSE, "generateRequest");
    }
  }
  else {
      m_piCallback = nullptr;
  }
#if defined(DEBUG)
  EXT_WV;
#endif
}

void MediaKeySession::onMessage(widevine::Cdm::MessageType f_messageType, const std::string& f_message) {
#if defined(DEBUG)
  ENT_WV;
#endif
  std::string destUrl;
  std::string message;
 
  switch (f_messageType) {
  case widevine::Cdm::kLicenseRequest:
  case widevine::Cdm::kLicenseRenewal:
  case widevine::Cdm::kLicenseRelease:
  {
    destUrl.assign(kLicenseServer);   
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tDestUrl: " << destUrl.c_str() << endl;
#endif

    // FIXME: Errrr, this is weird.
    //if ((Cdm::MessageType)f_message[1] == (Cdm::kIndividualizationRequest + 1)) {
    //  LOGI("switching message type to kIndividualizationRequest");
    //  messageType = Cdm::kIndividualizationRequest;
    //}
    
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tMessage Type: " << f_messageType << endl;
#endif
    message = std::to_string(f_messageType) + ":Type:";
    break;
  }
  default:
    printf("unsupported message type %d\n", f_messageType);
    break;
  }
  message.append(f_message.c_str(),  f_message.size());

  m_piCallback->OnKeyMessage((const uint8_t*) message.c_str(), message.size(), (char*) destUrl.c_str());
#if defined(DEBUG)
  EXT_WV;
#endif
}

static const char* widevineKeyStatusToCString(widevine::Cdm::KeyStatus widevineStatus)
{
    switch (widevineStatus) {
    case widevine::Cdm::kUsable:
#if defined(DEBUG)
 	cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tKey Usable" << endl;
#endif
        return "KeyUsable";
        break;
    case widevine::Cdm::kExpired:
#if defined(DEBUG)
	cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tKey Expired" << endl;
#endif
        return "KeyExpired";
        break;
    case widevine::Cdm::kOutputRestricted:
#if defined(DEBUG)
	cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tKey OutputRestricted" << endl;
#endif
        return "KeyOutputRestricted";
        break;
    case widevine::Cdm::kStatusPending:
#if defined(DEBUG)
	cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tKey StatusPending" << endl;
#endif
        return "KeyStatusPending";
        break;
    case widevine::Cdm::kInternalError:
#if defined(DEBUG)
	cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tKey InternalError" << endl;
#endif
        return "KeyInternalError";
        break;
    case widevine::Cdm::kReleased:	
#if defined(DEBUG)
	cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tKey Released" << endl;
#endif
        return "KeyReleased";
        break;
    default:	
#if defined(DEBUG)
	cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tUnknownError" << endl;
#endif
        return "UnknownError";
        break;
    }
}

void MediaKeySession::onKeyStatusChange()
{
#if defined(DEBUG)
    ENT_WV;
#endif
    widevine::Cdm::KeyStatusMap map;
    if (widevine::Cdm::kSuccess != m_cdm->getKeyStatuses(m_sessionId, &map)) {
#if defined(DEBUG)
	cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tInside if 'widevine::Cdm::kSuccess != m_cdm->getKeyStatuses(m_sessionId, &map)'" << endl;	
#endif
        return;
    }

    for (const auto& pair : map) {
        const std::string& keyValue = pair.first;
        widevine::Cdm::KeyStatus keyStatus = pair.second;

        m_piCallback->OnKeyStatusUpdate(widevineKeyStatusToCString(keyStatus),
                                        reinterpret_cast<const uint8_t*>(keyValue.c_str()),
                                        keyValue.length());
    }
    m_piCallback->OnKeyStatusesUpdated();
#if defined(DEBUG)
    EXT_WV;
#endif
}

void MediaKeySession::onKeyStatusError(widevine::Cdm::Status status) {
  std::string errorStatus;
  switch (status) {
  case widevine::Cdm::kNeedsDeviceCertificate:
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tNeeds DeviceCertificate" << endl;
#endif
    errorStatus = "NeedsDeviceCertificate";
    break;
  case widevine::Cdm::kSessionNotFound:
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tSessionNotFound" << endl;
#endif
    errorStatus = "SessionNotFound";
    break;
  case widevine::Cdm::kDecryptError:
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tDecryptError" << endl;
#endif
    errorStatus = "DecryptError";
    break;
  case widevine::Cdm::kTypeError:
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tTypeError" << endl;
#endif
    errorStatus = "TypeError";
    break;
  case widevine::Cdm::kQuotaExceeded:
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tQuotaExceeded" << endl;
#endif
    errorStatus = "QuotaExceeded";
    break;
  case widevine::Cdm::kNotSupported:
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tNotSupported" << endl;
#endif
    errorStatus = "NotSupported";
    break;
  default:
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tUnExpected Error" << endl;
#endif
    errorStatus = "UnExpectedError";
    break;
  }
  m_piCallback->OnError(0, CDMi_S_FALSE, errorStatus.c_str());
}

void MediaKeySession::onRemoveComplete() {
#if defined(DEBUG)
    ENT_WV;
#endif
    widevine::Cdm::KeyStatusMap map;
    if (widevine::Cdm::kSuccess == m_cdm->getKeyStatuses(m_sessionId, &map)) {
        for (const auto& pair : map) {
            const std::string& keyValue = pair.first;

            m_piCallback->OnKeyStatusUpdate("KeyReleased",
                                        reinterpret_cast<const uint8_t*>(keyValue.c_str()),
                                        keyValue.length());
        }
        m_piCallback->OnKeyStatusesUpdated();
    }
#if defined(DEBUG)
    EXT_WV;
#endif
}

void MediaKeySession::onDeferredComplete(widevine::Cdm::Status) {
}

void MediaKeySession::onDirectIndividualizationRequest(const string&) {
}

CDMi_RESULT MediaKeySession::Load(void) {

#if defined(DEBUG)
  ENT_WV;
#endif

  CDMi_RESULT ret = CDMi_S_FALSE;
  g_lock.Lock();
  widevine::Cdm::Status status = m_cdm->load(m_sessionId);
#if defined(DEBUG)
  cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tstatus: " << status << endl;
#endif
  if (widevine::Cdm::kSuccess != status) {
    onKeyStatusError(status);
  }else {
    ret = CDMi_SUCCESS;
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tLoad SUCCESS: " << ret << endl;
#endif
  }
  g_lock.Unlock();

#if defined(DEBUG)
  cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tresult: " << ret << endl;
  EXT_WV;
#endif
  return ret;
}

void MediaKeySession::Update(
    const uint8_t *f_pbKeyMessageResponse,
    uint32_t f_cbKeyMessageResponse) {

#if defined(DEBUG)
  ENT_WV;
#endif
  widevine::Cdm::Status ret = widevine::Cdm::kSuccess;
  std::string keyResponse(reinterpret_cast<const char*>(f_pbKeyMessageResponse),
      f_cbKeyMessageResponse);
#if defined(DEBUG)
  cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tKey Response: " << keyResponse.c_str() << endl;
#endif
  g_lock.Lock();
  if (widevine::Cdm::kSuccess != (ret = m_cdm->update(m_sessionId, keyResponse))) {
      onKeyStatusError(ret);
  }
  onKeyStatusChange();
  g_lock.Unlock();
#if defined(DEBUG)
  EXT_WV;
#endif
}

CDMi_RESULT MediaKeySession::Remove(void) {

#if defined(DEBUG)
  ENT_WV;
#endif
  CDMi_RESULT ret = CDMi_S_FALSE;
  g_lock.Lock();
  widevine::Cdm::Status status = m_cdm->remove(m_sessionId);

#if defined(DEBUG)
  cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tstatus: " << status << endl;
#endif
  if (widevine::Cdm::kSuccess != status) {
    onKeyStatusError(status);
  }else {
    ret =  CDMi_SUCCESS;
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tRemove SUCCESS: " << ret << endl;
#endif
  }
  g_lock.Unlock();

#if defined(DEBUG)
  cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tresult: " << ret << endl;
  EXT_WV;
#endif
  return ret;
}

CDMi_RESULT MediaKeySession::Close(void) {
#if defined(DEBUG)
  ENT_WV;
#endif
  CDMi_RESULT status = CDMi_S_FALSE;

#if defined(USE_SVP)
  m_stSecureBuffInfo.bReleaseSecureMemRegion = true;
  if(0 != svp_release_secure_buffers(m_pSVPContext, (void*)&m_stSecureBuffInfo, nullptr, nullptr, 0))
  {
      fprintf(stderr, "[%s:%d]  secure memory, free failed",__FUNCTION__,__LINE__);
  }
  else {
      m_stSecureBuffInfo.bCreateSecureMemRegion = false;
      m_stSecureBuffInfo.SecureMemRegionSize = 0;
  }
#endif

  g_lock.Lock();
  if (widevine::Cdm::kSuccess == m_cdm->close(m_sessionId)) {
    status = CDMi_SUCCESS;
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tClose SUCCESS: " << status << endl;
#endif
  }
  g_lock.Unlock();
#if defined(DEBUG)
  cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tstatus: " << status << endl;
  EXT_WV;
#endif
  return status;
}

const char* MediaKeySession::GetSessionId(void) const {
#if defined(DEBUG)
  ENT_WV;
  cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tSessionId: " << m_sessionId.c_str() << endl;
  EXT_WV;
#endif
  return m_sessionId.c_str();
}

const char* MediaKeySession::GetKeySystem(void) const {
#if defined(DEBUG)
  ENT_WV;
  cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tKeySystem: " << NYI_KEYSYSTEM << endl;
  EXT_WV;
#endif
  return NYI_KEYSYSTEM;//TODO: replace with keysystem and test
}

CDMi_RESULT MediaKeySession::Init(
    int32_t licenseType,
    const char *f_pwszInitDataType,
    const uint8_t *f_pbInitData,
    uint32_t f_cbInitData,
    const uint8_t *f_pbCDMData,
    uint32_t f_cbCDMData) {
#if defined(DEBUG)
  ENT_WV;
#endif
  switch ((LicenseType)licenseType) {
  case PersistentUsageRecord:
    m_licenseType = widevine::Cdm::kPersistentUsageRecord;
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tPersistentUsageRecord: " << m_licenseType <<endl;
#endif
    break;
  case PersistentLicense:
    m_licenseType = widevine::Cdm::kPersistentLicense;
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tPersistentLicense: " << m_licenseType<<endl;
#endif
    break;
  default:
    m_licenseType = widevine::Cdm::kTemporary;
#if defined(DEBUG)
    cout << "\n[RDK_LOG]" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "\tTemporary: " << m_licenseType << endl;
#endif
    break;
  }

  if (f_pwszInitDataType) {
    if (!strcmp(f_pwszInitDataType, "cenc"))
       m_initDataType = widevine::Cdm::kCenc;
    else if (!strcmp(f_pwszInitDataType, "webm"))
       m_initDataType = widevine::Cdm::kWebM;
  }

  if (f_pbInitData && f_cbInitData)
    m_initData.assign((const char*) f_pbInitData, f_cbInitData);

  if (f_pbCDMData && f_cbCDMData)
    m_CDMData.assign((const char*) f_pbCDMData, f_cbCDMData);
#if defined(DEBUG)
  EXT_WV;
#endif
  return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::SetParameter(const std::string& name, const std::string& value)
{
  CDMi_RESULT retVal = CDMi_S_FALSE;

  if(name.find("mediaType") != std::string::npos) {
    if(value.find("video") != std::string::npos) {
      // Found a video mime type
      m_StreamType = Video;
      retVal = CDMi_SUCCESS;
    }
    else if(value.find("audio") != std::string::npos) {
      // Found a audio mime type
      m_StreamType = Audio;
      retVal = CDMi_SUCCESS;
    }
  }

  if(name.find("RESOLUTION") != std::string::npos) {

    if (m_cdm != nullptr)
    {
      uint32_t videoWidth;
      uint32_t videoHeight;
      sscanf(value.c_str(), "%d,%d", &videoWidth, &videoHeight);
      m_cdm->setVideoResolution(m_sessionId, videoWidth, videoHeight);
    }
    else
    {
#if defined(DEBUG)
    cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] m_cdm is NULL" << endl;
#endif
    }
  }

  if(name.find("rpcId") != std::string::npos) {

    // Got the RPC ID for gst-svp-ext communication
    unsigned int nID = 0;
    nID =  (unsigned int)std::stoul(value.c_str(), nullptr, 16);
    if(nID != 0) {
#ifdef USE_SVP
      //fprintf(stderr, "Initializing SVP context for client side ID = %X\n", nID);
      gst_svp_ext_get_context(&m_pSVPContext, Client, nID);
#endif
    }
  }

  return retVal;
}

CDMi_RESULT MediaKeySession::Decrypt(
        uint8_t*                 inData,          // Incoming encrypted data
        const uint32_t           inDataLength,    // Incoming encrypted data length
        uint8_t**                outData,         // Outgoing decrypted data
        uint32_t*                outDataLength,   // Outgoing decrypted data length
        const SampleInfo*        sampleInfo,      // Information required to decrypt Sample
        const IStreamProperties* properties)
{
  g_lock.Lock();
  widevine::Cdm::KeyStatusMap map;
  std::string keyStatus;

  void *pEncryptedDataStart  = nullptr;
  widevine::Cdm::Subsample subsamplesInfo[ 2 ];
  CDMi_RESULT status = CDMi_S_FALSE;
  *outDataLength = 0;
  unsigned char iv[16];
  /* by default SVP is enabled for both A/V */
  bool useSVP = true;
  bool bIsDynamicSVPEncEnabled = false;
  void *DstPhys = NULL;

  void * header = NULL;
  void* secToken = NULL;

#ifdef USE_SVP
  bIsDynamicSVPEncEnabled = svpIsDynamicSVPEncEnabled();
  if (bIsDynamicSVPEncEnabled)
  {
    /* Dynamic SVP supported means, SVP is enabled for Video only */
    if (properties->GetMediaType() != Video) {
      useSVP = false;
    }
  }
#endif

  memset(iv,0,16);
  memcpy(iv,(char*)sampleInfo->iv, sampleInfo->ivLength);

  if (widevine::Cdm::kSuccess == m_cdm->getKeyStatuses(m_sessionId, &map)) {
#if defined(DEBUG)
    cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] m_cdm->getKeyStatuses is SUCCESS" << endl;
#endif
    widevine::Cdm::KeyStatusMap::iterator it;
    if(sampleInfo->keyIdLength > 0) {
      // if keyid is provided, find it in the map
      std::string keyIdString((const char*) sampleInfo->keyId, (size_t) sampleInfo->keyIdLength);
#if defined(DEBUG)
      cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] KeyIdString: " << keyIdString.c_str() << endl;
#endif
      it = map.find(keyIdString);
    } else {
      // if no keyid is provided, use the first one in the map
#if defined(DEBUG)
      cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] keyid is not provided" << endl;
#endif
      it = map.begin();
    }

    // FIXME: We just check the first key? How do we know that's the Widevine key and not, say, a PlayReady one?
    if (widevine::Cdm::kUsable == it->second) {
	    // Here we will sepreate each of these to create the decryptSample
	    widevine::Cdm::Sample decryptSample;
	    uint32_t actualEncDataLength = 0;

  if (gst_svp_has_header(m_pSVPContext, inData))
  {
    header = (void*)inData;
    pEncryptedDataStart = reinterpret_cast<uint8_t *>(gst_svp_header_get_start_of_data(m_pSVPContext, header));
    gst_svp_header_get_field(m_pSVPContext, header, SvpHeaderFieldName::DataSize, &actualEncDataLength);
  }

#if defined(DEBUG)
	    cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] actualEncDataLength: " << actualEncDataLength << endl;
#endif

#ifdef USE_SVP

  if (useSVP) {

    // Reallocate input memory if needed.
    if(m_stSecureBuffInfo.bCreateSecureMemRegion)
    {
      if (actualEncDataLength >  m_stSecureBuffInfo.SecureMemRegionSize) {
          m_stSecureBuffInfo.bReleaseSecureMemRegion = true;
          if(0 != svp_release_secure_buffers(m_pSVPContext, (void**)&m_stSecureBuffInfo, nullptr, nullptr, 0))
          {
              fprintf(stderr, "[%s:%d]  Secure memory free falied",__FUNCTION__,__LINE__);
              goto ErrorExit;
          }
          m_stSecureBuffInfo.SecureMemRegionSize = actualEncDataLength;
          m_stSecureBuffInfo.bReleaseSecureMemRegion = false;
          m_stSecureBuffInfo.bCreateSecureMemRegion = true;

          if(0 != svp_allocate_secure_buffers(m_pSVPContext, (void**)&m_stSecureBuffInfo, nullptr, nullptr, m_stSecureBuffInfo.SecureMemRegionSize))
          {
              fprintf(stderr, "[%s:%d] Secure memory, re-allocation failed %d",__FUNCTION__,__LINE__, m_stSecureBuffInfo.SecureMemRegionSize);
              goto ErrorExit;
          }
      }
    }

    m_stSecureBuffInfo.patternClearBlocks = sampleInfo->pattern.clear_blocks;

    if(0 != svp_allocate_secure_buffers(m_pSVPContext, (void**)&m_stSecureBuffInfo, nullptr, (uint8_t*)pEncryptedDataStart, actualEncDataLength))
    {
        fprintf(stderr, "[%s:%d]  secure memory, allocate failed [%d]",__FUNCTION__,__LINE__, actualEncDataLength);
        goto ErrorExit;
    }

    svp_buffer_alloc_token(&secToken);
    svp_buffer_to_token(m_pSVPContext, (void *)&m_stSecureBuffInfo, secToken);
  }

#endif

#if defined(DEBUG)
 	    cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] subSampleCount: " << sampleInfo->subSampleCount << endl;
#endif
      if (useSVP)
        decryptSample.input.data = static_cast<const uint8_t*>( m_stSecureBuffInfo.pEncryptedDataBuffer );
      else
	      decryptSample.input.data = static_cast<const uint8_t*>( pEncryptedDataStart );

	    decryptSample.input.data_length = actualEncDataLength;
	    decryptSample.input.iv = iv;
	    decryptSample.input.iv_length = sizeof(iv);

      if (sampleInfo->subSampleCount != 0 ) {
        decryptSample.input.subsamples = (const widevine::Cdm::Subsample*) sampleInfo->subSample;
	      decryptSample.input.subsamples_length = sampleInfo->subSampleCount;
      } else{
        memset( subsamplesInfo, 0, sizeof( subsamplesInfo ) );
        subsamplesInfo[ 0 ].clear_bytes = 0;
        subsamplesInfo[ 0 ].protected_bytes = actualEncDataLength;

        decryptSample.input.subsamples = (const widevine::Cdm::Subsample*) subsamplesInfo;
        decryptSample.input.subsamples_length = 1;
      }

	    if (useSVP)
		    decryptSample.output.data = m_stSecureBuffInfo.pPhysAddr;
	    else
		    decryptSample.output.data = pEncryptedDataStart;

	    decryptSample.output.data_offset = 0;
	    decryptSample.output.data_length = actualEncDataLength;

	    widevine::Cdm::DecryptionBatch decryptionBatch;
	    decryptionBatch.key_id = sampleInfo->keyId;
	    decryptionBatch.key_id_length = sampleInfo->keyIdLength;
	    decryptionBatch.samples = &decryptSample;
	    decryptionBatch.samples_length = 1;
	    decryptionBatch.pattern.encrypted_blocks = sampleInfo->pattern.encrypted_blocks;
	    decryptionBatch.pattern.clear_blocks = sampleInfo->pattern.clear_blocks;
	    if (useSVP) {
		    decryptionBatch.is_secure = true;
		    decryptionBatch.is_video = true;
	    } else {
		    decryptionBatch.is_secure = false;
		    decryptionBatch.is_video = false;
	    }

	    switch (sampleInfo->scheme) {
            case AesCtr_Cenc:
            case AesCtr_Cens:
		    //case 0:
			    decryptionBatch.encryption_scheme = widevine::Cdm::kAesCtr;
#if defined(DEBUG)
			    cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] Inside kAesCtr" << endl;
#endif
			    break;
            case AesCbc_Cbc1:
            case AesCbc_Cbcs:
		    //case 1:
			    decryptionBatch.encryption_scheme = widevine::Cdm::kAesCbc;
#if defined(DEBUG)
			    cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] Inside kAesCbc" << endl;
#endif
			    break;
	    }

	    if (widevine::Cdm::kSuccess == m_cdm->decrypt(m_sessionId, decryptionBatch)) {

        if (useSVP) {
#ifdef USE_SVP

          if (header)
          {
            gst_svp_header_set_field(m_pSVPContext, header, SvpHeaderFieldName::Type, TokenType::Handle);
          }
          memcpy((uint8_t *)pEncryptedDataStart, secToken, svp_token_size());
          svp_buffer_free_token(secToken);
          //TODO: note the return token data and size
#endif
          *outData = const_cast<uint8_t*>(inData);
          *outDataLength = inDataLength;
        } else{
          // Add a header to the output buffer.
          if (header)
          {
            gst_svp_header_set_field(m_pSVPContext, header, SvpHeaderFieldName::Type, TokenType::InPlace);
          }
		    } 

		    status = CDMi_SUCCESS;
#if defined(DEBUG)
		    cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] decryption success..! and status: " << status << endl;
#endif
	    }else{
		    cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] decryption failed..!" << endl;
#ifdef USE_SVP
      if (useSVP)
      {
        m_stSecureBuffInfo.bReleaseSecureMemRegion = false;
        // Free decrypted secure buffer.
        svp_release_secure_buffers(m_pSVPContext, (void*)&m_stSecureBuffInfo, m_stSecureBuffInfo.pAVSecBuffer , nullptr, 0);
      }
#endif
	    }

    }
  }

  g_lock.Unlock();
#if defined(DEBUG)
  cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "] status: " << status << endl;
  EXT_WV;
#endif

ErrorExit:
  return status;
}

CDMi_RESULT MediaKeySession::ReleaseClearContent(
    const uint8_t *f_pbSessionKey,
    uint32_t f_cbSessionKey,
    const uint32_t  f_cbClearContentOpaque,
    uint8_t  *f_pbClearContentOpaque ){
#if defined(DEBUG)
  ENT_WV;
#endif

  CDMi_RESULT ret = CDMi_S_FALSE;
  if (f_pbClearContentOpaque) {
    free(f_pbClearContentOpaque);
    ret = CDMi_SUCCESS;
#if defined(DEBUG)
    cout << "\n[RDK_LOG:" << __FILE__ << "(" << __LINE__ << ")" << __FUNCTION__ << "]ReleaseClearContent SUCCESS: " << ret <<endl;
#endif
  }

#if defined(DEBUG)
  EXT_WV;
#endif
  return ret;
}

}  // namespace CDMi
