#include "amd_oem.hpp"
#include "config.h"

#include <boost/system/error_code.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <ipmid/api.h>
#include <ipmid/handler.hpp>
#include <phosphor-logging/log.hpp>
#include <random>
#include <regex>
#include <security/pam_appl.h>
#include <sstream>
#include <string>
// #include <cstring>

#include <sdbusplus/bus.hpp>
#include <sdbusplus/message.hpp>

namespace ipmi {

using namespace phosphor::logging;
using namespace amd;
static std::mutex credentialBootstrappingMutex;
constexpr uint8_t credBootstrapEnabled = 0xA5;
static bool credentialBootstrappingControl = false;

// static void registerOEMFunctions() __attribute__((constructor));
void registerOEMFunctions() __attribute__((constructor(101)));

// sample skeleton function
ipmi::RspType<uint8_t, uint8_t, uint8_t>
ipmiOemAMDPlatID(Context::ptr ctx) {
  (void)ctx;

  log<level::INFO>("AMD platform " PLATFORM_NAME);

  uint8_t res0 = static_cast<uint8_t>(PLATFORM_NAME[0]);
  uint8_t res1 = static_cast<uint8_t>(PLATFORM_NAME[1]);
  uint8_t res2 = static_cast<uint8_t>(PLATFORM_NAME[2]);

  return ipmi::responseSuccess(res0, res1, res2);
}

bool getRandomUserName(std::string &uniqueStr) {
  std::ifstream randFp("/dev/urandom", std::ifstream::in);
  char byte;
  uint8_t maxStrSize = USERNAME_SIZE;

  if (!randFp.is_open()) {
    log<level::ERR>("getRandomUserName: Failed to open urandom file");
    return false;
  }

  for (uint8_t it = 0; it < maxStrSize; it++) {
    while (1) {
      if (randFp.get(byte)) {
        if (iswalnum(byte)) {
          if (it == 0) {
            if (iswalpha(byte)) {
              break;
            }
          } else {
            break;
          }
        }
      }
    }
    uniqueStr.push_back(byte);
  }
  randFp.close();
  return true;
}

bool isValidUserName(const std::string &userName) {
  if (userName.empty()) {
    log<level::ERR>("Requested empty UserName string");
    return false;
  }
  if (!std::regex_match(userName.c_str(),
                        std::regex("[a-zA-z_][a-zA-Z_0-9]*"))) {
    log<level::ERR>("Unsupported characters in string");
    return false;
  }

  return true;
}

bool getRandomPassword(std::string &uniqueStr) {
  std::ifstream randFp("/dev/urandom", std::ifstream::in);
  char byte;
  uint8_t maxStrSize = PASSWORD_SIZE;
  std::string invalidChar = "\'\\\"";

  if (!randFp.is_open()) {
    log<level::ERR>("getRandomPassword: Failed to open urandom file");
    return false;
  }

  for (uint8_t it = 0; it < maxStrSize; it++) {
    while (1) {
      if (randFp.get(byte)) {
        if (iswprint(byte)) {
          if (!iswspace(byte) && invalidChar.find(byte) == std::string::npos) {
            if (it == 0) {
              if (iswlower(byte)) {
                break;
              }
            } else if (it == 1) {
              if (iswupper(byte)) {
                break;
              }
            } else if (it == 2) {
              if (iswdigit(byte)) {
                break;
              }
            } else if (it == 3) {
              if (!iswdigit(byte) && !iswalpha(byte)) {
                break;
              }
            } else {
              break;
            }
          }
        }
      }
    }
    uniqueStr.push_back(byte);
  }
  randFp.close();
  std::random_device
      rd; // Will be used to obtain a seed for the random number engine
  std::mt19937 gen(rd()); // Standard mersenne_twister_engine seeded with rd()
  std::shuffle(uniqueStr.begin(), uniqueStr.end(), gen);
  return true;
}

bool isValidPassword(const std::string &password) {
  int i = 0;
  const char *ptr = password.c_str();

  while (ptr[0] && ptr[1]) {
    if ((ptr[1] == (ptr[0] + 1)) || (ptr[1] == (ptr[0] - 1))) {
      i++;
    }
    ptr++;
  }

  int maxrepeat = 3 + (0.09 * password.length());
  if (i > maxrepeat) {
    log<level::DEBUG>("isValidPassword: Password is too simplistic/systematic");
    return false;
  }
  return true;
}

// function used to get user input
inline int pamFunctionConversation(int numMsg, const struct pam_message **msg,
                                   struct pam_response **resp,
                                   void *appdataPtr) {
  if ((appdataPtr == nullptr) || (msg == nullptr) || (resp == nullptr)) {
    return PAM_CONV_ERR;
  }

  if (numMsg <= 0 || numMsg >= PAM_MAX_NUM_MSG) {
    return PAM_CONV_ERR;
  }

  auto msgCount = static_cast<size_t>(numMsg);
  auto messages = std::span(msg, msgCount);
  auto responses = std::span(resp, msgCount);

  for (size_t i = 0; i < msgCount; ++i) {
    /* Ignore all PAM messages except prompting for hidden input */
    if (messages[i]->msg_style != PAM_PROMPT_ECHO_OFF) {
      continue;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    char *appPass = reinterpret_cast<char *>(appdataPtr);
    size_t appPassSize = std::strlen(appPass);

    if ((appPassSize + 1) > PAM_MAX_RESP_SIZE) {
      return PAM_CONV_ERR;
    }
    // IDeally we'd like to avoid using malloc here, but because we're
    // passing off ownership of this to a C application, there aren't a lot
    // of sane ways to avoid it.

    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
    void *passPtr = malloc(appPassSize + 1);
    char *pass = reinterpret_cast<char *>(passPtr);
    if (pass == nullptr) {
      return PAM_BUF_ERR;
    }

    std::strncpy(pass, appPass, appPassSize + 1);

    size_t numMsgSize = static_cast<size_t>(numMsg);
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
    void *ptr = calloc(numMsgSize, sizeof(struct pam_response));
    if (ptr == nullptr) {
      free(pass);
      return PAM_BUF_ERR;
    }

    *resp = reinterpret_cast<pam_response *>(ptr);
    responses[i]->resp = pass;

    return PAM_SUCCESS;
  }

  return PAM_CONV_ERR;
}

int pamUpdatePasswd(const char *username, const char *password) {
  const struct pam_conv localConversation = {pamFunctionConversation,
                                             const_cast<char *>(password)};

  pam_handle_t *localAuthHandle = NULL; // this gets set by pam_start
  int retval =
      pam_start("webserver", username, &localConversation, &localAuthHandle);
  if (retval != PAM_SUCCESS) {
    log<level::ERR>(
        ("pam_start failed. RETVAL=" + std::to_string(retval)).c_str());
    return retval;
  }

  retval = pam_chauthtok(localAuthHandle, PAM_SILENT);
  if (retval != PAM_SUCCESS) {
    pam_end(localAuthHandle, retval);
    log<level::ERR>(
        ("pam_chauthtok failed. RETVAL=" + std::to_string(retval)).c_str());
    return retval;
  }
  return pam_end(localAuthHandle, PAM_SUCCESS);
}

static void setCredentialBootstrappingState(bool enabled)
{
    std::lock_guard<std::mutex> lock(credentialBootstrappingMutex);
    credentialBootstrappingControl = enabled;
}

static void disableAllCredentialBootstrappingUsers()
{
    std::lock_guard<std::mutex> lock(credentialBootstrappingMutex);
    credentialBootstrappingControl = false;
}

ipmi::RspType<std::vector<uint8_t>>
ipmiOemAMDGetBootStrapAccount(Context::ptr ctx, uint8_t disableCredBootstrap) {

  (void)ctx;

  if (disableCredBootstrap != credBootstrapEnabled) {
    disableAllCredentialBootstrappingUsers();

    log<level::ERR>("disable credential bootstrapping");
    std::vector<uint8_t> res(USERNAME_SIZE + PASSWORD_SIZE, 0);
    return ipmi::responseSuccess(res);
  }

  std::string randomUserName;

  bool ret = getRandomUserName(randomUserName);
  if (!ret) {
    log<level::ERR>(
        "ipmiOemAMDGetBootStrapAccount: Failed to generate alphanumeric "
        "UserName");
    return ipmi::responseResponseError();
  }

  constexpr std::string_view bootstrapSuffix = "bsu";
  static_assert(USERNAME_SIZE >= bootstrapSuffix.size(),
                "USERNAME_SIZE must be >= bootstrap suffix size");

  std::string userName =
      randomUserName.substr(0, USERNAME_SIZE - bootstrapSuffix.size()) +
      std::string(bootstrapSuffix);

  if (!isValidUserName(userName)) {
    log<level::ERR>(
        "ipmiOemAMDGetBootStrapAccount: Failed to generate valid UserName");
    return ipmi::responseResponseError();
  }

  auto bus = sdbusplus::bus::new_default();
  const std::string userMgrService = "xyz.openbmc_project.User.Manager";
  const std::string userMgrPath = "/xyz/openbmc_project/user";
  const std::string userMgrInterface = "xyz.openbmc_project.User.Manager";

  try {
    auto method =
        bus.new_method_call(userMgrService.c_str(), userMgrPath.c_str(),
                            userMgrInterface.c_str(), "CreateUser");

    method.append(userName, std::vector<std::string>{"redfish"}, "priv-admin",
                  true);

    auto reply = bus.call(method);
    if (reply.is_method_error()) {
      log<level::ERR>("D-Bus CreateUser failed");
      return ipmi::responseResponseError();
    }
  } catch (const std::exception &e) {
    log<level::ERR>("Exception during D-Bus user creation",
                    phosphor::logging::entry("EX=%s", e.what()));
    return ipmi::responseResponseError();
  }

  std::string password;
  bool passwordIsValid = false;
  int max_retries = 10;

  while (!passwordIsValid && (max_retries != 0)) {
    password.clear();
    ret = getRandomPassword(password);
    if (!ret) {
      log<level::ERR>(
          "ipmiOemAMDGetBootStrapAccount: Failed to generate alphanumeric "
          "Password");
      return ipmi::responseResponseError();
    }
    passwordIsValid = isValidPassword(password);
    max_retries--;
  }

  if (!passwordIsValid) {
    log<level::ERR>("ipmiOemAMDGetBootStrapAccount: Failed to generate valid "
                    "Password");
    return ipmi::responseResponseError();
  }

  int retval = pamUpdatePasswd(userName.c_str(), password.c_str());
  if (retval != PAM_SUCCESS) {
    try {
      auto method = bus.new_method_call(
          userMgrService.c_str(), (userMgrPath + "/" + userName).c_str(),
          "xyz.openbmc_project.Object.Delete", "Delete");
      auto reply = bus.call(method);
      if (reply.is_method_error()) {
        log<level::ERR>("D-Bus Delete failed");
        return ipmi::responseResponseError();
      }
    } catch (const std::exception &e) {
      log<level::ERR>("Exception during D-Bus user deletion",
                      phosphor::logging::entry("EX=%s", e.what()));
      return ipmi::responseResponseError();
    }
    return ipmi::responseResponseError();
  }

  setCredentialBootstrappingState(true);

  std::vector<uint8_t> res(USERNAME_SIZE + PASSWORD_SIZE, 0);

  std::memcpy(res.data(), userName.data(), USERNAME_SIZE);
  std::memcpy(res.data() + USERNAME_SIZE, password.data(), PASSWORD_SIZE);

  return ipmi::responseSuccess(res);
}

void registerOEMFunctions(void) {

  log<level::NOTICE>(
      "Registering ipmiOemAMDPlatID: ",
      entry("NetFn:[%02Xh], ", IPMI_GROUP_HANDLER),
      entry("Cmd:[%02Xh], ", CMD_PLATFORM_ID),
      entry("GroupId:[%02Xh]", REDFISH_BOOTSTRAP_GRPEXT_ID));

  ipmi::registerGroupHandler(ipmi::prioOemBase,
                             amd::REDFISH_BOOTSTRAP_GRPEXT_ID,
                             amd::CMD_PLATFORM_ID,
                             ipmi::Privilege::User,
                             ipmiOemAMDPlatID);

  log<level::NOTICE>(
      "Registering ipmiOemAMDGetBootStrapAccount: ",
      entry("NetFn:[%02Xh], ", IPMI_GROUP_HANDLER),
      entry("Cmd:[%02Xh], ", CMD_GET_BOOTSTRAP_ACC),
      entry("GroupId:[%02Xh]", REDFISH_BOOTSTRAP_GRPEXT_ID));

      ipmi::registerGroupHandler(ipmi::prioOemBase,
                             amd::REDFISH_BOOTSTRAP_GRPEXT_ID,
                             amd::CMD_GET_BOOTSTRAP_ACC,
                             ipmi::Privilege::Admin, // SYSTEM_INTERFACE - mapped in phosphor-ipmi-host/ipmid-new.cpp
                             ipmiOemAMDGetBootStrapAccount);
}

} // namespace ipmi
