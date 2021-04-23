#include "config.h"
#include "amd_oem.hpp"

#include <ipmid/api.h>
#include <phosphor-logging/log.hpp>

namespace ipmi
{

using namespace phosphor::logging;
using namespace amd;

static void registerOEMFunctions() __attribute__((constructor));

ipmi_ret_t ipmiOemAMDPlatID(ipmi_netfn_t /* netfn */,
                                  ipmi_cmd_t /* cmd */, ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t /* context */)
{
    auto amd_h = reinterpret_cast<AMDIANAHeader*>(request);
    uint8_t* res = reinterpret_cast<uint8_t*>(response);

    if(*data_len != 3)
        return IPMI_CC_REQ_DATA_LEN_INVALID;

    if( (amd_h->iana[0] | amd_h->iana[1] << 8) != AMD_IANA_ID)
        return IPMI_CC_INVALID_FIELD_REQUEST;

    log<level::INFO>("AMD platform " PLATFORM_NAME);
    res[0] = PLATFORM_NAME[0];
    res[1] = PLATFORM_NAME[1];
    res[2] = PLATFORM_NAME[2];

    return IPMI_CC_OK;
}

void registerOEMFunctions(void)
{
    ipmi_register_callback(NETFN_OEM_AMD, CMD_OEM_PLATFORM_ID, nullptr,
                           ipmiOemAMDPlatID, PRIVILEGE_USER);
}

} // namespace ipmi
