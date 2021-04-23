#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace amd
{


enum ipmi_amd_net_fns
{
    NETFN_OEM_AMD = 0x30,
};

enum amd_oem_cmds
{
    CMD_OEM_PLATFORM_ID = 0x01,
};

enum
{
    AMD_IANA_ID = 0xE78,
};

struct AMDIANAHeader
{
    uint8_t iana[3];
} __attribute__((packed));

}
