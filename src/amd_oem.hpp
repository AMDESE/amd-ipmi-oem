#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace amd {

constexpr auto CMD_PLATFORM_ID = 0x01;
constexpr auto CMD_GET_BOOTSTRAP_ACC = 0x02;
constexpr auto REDFISH_BOOTSTRAP_GRPEXT_ID = 0x52;
constexpr auto IPMI_GROUP_HANDLER = 0x2C;

constexpr auto USERNAME_SIZE = 16;
constexpr auto PASSWORD_SIZE = 16;

enum ipmi_amd_net_fns {
  NETFN_OEM_AMD = 0x30,
};

enum amd_oem_cmds {
  CMD_OEM_PLATFORM_ID = 0x01,
  CMD_OEM_GET_BOOT_STRAP_ACC = 0x02,
};

enum {
  AMD_IANA_ID = 0xE78,
};

struct AMDIANAHeader {
  uint8_t iana[3];
} __attribute__((packed));

struct GetBootstrapAccCreds {
  uint8_t groupExtIdentification;
  uint8_t disableCredBootstrap;
} __attribute__((packed));

} // namespace amd
