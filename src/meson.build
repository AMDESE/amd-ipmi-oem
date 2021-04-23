configure_file(output: 'config.h',
    configuration: cdata,
)

src_inc = include_directories('.')

so_version = '0.1.0'

shared_library(
  'amd-ipmi-oem',
  'amd_oem.cpp',
  dependencies: [
    phosphor_logging,
  ],
  version: so_version,
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers'
  )
