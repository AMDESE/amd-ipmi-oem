project(
    'amd-ipmi-oem',
    'cpp',
    default_options: [
        'warning_level=3',
        'werror=true',
        'cpp_std=c++23',
        'prefix=/usr',
        'b_lundef=false',
        'buildtype=debugoptimized',
    ],
    license: 'Apache-2.0',
    version: '1.0',
)

cc = meson.get_compiler('cpp')

phosphor_dbus_interfaces = dependency('phosphor-dbus-interfaces')
phosphor_logging = dependency('phosphor-logging')
libipmid = dependency('libipmid')

pam = cc.find_library('pam', required: true)
atomic = cc.find_library('atomic', required: true)

# Add to dependencies list
amd_ipmi_oem_dependencies = [pam, atomic]

# Common configurations for src
cdata = configuration_data()
cdata.set_quoted('PLATFORM_NAME', get_option('PLATFORM_NAME'))

subdir('src')

