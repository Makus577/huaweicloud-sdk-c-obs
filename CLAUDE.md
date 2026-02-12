# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Huawei Cloud OBS (Object Storage Service) C SDK - version 3.24.x
A C SDK for interacting with Huawei Cloud Object Storage Service, with support for standard TLS and Chinese national cryptography (SM2/SM3/SM4) via Tongsuo, as well as mutual TLS authentication.

## Build Commands

### Standard Build (CMake)
```bash
# Clean build directory
rm -rf build && mkdir build && cd build

# Configure with CMake (Debug mode by default)
cmake ..

# Configure with Release mode
cmake -DCMAKE_BUILD_TYPE=Release ..

# Enable GM (National Cryptography) support
cmake -DOBS_ENABLE_GM_SUPPORT=ON ..

# Build
make -j4

# Output: lib/libeSDKOBS.so
```

### Alternative Build Scripts
```bash
# For aarch64 (ARM64)
cd source/eSDK_OBS_API/eSDK_OBS_API_C++
./build_aarch64.sh

# For macOS
./build_macos.sh

# For NDK (Android)
./build_ndk_aarch64.sh
```

### Test Commands
```bash
# Run SSL configuration tests
cd source/eSDK_OBS_API/eSDK_OBS_API_C++/test
./test.sh

# Or run individual test binary
./ssl_config_test
```

## Architecture Overview

### Directory Structure
```
source/eSDK_OBS_API/eSDK_OBS_API_C++/
├── inc/              # Public headers (eSDKOBS.h is main API header)
├── include/          # Internal headers
├── src/              # Core SDK implementation
│   ├── bucket/        # Bucket operations
│   ├── object/        # Object operations
│   ├── general.c      # SSL/TLS adapter and general utilities
│   ├── request.c       # HTTP request handling
│   ├── ssl_config.c    # SSL configuration management
│   ├── ssl_gm_config.c # GM (national crypto) SSL configuration
│   └── obs_sm_crypto.c # GM crypto abstraction layer
└── test/             # Unit tests
```

### Core Layers

1. **API Layer** (`inc/eSDKOBS.h`) - Public SDK interface
2. **Core Layer** (`src/`) - Implementation of bucket/object operations
3. **HTTP Layer** (`request.c`, `request_util.c`) - HTTP request/response handling
4. **SSL/TLS Layer**:
   - `ssl_config.c/h` - Configuration management
   - `ssl_gm_config.c/h` - GM-specific SSL configuration
   - `obs_sm_crypto.c/h` - GM crypto abstraction (SM2/SM3/SM4)
5. **Transport** - libcurl + Tongsuo/OpenSSL for TLS

### SSL/TLS Architecture

The SDK supports two SSL/TLS modes:

#### Standard TLS Mode
- Uses standard ciphers like ECDHE-RSA-AES256-GCM-SHA384
- Supports TLS v1.0 through v1.3
- Configurable via `ssl_min_version`/`ssl_max_version`

#### GM (National Cryptography) Mode
- Requires Tongsuo library (currently strongly coupled)
- Uses SM2/SM3/SM4 algorithms with ciphers like ECDHE-SM2-WITH-SM4-SM3
- Enforces TLS v1.2 (GM algorithms compatibility requirement)
- Configured via `gm_mode_switch = OBS_GM_MODE_OPEN`

**Important**: GM support is disabled by default. Enable with `-DOBS_ENABLE_GM_SUPPORT=ON` at compile time.

### Configuration Hierarchy

Configuration is applied in this priority order (highest to lowest):
1. API calls (programmatic configuration)
2. Environment variables (currently disabled for security)
3. Configuration file (OBS.ini - currently disabled for SSL/GM config)

The `ssl_config.c` module implements a configuration manager with source tracking to know which source set each config value.

### Key Data Structures

**obs_http_request_option** (main SSL configuration structure):
```c
- mutual_ssl_switch:     OBS_MUTUAL_SSL_OPEN/CLOSE
- client_cert_path:       Path to client certificate (PEM)
- client_key_path:        Path to client private key (PEM)
- client_key_password:     Private key password (optional)
- gm_mode_switch:         OBS_GM_MODE_OPEN/CLOSE
- ssl_cipher_list:         Custom cipher list string
- ssl_min_version:         Minimum TLS version
- ssl_max_version:         Maximum TLS version
- server_cert_path:       Custom CA certificate path
- verify_hostname:         Hostname verification flag
```

### SSL Configuration Flow

1. `obs_options` initialization
2. `load_ssl_config_from_ini()` - Parse OBS.ini (disabled for SSL/GM)
3. `load_ssl_config_from_env()` - Load env vars (disabled for security)
4. API calls set individual options
5. `validate_ssl_config()` - Validates configuration consistency
6. `setup_CA()` in `request.c` - Applies SSL settings to curl handle

## Security Considerations

- SSL/GM configuration (mutual auth, GM mode) should ONLY be set via API, not from config files or environment variables (security measure)
- Client certificates and private keys must be valid file paths
- Hostname verification is enabled by default
- The `setup_CA()` function in `general.c` handles SSL context configuration with curl

## Dependencies

Required libraries (versions may vary):
- libcurl (8.11.1)
- Tongsuo/OpenSSL (8.3.0 for Tongsuo)
- libxml2 (2.9.9)
- pcre (8.45)
- iconv (1.15)
- cjson (1.7.18)
- spdlog (1.12.0)
- eSDKLogAPI (internal logging)

## GM (National Cryptography) Notes

The current implementation has a **strong coupling** to Tongsuo:
- Build system hardcodes `TONGSUO_VERSION = tongsuo-8.3.0`
- Code checks for Tongsuo-specific ciphers and version strings
- libcurl must be built against Tongsuo to support GM ciphers

This is a deliberate design choice for now - Tongsuo is the most mature GM implementation. The design document (`OBS_C_SDK_HTTPS_SM_Final_Document.md`) discusses a future abstraction layer to support multiple backends.

## Platform Support

- Linux (x86_64, aarch64)
- macOS
- Android NDK

Platform-specific build directories are selected based on `uname -m` output.
