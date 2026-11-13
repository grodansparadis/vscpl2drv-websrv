# Changes in vscpl2drv-websrv

Every change that goes into a release is listed here, newest release first.
Add each change under **Unreleased** when it is made. When a release is
tagged, rename **Unreleased** to the version and date, and start a new
**Unreleased** section above it.

## Unreleased

- Replace the third_party git submodules (civetweb, vscp, spdlog, json, Mustache) and the copied Lua 5.3.5, duktape 2.7.0 and SQLite 3.50.4 sources with CMake FetchContent (same versions)
- Add scripts/download-artifacts.sh to download and verify the newest CI build artifacts
- CI writes a SHA256SUMS-<artifact> checksum file into every uploaded build artifact
- Adopted for new src structure (7d6f773)
- Cleaned up (5f5345c)
- Updated dependencies (842678f)

## v15.0.0 - 2021-07-01

- Updated changelog (fb37e97)
- Edit (f84810e)
- Added user database sample (8c0a19a)
- Prepare for firts release (a073472)
- Added configuaration info (6f84738)
- Added some documentation (a3569b4)
- Format (305f5b5)
- websocket functionality verified with demo (ad7f61e)
- Added tx handling (bd01afa)
- Verified REST interface functionality (14db298)
- Fixed ws1 authentication (8f32499)
- Added debug print out of settings (313ecb7)
- Fixed bug that eat to much cpu (4bcd698)
- Formated logging (1d7adfe)
- Webserver working (e0990fd)
- Debugging web config read in and start of server (b869277)
- Verified config read in (f638fe5)
- Replaced syslog with new logger mechansism (f7444ea)
- Config file read in (a27fa9b)
- Renamed project (68c926b)
- Clean compile (752cdbe)
- Added rest server to project (ebc2465)
- Added web, duktape and lua to project (2198b4b)
- Initial checkin (94aa9b5)
- Cleaned up (55b8609)
- First checkin (af3ba6f)
- Initial commit (fd1a689)
