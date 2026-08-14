#ifndef _FTP_H_
#define _FTP_H_

#include <stdint.h>

// Dashboard network support. PS2IP, socket-backed UDPFS and ps2ftpd share one
// SMAP interface, so the same persisted configuration controls game browsing
// and the FTP server.  The configuration lives on memory card and is readable
// before the UDPFS device exists.

typedef enum {
  FTP_NET_STATIC = 0,
  FTP_NET_DHCP = 1,
} FtpNetMode;

typedef struct {
  FtpNetMode mode;
  char ip[16];
  char mask[16];
  char gw[16];
} FtpConfig;

// Loads the persisted network config into cfg. Returns 1 when a saved or
// rollback config was read and 0 when safe defaults were seeded from
// nhddl.yaml/IPCONFIG.DAT. Invalid/partial saved files are ignored so they
// cannot cause a boot loop; cfg is always initialized.
int ftpLoadConfig(FtpConfig *cfg);

// Validates and persists cfg to the memory card that launched NHDDL (falling
// back to the other slot). The static address is also the fallback/in-game
// address when dashboard DHCP is enabled.
int ftpValidateConfig(const FtpConfig *cfg);
int ftpSaveConfig(const FtpConfig *cfg);

// Keeps Neutrino's separate in-game ministack on the same saved static or
// DHCP-fallback address. Returns 0 when every discovered UDPFS config was
// updated, -ENOENT when no Neutrino config was present, or another negative
// errno-style result on failure.
int ftpSyncNeutrinoConfig(const FtpConfig *cfg);

// Starts the FTP server using cfg. On success returns 0 and writes the IP the
// server is reachable at into ipOut (the DHCP-assigned address in DHCP mode).
// On failure the IOP may already have been rebooted: the caller must relaunch
// the dashboard either way.
int ftpStartServer(const FtpConfig *cfg, char *ipOut, int ipOutLen);

// Diagnostic state survives the IOP swap in EE memory. The UI displays it
// verbatim on failure and also writes it to the memory card for later review.
const char *ftpGetLastDiagnostic(void);
void ftpWriteDiagnostic(const FtpConfig *cfg, int result);

// True once the replacement IOP has successfully loaded freepad.irx.
int ftpPadAvailable(void);

// Cleanly releases the currently loaded network stack's DEV9/SMAP hardware
// before an IOP reset or an ELF handoff. This must be called while fileXio is
// still alive, because DDIOC_OFF is exposed through the dev9x: device.
int ftpShutdownNetwork(void);

// Shared-stack dashboard mode. The SMAP argument builder is used before the
// PS2IP driver loads; attach verifies/applies that same configuration through
// ps2ips before UDPFS and ps2ftpd start.
char *ftpBuildSmapArguments(uint32_t *argLength);
int ftpAttachSharedNetwork(char *ipOut, int ipOutLen);

// The dashboard UDPFS IOP module keeps trying service discovery after a cable
// or server interruption. Status is 1=connected, 0=reconnecting, negative if
// the device is unavailable. The request function wakes an immediate retry.
int ftpGetUdpfsConnectionStatus(void);
int ftpRequestUdpfsReconnect(void);

// Background ps2ftpd status exposed to the game-list UI.
void ftpSetBackgroundStatus(int result);
int ftpIsBackgroundRunning(void);
int ftpGetBackgroundError(void);
const char *ftpGetBackgroundIP(void);

#endif
