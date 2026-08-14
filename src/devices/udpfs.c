// Implements support for MMCE devices
#include "common.h"
#include "devices/devices.h"
#include "dprintf.h"
#include "ftp.h"
#include "ui/ui.h"
#include <errno.h>
#include <kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char udpfsMountpoint[] = "udpfs0:";

// Initializes map entries for MMCE devices
int initUDPFSDevices(int newDeviceIdx) {
  DIR *directory;

  int deviceCount = 0;
  const ModeType storageModes = LAUNCHER_OPTIONS.mode &
                                (MODE_ATA | MODE_MX4SIO | MODE_UDPFS |
                                 MODE_USB | MODE_ILINK | MODE_MMCE | MODE_HDL);
  const int udpfsIsRequired = (storageModes == MODE_UDPFS);

  /* The IOP device remains registered even when its first discovery attempt
   * fails. Retry discovery so booting before the cable or Windows service is
   * ready becomes a clear waiting state instead of a safe-dashboard loop. */
  for (int attempts = 0; udpfsIsRequired || (attempts < 4); attempts++) {
    int status = ftpGetUdpfsConnectionStatus();
    if (status <= 0) {
      if ((attempts == 0) || ((attempts % 6) == 0))
        uiSplashLogString(LEVEL_WARN,
                          "Ethernet/UDPFS server unavailable\nReconnecting automatically...\n");
      ftpRequestUdpfsReconnect();
    }

    directory = opendir(udpfsMountpoint);
    if (directory != NULL) {
      closedir(directory);
      uiSplashLogString(LEVEL_INFO_NODELAY, "Found device %s\n", udpfsMountpoint);

      deviceModeMap[newDeviceIdx].mode = MODE_UDPFS;
      deviceModeMap[newDeviceIdx].index = 0;
      deviceModeMap[newDeviceIdx].mountpoint = strdup(udpfsMountpoint);
      deviceModeMap[newDeviceIdx].scan = &findISO;

      deviceCount++;
      newDeviceIdx++;
      return deviceCount;
    }
    sleep(1);
  }
  return 0;
}
