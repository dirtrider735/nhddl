# Editable network settings (hardware-testing feature)

This feature extends the integrated FTP/UDPFS dashboard with:

- editable DHCP or static IPv4 mode;
- editable console address, subnet mask, and gateway;
- validation before settings are written;
- an atomic primary/backup configuration-file update;
- caching of a successful DHCP lease for Neutrino's in-game UDPFS transport;
- automatic title-list reconnect attempts after Ethernet or server loss; and
- a manual reconnect action in Settings.

The dashboard and in-game loader use different UDPFS transports. The dashboard
can request DHCP through PS2IP, while Neutrino's compact in-game transport still
needs a deterministic numeric address. A successful DHCP lease is therefore
saved as Neutrino's address before a game is launched.

This branch is deliberately separate from the hardware-proven integrated-FTP
release candidate. It builds successfully, but DHCP, cable removal/reinsertion,
server restart, corrupt configuration recovery, and launch-after-reconnect must
all pass real-console testing before this branch is merged or shipped as the
default.

The preservation build completed successfully and produced a deterministic
442,580-byte packed ELF with SHA-256
`368E36EF99939D9C565F67BB3B6AC0B4EF0AEF0B43DAD444CF8577D56DE5F4E8`.
