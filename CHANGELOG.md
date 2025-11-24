# Changelog

All notable changes to this project will be documented in this file.

## [v1.0.3] – 2025-11-24
### Added
- `last_seen_at` timestamp for each device.
- New “Last Seen” column in the UI.

### Changed
- Offline devices now retain their last_seen_at timestamp (IP resets to "-" but last_seen_at remains).
- Scan timestamps now use the system’s local time.

### Fixed
- Database migration for `last_seen_at` is now handled automatically **via the install script** on upgrade.
- IPv6 cleanup properly removes IPv6 addresses when IPv6 discovery is disabled.

## [v1.0.2] – 2025-11-19
### Changed
- Updated IP handling: device IP lists are now rebuilt on each scan, ensuring only addresses detected in the latest scan are stored.
- Replaced checkbox controls with modern toggle switches for a cleaner and more consistent UI.

## [v1.0.1] – 2025-11-16
### Changed
- Added modal dialog for devices with multiple IP addresses (IPv4/IPv6).
- Improved text readability in dialogs (modals use dark text on light background).
- Prevented layout overflow when many IP addresses are shown.
- Bumped internal version to 1.0.1.

## [v1.0.0] – 2025-11-15
### Added
- Initial public release of EggScan.
- Nmap-based network scan for configured subnets.
- Web dashboard with login, user management and basic settings.
- Device list with IP, MAC, alias, manufacturer, ping and status (online/offline).
