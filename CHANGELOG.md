# CHANGELOG - NextGenBlock

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-14

### Added
- Modern PyQt6 interface with real-time dashboard
- WinDivert-based packet capture with deep packet inspection
- GeoIP-based country blocking and threat intelligence feeds
- IDS/IPS behavioral detection system
- DNS filtering with sinkhole capability
- Application-level filtering by process ID and executable
- IPv6 support for modern networks
- SQLite-based structured logging
- Passive observation mode (default, safe)
- Active blocking mode (user-configurable)

### Features
- **IP Blocking**: Optimized CIDR notation for efficient list management
- **DPI (Deep Packet Inspection)**: Protocol-level filtering
- **Geo-blocking**: Block traffic by country/region
- **Application Filtering**: Block traffic per application
- **Threat Intelligence**: Real-time feed integration
- **Modern Driver**: WinDivert (signed, Windows Filtering Platform)

### Changed
- Improved from PeerBlock (abandoned since 2014)
- Modern architecture for Windows 10/11
- Performance optimizations for large blocklists

### Security
- Windows Filtering Platform integration
- Signed driver for secure operation
- Administrator-only blocking mode

---

## Roadmap

### Planned for v1.1.0
- [ ] Rule scheduling (time-based blocking)
- [ ] Custom protocol detection
- [ ] Performance dashboards
- [ ] Export/import configurations

### Planned for v1.2.0
- [ ] API for third-party tools
- [ ] Advanced anomaly detection
- [ ] Detailed threat reports

---

## Installation

```bash
pip install -r requirements.txt
python run.py
```

## Support

For issues and feature requests: https://github.com/K413MP3R4/NextGenBlock/issues

## License

MIT License - See LICENSE file for details
