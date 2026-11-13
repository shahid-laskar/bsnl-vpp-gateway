# Legacy vppctl oneshot units (retired 2026-11-13)

These units configured VPP with `vppctl` after `vpp.service` started. Because
`vpp.service` is `Type=simple`, `After=vpp.service` did not wait for the CLI
socket, and on 2026-11-13 06:35 UTC a restart failed with
`connect: Connection refused`, taking every dependent unit down.

Their configuration now lives in `deployment/vpp/bsnl-lab.cli`, executed by VPP
itself via `unix { exec ... }`. Kept for reference only; do not install.
