# Mini-SIEM
Security Information and Event Management configured in a server with a script that sends a Telegram message when a SSH brute force attack takes place.

For obvious reasons I can not upload the server's ISO that I used for this. Instead, I will leave here the specifications.

## Specifications
- OS: Ubuntu Server 22.04
- Partition Configuration: Manual
  - `/` - 10GB
  - `/boot`- 2GB
  - `/home` - 7GB
  - `/srv` - 5GB
  - `/var` - where all variables and logs will be. I assigned 6GB here assuming it was going to store a great amount of log files.
- Firewall: Nginx 1.30.5 (configured with `proxy_pass` in `nginx.conf`)

