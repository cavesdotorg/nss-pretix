# NSS AWS Hosted Pretix
https://tickets.caves.org

# TODO
1. Make YM auth available to all organizers to prevent having to set up the SSO provider manually for each one
1. Test with VTC org
1. Make reqs for convention

## Components
https://docs.pretix.eu/self-hosting/installation/docker_smallscale/
* pretix (Docker container on EC2)
* Caddy (Docker container on EC2, SSL termination + reverse proxy)
* PostgreSQL 14+ (Docker container on EC2)
* Redis (Docker container on EC2)
* SMTP for outbound emails

### AWS
* All-in-one: EC2 t3.medium running pretix, Redis, and PostgreSQL via Docker Compose
* SMTP: SES
* Storage: EBS gp3 50GB
* Backups: AWS Backup (daily snapshots, 60-day retention)


### AWS Pricing

Prices for us-east-2 (Ohio). Estimates assume a small-scale deployment.

| Component | Service | Rate | Est. Monthly |
|-----------|---------|------|-------------|
| Server | EC2 t3.medium (2 vCPU, 4GB) | $0.0416/hr | ~$30 |
| Storage | EBS gp3 50GB | $0.08/GB-month | ~$4 |
| Backups | AWS Backup (daily, 60-day retention) | $0.05/GB-month | ~$2 |
| Outbound email | SES | $0.10/1,000 emails | ~$1 |
| **Total** | | | **~$37/month** |

Notes:
- pretix does not publish official ARM64 images, so EC2 must be x86 (t3 not t4g)
- PostgreSQL and Redis run in Docker on the same instance — no RDS or Elasticache needed at this scale
- Caddy runs as a sidecar container for SSL termination (Let's Encrypt)
- AWS Backup estimate assumes ~20GB used data and ~200MB daily change rate
