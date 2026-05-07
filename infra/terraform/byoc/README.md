# AiSOC Bring-Your-Own-Cloud (BYOC)

This module provisions a production-ready AiSOC control plane in your own AWS account.

## Quick Start

```bash
terraform init
terraform apply -var="db_password=$(openssl rand -base64 32)"
```

After apply completes you will receive:

- EKS cluster name
- Postgres endpoint + credentials (store securely)
- Redis endpoint

## Next Steps

1. Deploy the AiSOC Helm chart into the EKS cluster using the outputs above.
2. Configure DNS / Ingress for the API and web UI.
3. Set up CI/CD to keep the cluster and application images up to date.

## Security Notes

- All data at rest is encrypted (RDS, EBS, S3).
- EKS control plane and node groups run in private subnets.
- Use AWS Secrets Manager or Parameter Store for long-lived credentials in production.

For full multi-region or air-gapped variants, contact the AiSOC maintainers.
