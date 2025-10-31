# Terraform_AI_Validator #

## 📘 Overview
**Terraform_Baseline** provides a modular, reusable baseline for deploying infrastructure using Terraform.  
It supports a standard folder hierarchy for environment isolation (e.g., `dev`, `prod`), modular organization (e.g., `networking`, `iam`, `compute`, `storage`), and integrates seamlessly with **GitLab CI/CD pipelines** for automated provisioning, validation, and version control.

---

## 🧱 Project Structure

```bash
Terraform_AI_validator/
├── .gitignore
├── .gitlab-ci.yml                 # (rename)
├── README.md
├── versions.tf                    # (add)
├── provider.tf
├── locals.tf                      # (add)
├── variables.tf
├── terraform.tfvars               # (rename)
├── main.tf
├── outputs.tf
└── modules/
    ├── api_gateway/
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── bedrock/
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── cloudfront/
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── iam/
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── lambda/
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    └── s3/
        ├── main.tf
        ├── variables.tf
        └── outputs.tf
```
