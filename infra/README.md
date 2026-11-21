# infra/ - Terraform (Infrastructure as Code)

Terraform controls Docker for this project: it builds the image from the
repository `Dockerfile` and creates a container from it. Defining this as
code makes the build predictable and reviewable (the security point of IaC),
instead of relying on manual docker commands.

## Prerequisites
- Terraform >= 1.3
- Docker running locally (Docker Desktop on Windows/Mac, dockerd on Linux)

## Use
```sh
cd infra
terraform init       # download the Docker provider
terraform fmt -check  # formatting
terraform validate    # configuration is valid
terraform plan        # preview
terraform apply       # build the image and create the demo container
terraform destroy     # tear it down
```

## What it manages
- `docker_image.permctl`        - builds the hardened image from the Dockerfile.
- `docker_container.permctl_demo` - creates a container that runs the demo.
