# ---------------------------------------------------------------------------
# Terraform (Infrastructure as Code) for the CISE 330 permission manager.
#
# Terraform CONTROLS Docker here, it does not replace it: it builds the
# project's Docker image from the repository Dockerfile and creates a
# container from that image. Defining the infrastructure as code makes the
# build predictable and reviewable, which is the security point: the same
# image and container come out of `terraform apply` every time, with no
# manual, unlogged docker commands.
#
# It uses the Docker provider against the local Docker daemon, so it needs
# no cloud account or credentials.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.3.0"

  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

# Talk to the local Docker daemon (Docker Desktop on Windows/Mac, dockerd on
# Linux, or the Docker-in-Docker service in GitLab CI via DOCKER_HOST).
provider "docker" {}

# REQUIREMENT: Terraform must build the Docker image.
# Builds the hardened image from the repository Dockerfile one level up.
resource "docker_image" "permctl" {
  name = var.image_name

  build {
    context    = "${path.module}/.."
    dockerfile = "Dockerfile"
    tag        = [var.image_name]
  }
}

# REQUIREMENT: Terraform must create the Docker container.
# permctl is a short-lived CLI: it runs the guided demo and exits, so
# must_run=false lets Terraform create the container without treating the
# clean exit as a failure. rm=false keeps the exited container so Terraform
# can track and later destroy it.
resource "docker_container" "permctl_demo" {
  name     = var.container_name
  image    = docker_image.permctl.image_id
  command  = ["demo"]
  must_run = false
  rm       = false
}
