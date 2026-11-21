output "image_id" {
  description = "ID of the image Terraform built."
  value       = docker_image.permctl.image_id
}

output "image_name" {
  description = "Tag of the image Terraform built."
  value       = docker_image.permctl.name
}

output "container_name" {
  description = "Name of the demo container Terraform created."
  value       = docker_container.permctl_demo.name
}
