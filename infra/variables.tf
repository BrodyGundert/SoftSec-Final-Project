variable "image_name" {
  description = "Tag for the permission-manager image Terraform builds."
  type        = string
  default     = "permctl:tf"
}

variable "container_name" {
  description = "Name of the demo container Terraform creates."
  type        = string
  default     = "permctl-demo"
}
