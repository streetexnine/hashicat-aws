module "s3-bucket" {
  source  = "app.terraform.io/ivatama-david/s3-bucket/aws"
  version = "2.8.0"
  # insert required variables here
  variable "bucket_prefix" {
      type        = string
      description = "(required since we are not using 'bucket') Creates a unique bucket name beginning with the specified prefix"
      default     = "dmatius8"
  }
}
