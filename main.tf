<<<<<<< HEAD
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "=3.42.0"
    }
  }
}

provider "aws" {
  region  = var.region
}

resource "aws_vpc" "hashicat" {
  cidr_block           = var.address_space
  enable_dns_hostnames = true

  tags = {
    name = "${var.prefix}-vpc-${var.region}"
    environment = "Production"
  }
}

resource "aws_subnet" "hashicat" {
  vpc_id     = aws_vpc.hashicat.id
  cidr_block = var.subnet_prefix

  tags = {
    name = "${var.prefix}-subnet"
  }
}

resource "aws_security_group" "hashicat" {
  name = "${var.prefix}-security-group"

  vpc_id = aws_vpc.hashicat.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
    prefix_list_ids = []
  }

  tags = {
    Name = "${var.prefix}-security-group"
  }
}

resource "aws_internet_gateway" "hashicat" {
  vpc_id = aws_vpc.hashicat.id

  tags = {
    Name = "${var.prefix}-internet-gateway"
  }
}

resource "aws_route_table" "hashicat" {
  vpc_id = aws_vpc.hashicat.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.hashicat.id
  }
}

resource "aws_route_table_association" "hashicat" {
  subnet_id      = aws_subnet.hashicat.id
  route_table_id = aws_route_table.hashicat.id
}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name = "name"
    #values = ["ubuntu/images/hvm-ssd/ubuntu-disco-19.04-amd64-server-*"]
    values = ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_eip" "hashicat" {
  instance = aws_instance.hashicat.id
  vpc      = true
}

resource "aws_eip_association" "hashicat" {
  instance_id   = aws_instance.hashicat.id
  allocation_id = aws_eip.hashicat.id
}

resource "aws_instance" "hashicat" {
  department                  = devops
  billable                    = true
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.hashicat.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.hashicat.id
  vpc_security_group_ids      = [aws_security_group.hashicat.id]

  tags = {
    Name = "${var.prefix}-hashicat-instance"
  }
}



# We're using a little trick here so we can run the provisioner without
# destroying the VM. Do not do this in production.

# If you need ongoing management (Day N) of your virtual machines a tool such
# as Chef or Puppet is a better choice. These tools track the state of
# individual files and can keep them in the correct configuration.

# Here we do the following steps:
# Sync everything in files/ to the remote VM.
# Set up some environment variables for our script.
# Add execute permissions to our scripts.
# Run the deploy_app.sh script.
resource "null_resource" "configure-cat-app" {
  depends_on = [aws_eip_association.hashicat]

  triggers = {
    build_number = timestamp()
  }

  provisioner "file" {
    source      = "files/"
    destination = "/home/ubuntu/"

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = tls_private_key.hashicat.private_key_pem
      host        = aws_eip.hashicat.public_ip
    }
  }

  provisioner "remote-exec" {
    inline = [
      "sudo apt -y update",
      "sleep 15",
      "sudo apt -y update",
      "sudo apt -y install apache2",
      "sudo systemctl start apache2",
      "sudo chown -R ubuntu:ubuntu /var/www/html",
      "chmod +x *.sh",
      "PLACEHOLDER=${var.placeholder} WIDTH=${var.width} HEIGHT=${var.height} PREFIX=${var.prefix} ./deploy_app.sh",
      "sudo apt -y install cowsay",
      "cowsay Mooooooooooo!",
    ]

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = tls_private_key.hashicat.private_key_pem
      host        = aws_eip.hashicat.public_ip
=======
locals {
  attach_policy = var.attach_require_latest_tls_policy || var.attach_elb_log_delivery_policy || var.attach_lb_log_delivery_policy || var.attach_deny_insecure_transport_policy || var.attach_policy
}

resource "aws_s3_bucket" "this" {
  count = var.create_bucket ? 1 : 0

  bucket        = var.bucket
  bucket_prefix = var.bucket_prefix

  # hack when `null` value can't be used (eg, from terragrunt, https://github.com/gruntwork-io/terragrunt/pull/1367)
  acl = var.acl != "null" ? var.acl : null

  tags                = var.tags
  force_destroy       = var.force_destroy
  acceleration_status = var.acceleration_status
  request_payer       = var.request_payer

  dynamic "website" {
    for_each = length(keys(var.website)) == 0 ? [] : [var.website]

    content {
      index_document           = lookup(website.value, "index_document", null)
      error_document           = lookup(website.value, "error_document", null)
      redirect_all_requests_to = lookup(website.value, "redirect_all_requests_to", null)
      routing_rules            = lookup(website.value, "routing_rules", null)
    }
  }

  dynamic "cors_rule" {
    for_each = try(jsondecode(var.cors_rule), var.cors_rule)

    content {
      allowed_methods = cors_rule.value.allowed_methods
      allowed_origins = cors_rule.value.allowed_origins
      allowed_headers = lookup(cors_rule.value, "allowed_headers", null)
      expose_headers  = lookup(cors_rule.value, "expose_headers", null)
      max_age_seconds = lookup(cors_rule.value, "max_age_seconds", null)
    }
  }

  dynamic "versioning" {
    for_each = length(keys(var.versioning)) == 0 ? [] : [var.versioning]

    content {
      enabled    = lookup(versioning.value, "enabled", null)
      mfa_delete = lookup(versioning.value, "mfa_delete", null)
    }
  }

  dynamic "logging" {
    for_each = length(keys(var.logging)) == 0 ? [] : [var.logging]

    content {
      target_bucket = logging.value.target_bucket
      target_prefix = lookup(logging.value, "target_prefix", null)
    }
  }

  dynamic "grant" {
    for_each = try(jsondecode(var.grant), var.grant)

    content {
      id          = lookup(grant.value, "id", null)
      type        = grant.value.type
      permissions = grant.value.permissions
      uri         = lookup(grant.value, "uri", null)
    }
  }

  dynamic "lifecycle_rule" {
    for_each = try(jsondecode(var.lifecycle_rule), var.lifecycle_rule)

    content {
      id                                     = lookup(lifecycle_rule.value, "id", null)
      prefix                                 = lookup(lifecycle_rule.value, "prefix", null)
      tags                                   = lookup(lifecycle_rule.value, "tags", null)
      abort_incomplete_multipart_upload_days = lookup(lifecycle_rule.value, "abort_incomplete_multipart_upload_days", null)
      enabled                                = lifecycle_rule.value.enabled

      # Max 1 block - expiration
      dynamic "expiration" {
        for_each = length(keys(lookup(lifecycle_rule.value, "expiration", {}))) == 0 ? [] : [lookup(lifecycle_rule.value, "expiration", {})]

        content {
          date                         = lookup(expiration.value, "date", null)
          days                         = lookup(expiration.value, "days", null)
          expired_object_delete_marker = lookup(expiration.value, "expired_object_delete_marker", null)
        }
      }

      # Several blocks - transition
      dynamic "transition" {
        for_each = lookup(lifecycle_rule.value, "transition", [])

        content {
          date          = lookup(transition.value, "date", null)
          days          = lookup(transition.value, "days", null)
          storage_class = transition.value.storage_class
        }
      }

      # Max 1 block - noncurrent_version_expiration
      dynamic "noncurrent_version_expiration" {
        for_each = length(keys(lookup(lifecycle_rule.value, "noncurrent_version_expiration", {}))) == 0 ? [] : [lookup(lifecycle_rule.value, "noncurrent_version_expiration", {})]

        content {
          days = lookup(noncurrent_version_expiration.value, "days", null)
        }
      }

      # Several blocks - noncurrent_version_transition
      dynamic "noncurrent_version_transition" {
        for_each = lookup(lifecycle_rule.value, "noncurrent_version_transition", [])

        content {
          days          = lookup(noncurrent_version_transition.value, "days", null)
          storage_class = noncurrent_version_transition.value.storage_class
        }
      }
    }
  }

  # Max 1 block - replication_configuration
  dynamic "replication_configuration" {
    for_each = length(keys(var.replication_configuration)) == 0 ? [] : [var.replication_configuration]

    content {
      role = replication_configuration.value.role

      dynamic "rules" {
        for_each = replication_configuration.value.rules

        content {
          id                               = lookup(rules.value, "id", null)
          priority                         = lookup(rules.value, "priority", null)
          prefix                           = lookup(rules.value, "prefix", null)
          delete_marker_replication_status = lookup(rules.value, "delete_marker_replication_status", null)
          status                           = rules.value.status

          dynamic "destination" {
            for_each = length(keys(lookup(rules.value, "destination", {}))) == 0 ? [] : [lookup(rules.value, "destination", {})]

            content {
              bucket             = destination.value.bucket
              storage_class      = lookup(destination.value, "storage_class", null)
              replica_kms_key_id = lookup(destination.value, "replica_kms_key_id", null)
              account_id         = lookup(destination.value, "account_id", null)

              dynamic "access_control_translation" {
                for_each = length(keys(lookup(destination.value, "access_control_translation", {}))) == 0 ? [] : [lookup(destination.value, "access_control_translation", {})]

                content {
                  owner = access_control_translation.value.owner
                }
              }

              dynamic "replication_time" {
                for_each = length(keys(lookup(destination.value, "replication_time", {}))) == 0 ? [] : [lookup(destination.value, "replication_time", {})]

                content {
                  status  = replication_time.value.status
                  minutes = replication_time.value.minutes
                }
              }

              dynamic "metrics" {
                for_each = length(keys(lookup(destination.value, "metrics", {}))) == 0 ? [] : [lookup(destination.value, "metrics", {})]

                content {
                  status  = metrics.value.status
                  minutes = metrics.value.minutes
                }
              }
            }
          }

          dynamic "source_selection_criteria" {
            for_each = length(keys(lookup(rules.value, "source_selection_criteria", {}))) == 0 ? [] : [lookup(rules.value, "source_selection_criteria", {})]

            content {

              dynamic "sse_kms_encrypted_objects" {
                for_each = length(keys(lookup(source_selection_criteria.value, "sse_kms_encrypted_objects", {}))) == 0 ? [] : [lookup(source_selection_criteria.value, "sse_kms_encrypted_objects", {})]

                content {

                  enabled = sse_kms_encrypted_objects.value.enabled
                }
              }
            }
          }

          # Send empty map if `filter` is an empty map or absent entirely
          dynamic "filter" {
            for_each = length(keys(lookup(rules.value, "filter", {}))) == 0 ? [{}] : []

            content {}
          }

          # Send `filter` if it is present and has at least one field
          dynamic "filter" {
            for_each = length(keys(lookup(rules.value, "filter", {}))) != 0 ? [lookup(rules.value, "filter", {})] : []

            content {
              prefix = lookup(filter.value, "prefix", null)
              tags   = lookup(filter.value, "tags", null)
            }
          }

        }
      }
    }
  }

  # Max 1 block - server_side_encryption_configuration
  dynamic "server_side_encryption_configuration" {
    for_each = length(keys(var.server_side_encryption_configuration)) == 0 ? [] : [var.server_side_encryption_configuration]

    content {

      dynamic "rule" {
        for_each = length(keys(lookup(server_side_encryption_configuration.value, "rule", {}))) == 0 ? [] : [lookup(server_side_encryption_configuration.value, "rule", {})]

        content {
          bucket_key_enabled = lookup(rule.value, "bucket_key_enabled", null)

          dynamic "apply_server_side_encryption_by_default" {
            for_each = length(keys(lookup(rule.value, "apply_server_side_encryption_by_default", {}))) == 0 ? [] : [
            lookup(rule.value, "apply_server_side_encryption_by_default", {})]

            content {
              sse_algorithm     = apply_server_side_encryption_by_default.value.sse_algorithm
              kms_master_key_id = lookup(apply_server_side_encryption_by_default.value, "kms_master_key_id", null)
            }
          }
        }
      }
    }
  }

  # Max 1 block - object_lock_configuration
  dynamic "object_lock_configuration" {
    for_each = length(keys(var.object_lock_configuration)) == 0 ? [] : [var.object_lock_configuration]

    content {
      object_lock_enabled = object_lock_configuration.value.object_lock_enabled

      dynamic "rule" {
        for_each = length(keys(lookup(object_lock_configuration.value, "rule", {}))) == 0 ? [] : [lookup(object_lock_configuration.value, "rule", {})]

        content {
          default_retention {
            mode  = lookup(lookup(rule.value, "default_retention", {}), "mode")
            days  = lookup(lookup(rule.value, "default_retention", {}), "days", null)
            years = lookup(lookup(rule.value, "default_retention", {}), "years", null)
          }
        }
      }
    }
  }

}

resource "aws_s3_bucket_policy" "this" {
  count = var.create_bucket && local.attach_policy ? 1 : 0

  bucket = aws_s3_bucket.this[0].id
  policy = data.aws_iam_policy_document.combined[0].json
}

data "aws_iam_policy_document" "combined" {
  count = var.create_bucket && local.attach_policy ? 1 : 0

  source_policy_documents = compact([
    var.attach_elb_log_delivery_policy ? data.aws_iam_policy_document.elb_log_delivery[0].json : "",
    var.attach_lb_log_delivery_policy ? data.aws_iam_policy_document.lb_log_delivery[0].json : "",
    var.attach_require_latest_tls_policy ? data.aws_iam_policy_document.require_latest_tls[0].json : "",
    var.attach_deny_insecure_transport_policy ? data.aws_iam_policy_document.deny_insecure_transport[0].json : "",
    var.attach_policy ? var.policy : ""
  ])
}

# AWS Load Balancer access log delivery policy
data "aws_elb_service_account" "this" {
  count = var.create_bucket && var.attach_elb_log_delivery_policy ? 1 : 0
}

data "aws_iam_policy_document" "elb_log_delivery" {
  count = var.create_bucket && var.attach_elb_log_delivery_policy ? 1 : 0

  statement {
    sid = ""

    principals {
      type        = "AWS"
      identifiers = data.aws_elb_service_account.this.*.arn
    }

    effect = "Allow"

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "${aws_s3_bucket.this[0].arn}/*",
    ]
  }
}

# ALB/NLB

data "aws_iam_policy_document" "lb_log_delivery" {
  count = var.create_bucket && var.attach_lb_log_delivery_policy ? 1 : 0

  statement {
    sid = "AWSLogDeliveryWrite"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    effect = "Allow"

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "${aws_s3_bucket.this[0].arn}/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid = "AWSLogDeliveryAclCheck"

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
    ]

    resources = [
      aws_s3_bucket.this[0].arn,
    ]

  }
}

data "aws_iam_policy_document" "deny_insecure_transport" {
  count = var.create_bucket && var.attach_deny_insecure_transport_policy ? 1 : 0

  statement {
    sid    = "denyInsecureTransport"
    effect = "Deny"

    actions = [
      "s3:*",
    ]

    resources = [
      aws_s3_bucket.this[0].arn,
      "${aws_s3_bucket.this[0].arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values = [
        "false"
      ]
>>>>>>> e732c9cd947d6f01c28b97262d4309585827be05
    }
  }
}

<<<<<<< HEAD
resource "tls_private_key" "hashicat" {
  algorithm = "RSA"
}

locals {
  private_key_filename = "${var.prefix}-ssh-key.pem"
}

resource "aws_key_pair" "hashicat" {
  key_name   = local.private_key_filename
  public_key = tls_private_key.hashicat.public_key_openssh
=======
data "aws_iam_policy_document" "require_latest_tls" {
  count = var.create_bucket && var.attach_require_latest_tls_policy ? 1 : 0

  statement {
    sid    = "denyOutdatedTLS"
    effect = "Deny"

    actions = [
      "s3:*",
    ]

    resources = [
      aws_s3_bucket.this[0].arn,
      "${aws_s3_bucket.this[0].arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values = [
        "1.2"
      ]
    }
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  count = var.create_bucket && var.attach_public_policy ? 1 : 0

  # Chain resources (s3_bucket -> s3_bucket_policy -> s3_bucket_public_access_block)
  # to prevent "A conflicting conditional operation is currently in progress against this resource."
  # Ref: https://github.com/hashicorp/terraform-provider-aws/issues/7628

  bucket = local.attach_policy ? aws_s3_bucket_policy.this[0].id : aws_s3_bucket.this[0].id

  block_public_acls       = var.block_public_acls
  block_public_policy     = var.block_public_policy
  ignore_public_acls      = var.ignore_public_acls
  restrict_public_buckets = var.restrict_public_buckets
}

resource "aws_s3_bucket_ownership_controls" "this" {
  count = var.create_bucket && var.control_object_ownership ? 1 : 0

  bucket = local.attach_policy ? aws_s3_bucket_policy.this[0].id : aws_s3_bucket.this[0].id

  rule {
    object_ownership = var.object_ownership
  }

  # This `depends_on` is to prevent "A conflicting conditional operation is currently in progress against this resource."
  depends_on = [
    aws_s3_bucket_policy.this,
    aws_s3_bucket_public_access_block.this,
    aws_s3_bucket.this
  ]
>>>>>>> e732c9cd947d6f01c28b97262d4309585827be05
}
