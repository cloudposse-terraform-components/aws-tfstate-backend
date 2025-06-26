terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "< 7.0.0"
    }
    awsutils = {
      source  = "cloudposse/awsutils"
      version = ">= 0.16.0, < 6.0.0"
    }
  }
}
