terraform {
  required_version = "~> 1.11.0"
  required_providers {
    archive = {
      source  = "registry.terraform.io/hashicorp/archive"
      version = "~> 2.0"
    }
    aws = {
      source  = "registry.terraform.io/hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "registry.terraform.io/hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = "ap-northeast-1"
  default_tags {
    tags = {
      Purpose = "OneDriveAuthRefreshServerless"
    }
  }
}
