terraform {
  backend "remote" {
    hostname = "app.terraform.io"
    organization = "ivatama-david"
    workspaces {
      name = "hashicat-aws"
    }
  }
}
