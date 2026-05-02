variable "name_prefix" { type = string }
variable "vpc_cidr" { type = string }
variable "availability_zones" { type = list(string) }
variable "public_subnets_cidr" { type = list(string) }
variable "private_subnets_cidr" { type = list(string) }
variable "db_subnets_cidr" { type = list(string) }
