variable "name_prefix" { type = string }
variable "callback_urls" { type = list(string) default = [] }
variable "logout_urls"   { type = list(string) default = [] }
variable "region"        { type = string }
variable "tags"          { type = map(string) default = {} }
