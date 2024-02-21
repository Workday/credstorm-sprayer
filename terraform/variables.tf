######################################
# Defining Variables for the Project #
######################################

# Required INPUTS

variable "region" {
  type = string
  description = "The default AWS region for the project"
}

variable "profile" {
  type = string
  description = "Choose the AWS profile you'd like to use. (Leave blank for default)"
}
variable "lambdacount"{
  type = number
  description = "The number of lambda functions to be created"


}
variable "pythonversion" {
  type = string
  description = "The python version used for lambda"
  default = "python3.8"
}

variable "lambdaiamrole" {
  type = string
  description = "Name for the iam role for the lambda function"
  default = "Lambda_Spray_Role"
}

variable "lambdaiampolicy" {
  type = string
  description = "Name for the lambda iam policy"
  default = "Lambda_Spray_Policy"
}

variable "lambdafunction"{
  type = string
  description = "Name for the lambda function"
  default = "Lambda_Spray_Function"
}

