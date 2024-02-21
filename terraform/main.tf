provider "aws" {

  region  = var.region
  profile = var.profile
}

resource "aws_iam_role" "lambda_role" {
name = var.lambdaiamrole
assume_role_policy = <<EOF
{
 "Version": "2012-10-17",
 "Statement": [
   {
     "Action": "sts:AssumeRole",
     "Principal": {
       "Service": "lambda.amazonaws.com"
     },
     "Effect": "Allow",
     "Sid": ""
   }
 ]
}
EOF
}
resource "aws_iam_policy" "iam_policy_for_lambda" {

 name         = var.lambdaiampolicy
 path         = "/"
 description  = "AWS IAM Policy for managing aws lambda role"
 policy = <<EOF
{
 "Version": "2012-10-17",
 "Statement": [
   {
     "Action": [
       "logs:CreateLogGroup",
       "logs:CreateLogStream",
       "logs:PutLogEvents",
       "lambda:InvokeFunction",
       "lambda:UpdateFunctionConfiguration",
       "lambda:InvokeAsync",
       "lambda:GetFunctionConfiguration"
     ],
     "Resource": "*",
     "Effect": "Allow"
   }
 ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "attach_iam_policy_to_iam_role" {
 role        = aws_iam_role.lambda_role.name
 policy_arn  = aws_iam_policy.iam_policy_for_lambda.arn
}

data "archive_file" "zip_the_python_code" {
type        = "zip"
source_dir  = "${path.module}/lambda/"
output_path = "${path.module}/lambda/sprayer.zip"
}

resource "aws_lambda_function" "terraform_lambda_func" {
count                          = var.lambdacount
filename                       = "${path.module}/lambda/sprayer.zip"
function_name                  =  "${var.lambdafunction}-${count.index + 1}"
role                           = aws_iam_role.lambda_role.arn
handler                        = "index.lambda_handler"
runtime                        = var.pythonversion
timeout                        = 10
depends_on                     = [aws_iam_role_policy_attachment.attach_iam_policy_to_iam_role]
}