locals {
  project_name = "od-auth-refresh"
}

resource "aws_lambda_function" "authorizer" {
  function_name    = "${local.project_name}-authorizer"
  role             = aws_iam_role.authorizer.arn
  filename         = data.archive_file.authorizer.output_path
  source_code_hash = data.archive_file.authorizer.output_base64sha256
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  environment {
    variables = {
      "CLIENT_SECRET_ARN"               = aws_secretsmanager_secret.client_secret.arn
      "AUTHORIZATION_STATES_TABLE_NAME" = aws_dynamodb_table.authorization_states.name
      "TOKENS_TABLE_NAME"               = aws_dynamodb_table.tokens.name
    }
  }
}

data "archive_file" "authorizer" {
  type        = "zip"
  output_path = "${path.module}/authorizer.zip"
  source {
    filename = "lambda_function.py"
    content  = file("${path.module}/../lambda/authorizer/lambda_function.py")
  }
}

resource "aws_iam_role" "authorizer" {
  name               = "${local.project_name}-authorizer"
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy_for_lambda.json
}

data "aws_iam_policy_document" "assume_role_policy_for_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "authorizer_AWSLambdaBasicExecutionRole" {
  role       = aws_iam_role.authorizer.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "authorizer_authorizer" {
  role   = aws_iam_role.authorizer.name
  name   = "authorizer"
  policy = data.aws_iam_policy_document.authorizer.json
}

data "aws_iam_policy_document" "authorizer" {
  statement {
    sid = "AccessUserCredentialStore"
    actions = [
      "dynamodb:BatchGetItem",
      "dynamodb:BetchWriteItem",
      "dynamodb:GetItem",
      "dynamodb:DeleteItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:Scan",
      "dynamodb:Query",
      "dynamodb:PartiQLDelete",
      "dynamodb:PartiQLInsert",
      "dynamodb:PartiQLSelect",
      "dynamodb:PartiQLUpdate",
    ]
    resources = [
      aws_dynamodb_table.tokens.arn,
      aws_dynamodb_table.authorization_states.arn,
    ]
  }
  statement {
    sid = "AccessClientSecret"
    actions = [
      "secretsmanager:GetSecretValue",
    ]
    resources = [
      aws_secretsmanager_secret.client_secret.arn,
    ]
  }
}

resource "aws_lambda_function_url" "authorizer" {
  function_name      = aws_lambda_function.authorizer.function_name
  authorization_type = "NONE"
}

resource "aws_dynamodb_table" "tokens" {
  name         = "${local.project_name}-tokens"
  billing_mode = "PAY_PER_REQUEST"
  attribute {
    name = "ID"
    type = "S"
  }
  hash_key = "ID"
}

resource "aws_dynamodb_table" "authorization_states" {
  name         = "${local.project_name}-authorization-states"
  billing_mode = "PAY_PER_REQUEST"
  attribute {
    name = "SessionID"
    type = "S"
  }
  hash_key = "SessionID"
  ttl {
    enabled        = true
    attribute_name = "Expiration"
  }
}

resource "random_uuid" "client_secret_store" {}

resource "aws_secretsmanager_secret" "client_secret" {
  name                    = "${local.project_name}-client-secret-${random_uuid.client_secret_store.result}"
  recovery_window_in_days = 7
}
