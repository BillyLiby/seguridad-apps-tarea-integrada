# VERSION CORREGIDA. No se aprovisiona nada: solo analisis estatico.
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "vpc_id" {
  type    = string
  default = "vpc-0123456789abcdef0"
}

resource "aws_security_group" "api" {
  name        = "notas-api-sg"
  description = "Grupo de seguridad de la API de notas (laboratorio)"
  vpc_id      = var.vpc_id

  # Solo el puerto de la API y solo desde la red interna; sin SSH publico
  ingress {
    description = "API de notas desde la red interna"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Salida limitada a HTTPS
  egress {
    description = "HTTPS saliente"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
