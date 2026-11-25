# VERSION INSEGURA DE LABORATORIO (solo para demostrar el hallazgo de Checkov). No se aprovisiona nada.
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_security_group" "api" {
  name   = "notas-api-sg"
  vpc_id = "vpc-0123456789abcdef0"

  # INSEGURO: SSH abierto a todo Internet y sin descripcion
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # INSEGURO: salida sin restriccion a todos los puertos
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
