resource "aws_security_group" "kafka" {
  name        = "${var.name_prefix}-kafka"
  description = "Allow Kafka access from approved security groups"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-kafka"
  }
}

resource "aws_security_group_rule" "kafka_ingress" {
  for_each = {
    for pair in setproduct(var.allowed_security_groups, [9092, 9094, 9098, 2181]) :
    "${pair[0]}-${pair[1]}" => {
      sg   = pair[0]
      port = pair[1]
    }
  }

  type                     = "ingress"
  from_port                = each.value.port
  to_port                  = each.value.port
  protocol                 = "tcp"
  security_group_id        = aws_security_group.kafka.id
  source_security_group_id = each.value.sg
}

resource "aws_cloudwatch_log_group" "kafka" {
  name              = "/aws/msk/${var.name_prefix}"
  retention_in_days = 30

  tags = {
    Name = "${var.name_prefix}-kafka"
  }
}

resource "aws_msk_cluster" "main" {
  cluster_name           = "${var.name_prefix}-kafka"
  kafka_version          = var.kafka_version
  number_of_broker_nodes = var.broker_count

  broker_node_group_info {
    instance_type   = var.instance_type
    client_subnets  = var.subnet_ids
    security_groups = [aws_security_group.kafka.id]

    storage_info {
      ebs_storage_info {
        volume_size = var.ebs_volume_size
      }
    }
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.kafka.name
      }
    }
  }

  tags = {
    Name = "${var.name_prefix}-kafka"
  }
}

output "bootstrap_brokers" {
  description = "TLS bootstrap broker connection string"
  value       = aws_msk_cluster.main.bootstrap_brokers_tls
  sensitive   = true
}

output "security_group_id" {
  description = "Security group attached to the Kafka brokers"
  value       = aws_security_group.kafka.id
}
