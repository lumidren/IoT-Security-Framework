#------------------------------------------------------------------------------
# IRSA helper
#------------------------------------------------------------------------------

locals {
  service_accounts = {
    alb_controller = { namespace = "kube-system", name = "aws-load-balancer-controller" }
    cert_manager   = { namespace = "cert-manager", name = "cert-manager" }
    external_dns   = { namespace = "external-dns", name = "external-dns" }
  }
}

data "aws_iam_policy_document" "irsa_assume" {
  for_each = local.service_accounts

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:sub"
      values   = ["system:serviceaccount:${each.value.namespace}:${each.value.name}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

#------------------------------------------------------------------------------
# AWS Load Balancer Controller
#------------------------------------------------------------------------------

resource "aws_iam_role" "alb_controller" {
  name               = "${var.name_prefix}-irsa-aws-load-balancer-controller"
  assume_role_policy = data.aws_iam_policy_document.irsa_assume["alb_controller"].json
}

# Upstream policy (docs/install/iam_policy.json of the controller release matching the chart),
# vendored for offline/reproducible applies. Re-diff against upstream when bumping the chart.
resource "aws_iam_policy" "alb_controller" {
  name   = "${var.name_prefix}-aws-load-balancer-controller"
  policy = replace(file("${path.module}/policies/aws-load-balancer-controller.json"), "arn:aws:", "arn:${var.partition}:")
}

resource "aws_iam_role_policy_attachment" "alb_controller" {
  role       = aws_iam_role.alb_controller.name
  policy_arn = aws_iam_policy.alb_controller.arn
}

resource "helm_release" "aws_load_balancer_controller" {
  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  version    = var.chart_versions.aws_load_balancer_controller
  namespace  = "kube-system"

  atomic          = true
  cleanup_on_fail = true
  wait            = true
  timeout         = 600

  values = [yamlencode({
    clusterName  = var.cluster_name
    region       = var.region
    vpcId        = var.vpc_id
    replicaCount = 2
    serviceAccount = {
      create = true
      name   = local.service_accounts.alb_controller.name
      annotations = {
        "eks.amazonaws.com/role-arn" = aws_iam_role.alb_controller.arn
      }
    }
    enableShield = false
    enableWaf    = false
    enableWafv2  = true
    podDisruptionBudget = {
      maxUnavailable = 1
    }
    resources = {
      requests = { cpu = "100m", memory = "128Mi" }
      limits   = { cpu = "500m", memory = "512Mi" }
    }
  })]

  depends_on = [aws_iam_role_policy_attachment.alb_controller]
}

#------------------------------------------------------------------------------
# cert-manager (Route 53 DNS-01 for the public hostnames)
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "cert_manager" {
  statement {
    actions   = ["route53:GetChange"]
    resources = ["arn:${var.partition}:route53:::change/*"]
  }

  statement {
    actions   = ["route53:ChangeResourceRecordSets", "route53:ListResourceRecordSets"]
    resources = ["arn:${var.partition}:route53:::hostedzone/${var.dns_zone_id}"]
  }

  statement {
    actions   = ["route53:ListHostedZonesByName"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "cert_manager" {
  name               = "${var.name_prefix}-irsa-cert-manager"
  assume_role_policy = data.aws_iam_policy_document.irsa_assume["cert_manager"].json
}

resource "aws_iam_role_policy" "cert_manager" {
  name   = "route53-dns01"
  role   = aws_iam_role.cert_manager.id
  policy = data.aws_iam_policy_document.cert_manager.json
}

resource "helm_release" "cert_manager" {
  name             = "cert-manager"
  repository       = "https://charts.jetstack.io"
  chart            = "cert-manager"
  version          = var.chart_versions.cert_manager
  namespace        = local.service_accounts.cert_manager.namespace
  create_namespace = true

  atomic          = true
  cleanup_on_fail = true
  wait            = true
  timeout         = 600

  values = [yamlencode({
    crds = {
      enabled = true
      keep    = true
    }
    replicaCount = 2
    podDisruptionBudget = {
      enabled      = true
      minAvailable = 1
    }
    serviceAccount = {
      create = true
      name   = local.service_accounts.cert_manager.name
      annotations = {
        "eks.amazonaws.com/role-arn" = aws_iam_role.cert_manager.arn
      }
    }
    # Required for IRSA: the projected token must be readable by the non-root controller.
    securityContext = {
      fsGroup = 1001
    }
    extraArgs = [
      "--dns01-recursive-nameservers-only",
      "--dns01-recursive-nameservers=1.1.1.1:53,8.8.8.8:53",
    ]
    prometheus = {
      enabled = true
    }
    resources = {
      requests = { cpu = "50m", memory = "128Mi" }
      limits   = { cpu = "500m", memory = "512Mi" }
    }
  })]

  depends_on = [aws_iam_role_policy.cert_manager]
}

#------------------------------------------------------------------------------
# external-dns
#------------------------------------------------------------------------------

data "aws_iam_policy_document" "external_dns" {
  statement {
    actions   = ["route53:ChangeResourceRecordSets"]
    resources = ["arn:${var.partition}:route53:::hostedzone/${var.dns_zone_id}"]
  }

  statement {
    actions   = ["route53:ListHostedZones", "route53:ListResourceRecordSets", "route53:ListTagsForResource"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "external_dns" {
  name               = "${var.name_prefix}-irsa-external-dns"
  assume_role_policy = data.aws_iam_policy_document.irsa_assume["external_dns"].json
}

resource "aws_iam_role_policy" "external_dns" {
  name   = "route53-records"
  role   = aws_iam_role.external_dns.id
  policy = data.aws_iam_policy_document.external_dns.json
}

resource "helm_release" "external_dns" {
  name             = "external-dns"
  repository       = "https://kubernetes-sigs.github.io/external-dns/"
  chart            = "external-dns"
  version          = var.chart_versions.external_dns
  namespace        = local.service_accounts.external_dns.namespace
  create_namespace = true

  atomic          = true
  cleanup_on_fail = true
  wait            = true
  timeout         = 600

  values = [yamlencode({
    provider = {
      name = "aws"
    }
    serviceAccount = {
      create = true
      name   = local.service_accounts.external_dns.name
      annotations = {
        "eks.amazonaws.com/role-arn" = aws_iam_role.external_dns.arn
      }
    }
    domainFilters = [var.domain_filter]
    zoneIdFilters = [var.dns_zone_id]
    policy        = "upsert-only"
    registry      = "txt"
    txtOwnerId    = var.cluster_name
    sources       = ["service", "ingress"]
    extraArgs     = ["--aws-zone-type=public"]
    env = [
      { name = "AWS_DEFAULT_REGION", value = var.region },
    ]
    resources = {
      requests = { cpu = "25m", memory = "64Mi" }
      limits   = { cpu = "200m", memory = "256Mi" }
    }
  })]

  depends_on = [aws_iam_role_policy.external_dns]
}

#------------------------------------------------------------------------------
# Default encrypted gp3 storage class (the EBS CSI add-on ships none)
#------------------------------------------------------------------------------

resource "kubernetes_storage_class_v1" "gp3_encrypted" {
  metadata {
    name = "gp3-encrypted"

    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }

  storage_provisioner    = "ebs.csi.aws.com"
  reclaim_policy         = "Delete"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true

  parameters = {
    type      = "gp3"
    encrypted = "true"
    fsType    = "ext4"
  }
}
