# AWS ALB / API Gateway — level 2 (the proxy secret)

An ALB has no built-in header rewriting, so the secret is injected wherever that
is possible and the client-supplied version MUST be dropped.

## Option A — Application Load Balancer plus a listener rule
An ALB supports fixed headers only to a limited degree; in practice the secret is
set at the target level or through a CloudFront/Lambda@Edge front. At a minimum:
- dropping the client-supplied header cannot be enabled on the ALB directly — so
  **do not rely on the ALB alone**; set the secret and do the stripping on
  CloudFront (see the `cloudflare.md` equivalent) or in API Gateway below.

## Option B — API Gateway (HTTP API) plus parameter mapping
The parameter mapping for the integration:

```
# (1) Delete the client-supplied version (an overwrite is equivalent to a delete
#     as far as the backend is concerned).
overwrite:header.X-Proxy-Secret = ${stageVariables.ProxySecret}
```

Here `ProxySecret` is a stage variable whose value comes from AWS Secrets Manager
/ SSM Parameter Store at deploy time (through CloudFormation/Terraform) and is
NOT stored in the clear.

`overwrite:header.*` replaces the value entirely, so the client-supplied version
of the header is guaranteed to be overwritten by the secret. Never use
`append:header.X-Proxy-Secret` — that leaves the client value in place.

## Option C — REST API plus Integration Request
In the integration mapping set
`integration.request.header.X-Proxy-Secret = stageVariables.ProxySecret`.
The value from the stage variable overwrites any client-supplied header.
