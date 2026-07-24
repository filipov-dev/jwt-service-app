# AWS ALB / API Gateway — уровень 2 (proxy-secret)

У ALB нет встроенной перезаписи заголовков, поэтому секрет инжектится там, где
это возможно, и клиентская версия ОБЯЗАТЕЛЬНО отбрасывается.

## Вариант A — Application Load Balancer + правило листенера
ALB умеет фиксированные заголовки ограниченно; на практике секрет ставят на
уровне цели (target) или через фронтящий Lambda@Edge/CloudFront. Минимум:
- Включите на ALB отбрасывание клиентского заголовка нельзя напрямую — поэтому
  **не полагайтесь только на ALB**; ставьте секрет и чистку на CloudFront (см.
  `cloudflare.md`-аналог) или в API Gateway ниже.

## Вариант B — API Gateway (HTTP API) + parameter mapping
Parameter mapping для интеграции:

```
# (1) Удаляем клиентскую версию (overwrite пустым эквивалент удалению на бэкенд).
overwrite:header.X-Proxy-Secret = ${stageVariables.ProxySecret}
```

Где `ProxySecret` — stage variable, значение которой берётся из AWS Secrets
Manager / SSM Parameter Store при деплое (через CloudFormation/Terraform),
а НЕ хранится в открытом виде.

`overwrite:header.*` заменяет значение целиком, поэтому клиентская версия
заголовка гарантированно затирается секретом. Никогда не используйте
`append:header.X-Proxy-Secret` — это оставит клиентское значение.

## Вариант C — REST API + Integration Request
В маппинге интеграции задайте
`integration.request.header.X-Proxy-Secret = stageVariables.ProxySecret`.
Значение из stage variable перезаписывает любой клиентский заголовок.
