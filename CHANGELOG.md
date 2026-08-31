# Changelog

All notable changes to `l4s3r-authnz` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-08-31

### Security
- **OAuth Target Origin Validation**: Enforced strict allowlist validation (`ALLOWED_FRONTEND_ORIGINS`) on client-supplied OAuth login and callback target URLs, Origin headers, and Referer headers to prevent unauthorized open redirects and token leakage.

### Added
- **Microsoft Entra ID OAuth Provider**: Added native support for Microsoft Entra ID (Azure AD) OAuth 2.0 / OpenID Connect authentication using Microsoft identity platform v2.0 endpoints (`login.microsoftonline.com`) and Microsoft Graph API (`graph.microsoft.com/v1.0/me`).
- **Environment Configuration**: Introduced `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `MICROSOFT_TENANT_ID` (defaulting to `"common"`), `MICROSOFT_REDIRECT_URI`, and `ALLOWED_FRONTEND_ORIGINS`.
