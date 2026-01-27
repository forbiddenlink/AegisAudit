# Check Catalog (MVP)

## Headers

- **HSTS**: Present, max-age >= 6 months, includeSubDomains.
- **CSP**: Present, no parsing errors.
- **Referrer-Policy**: Present, secure value (e.g., `strict-origin-when-cross-origin`).
- **Permissions-Policy**: Present.
- **X-Content-Type-Options**: `nosniff`.
- **Cross-Origin-Opener-Policy (COOP)**: Present (optional/warn for MVP).
- **Cross-Origin-Embedder-Policy (COEP)**: Present (optional/warn for MVP).
- **Cross-Origin-Resource-Policy (CORP)**: Present (optional/warn for MVP).

## Cookies

- **Secure**: Present if HTTPS.
- **HttpOnly**: Present (context dependent).
- **SameSite**: Present (`Lax` or `Strict`).

## HTTPS Hygiene

- **Redirects**: http:// -> https://.
- **Final URL**: Must be https://.
- **Mixed Content**: No `http://` resources in HTML (img, script, link).
- **Certificate**: Not expired (passive check).

## RFC 9116 (security.txt)

- **Presence**: Check `/.well-known/security.txt`.
- **Validity**: Check `Expires` field is present and in future.
- **Contact**: Check `Contact` field is present.
- **Protocol**: Must be served over HTTPS.

## Supply Chain (SRI)

- **Integrity**: External `<script>` and `<link>` tags must have `integrity` attribute.
- **Cross-Origin**: Usage of `crossorigin="anonymous"` with integrity.

## CSP Quality (Basic/Regex)

- Warning on `unsafe-inline` / `unsafe-eval`.
- Warning on `*` in usage.
- Missing `object-src` or `base-uri`.
- Missing `frame-ancestors` (if no XFO).

## Info Leakage

- **Server Header**: Present (warn).
- **X-Powered-By**: Present (warn).
- **Debug Headers**: Warnings for `X-Asp*` or similar.
