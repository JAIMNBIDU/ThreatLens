# ── Stage 1: build the Vite app ───────────────────────────────────────────────
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci || npm install
COPY . .
# Build-time API base: same-origin /api, proxied by nginx to the backend.
ENV VITE_API_BASE=/api
RUN npm run build

# ── Stage 2: serve static files with nginx (tiny, no Node at runtime) ─────────
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
