# Stagy web UI container (roadmap 9.1): build the Vite bundle, then serve the
# static output from nginx. Two stages so node never ships to production.
FROM node:22-slim AS build
WORKDIR /app

# npm ci off the lockfile alone, so dependency install caches independently of
# source changes.
COPY web/frontend/package.json web/frontend/package-lock.json ./
RUN npm ci

COPY web/frontend/ ./
RUN npm run build

FROM nginx:alpine
COPY web/frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
