# DockFlare: Automates Cloudflare Tunnel ingress from Docker labels.
# Copyright (C) 2025 ChrispyBacon-Dev <https://github.com/ChrispyBacon-dev/DockFlare>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# dockflare/Dockerfile
FROM node:20-alpine AS frontend-builder
LABEL stage=frontend-builder
WORKDIR /usr/src/app
COPY package.json package-lock.json* ./
RUN npm install
COPY tailwind.config.js postcss.config.js ./
COPY ./app ./app
RUN echo "DEBUG: Contents of /usr/src/app after COPY ./app ./app:" && ls -Alp /usr/src/app
RUN echo "DEBUG: Contents of /usr/src/app/app after COPY ./app ./app:" && ls -Alp /usr/src/app/app
RUN echo "DEBUG: Details of /usr/src/app/app/static after COPY ./app ./app (if it exists):" && ls -ld /usr/src/app/app/static || echo "/usr/src/app/app/static does not exist yet"
RUN mkdir -p ./app/static/css
RUN echo "DEBUG: Details of /usr/src/app/app/static AFTER mkdir -p:" && ls -ld /usr/src/app/app/static
RUN echo "DEBUG: Contents of /usr/src/app/app/static AFTER mkdir -p:" && ls -Alp /usr/src/app/app/static
RUN npm run build:css || (echo "npm run build:css FAILED"; exit 1)
RUN echo "DEBUG: Details of /usr/src/app/app/static AFTER npm run build:css:" && ls -ld /usr/src/app/app/static || echo "/usr/src/app/app/static NOT FOUND after build"
RUN echo "DEBUG: Contents of /usr/src/app/app/static AFTER npm run build:css:" && ls -Alp /usr/src/app/app/static || echo "/usr/src/app/app/static NOT FOUND after build"
RUN echo "DEBUG: Specifically checking for /usr/src/app/app/static/css/output.css AFTER npm run build:css:"
RUN ls -l /usr/src/app/app/static/css/output.css || echo "/usr/src/app/app/static/css/output.css NOT FOUND after build"
FROM python:3.13-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /app
ENV CLOUDFLARED_VERSION="2024.1.5"
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        CLOUDFLARED_ARCH="linux-amd64"; \
    elif [ "$ARCH" = "arm64" ]; then \
        CLOUDFLARED_ARCH="linux-arm64"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    wget -q "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-${CLOUDFLARED_ARCH}.deb" && \
    dpkg -i "cloudflared-${CLOUDFLARED_ARCH}.deb" && \
    rm "cloudflared-${CLOUDFLARED_ARCH}.deb" && \
    cloudflared --version && \
    mkdir -p /root/.cloudflared

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --from=frontend-builder /usr/src/app/app/static/css/output.css /app/static/css/output.css
COPY ./app /app
ENV PYTHONPATH=/
EXPOSE 5000
CMD ["python", "main.py"]