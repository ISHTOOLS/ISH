# syntax=docker/dockerfile:1
# ---- Stage 1: PQC bridge derleme (liboqs + gcc) ----
FROM ubuntu:24.04 AS pqc-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build gcc libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY c_pqc/ ./c_pqc/
RUN cd c_pqc && ./build.sh

# ---- Stage 2: Calisma zamani ----
FROM node:20-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 opensc openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .
# gercek derlenmis liboqs+PQC koprusunu builder asamasindan al
COPY --from=pqc-builder /build/c_pqc/ishv4_pqc_bridge ./c_pqc/ishv4_pqc_bridge
COPY --from=pqc-builder /build/c_pqc/liboqs-install ./c_pqc/liboqs-install

RUN mkdir -p data && useradd -m -u 1001 ishv4 && chown -R ishv4:ishv4 /app
USER ishv4

ENV NODE_ENV=production
EXPOSE 4000
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:4000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
