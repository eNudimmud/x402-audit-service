# ENKI x402 Audit Service — multi-stage build
# NOTE: use Debian (slim, glibc) not alpine: @x402/* deps pull native/crypto
# bindings (Solana web3, tweetnacl) that fail under alpine/musl at npm ci.
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM node:22-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
EXPOSE 4021
ENV PORT=4021
CMD ["node", "dist/server.js"]
