# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

# Stage 2: Production
FROM node:20-alpine

WORKDIR /app

COPY --from=builder /app /app

ENV NODE_ENV=production

EXPOSE 3004

CMD ["node", "server.js"]