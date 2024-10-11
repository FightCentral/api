FROM node:20-alpine AS builder

WORKDIR /build

COPY package*.json ./

RUN npm ci

COPY . .

RUN npm run build

FROM node:20-alpine AS production

WORKDIR /app

COPY package*.json ./

RUN npm ci --omit=dev && npm cache clean --force

COPY --from=builder /build/dist ./dist

EXPOSE 8080

ENV NODE_ENV=production

CMD ["node", "./dist/index.js"]
