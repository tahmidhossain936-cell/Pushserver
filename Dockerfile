# Stage 1: Build & Dependencies
FROM node:22-alpine AS builder

WORKDIR /usr/src/app

COPY package*.json ./

# npm ci এর পরিবর্তে npm install ব্যবহার করা হয়েছে
RUN npm install --omit=dev

# Stage 2: Runtime Production Image
FROM node:22-alpine

WORKDIR /usr/src/app

ENV NODE_ENV=production
ENV PORT=10000

COPY package*.json ./
COPY --from=builder /usr/src/app/node_modules ./node_modules
COPY server.js ./

USER node

EXPOSE 10000

CMD ["node", "server.js"]
