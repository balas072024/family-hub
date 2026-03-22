FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
RUN mkdir -p data && node server/src/seed.js
EXPOSE 3000
CMD ["node", "server/src/index.js"]
