FROM node:22-alpine
RUN npm install -g npm@latest
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
EXPOSE 5000
CMD ["node", "app.js"]

