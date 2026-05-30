FROM node:20-alpine

WORKDIR /app

COPY package.json ./
COPY bun.lock* package-lock.json* ./

RUN npm install

COPY . .

EXPOSE 5173

# Vite dev server — host:true in vite.config.js binds to 0.0.0.0
CMD ["npm", "run", "dev"]
