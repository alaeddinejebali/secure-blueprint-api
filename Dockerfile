FROM node:20-alpine

WORKDIR /app

# Copy dependency manifests first to leverage Docker layer caching.
# Dependencies are only reinstalled when package.json changes.
COPY package*.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 5000

CMD ["npm", "start"]
