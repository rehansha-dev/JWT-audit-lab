FROM node:20-alpine
WORKDIR /app

# curl is used by the docker-compose healthcheck.
RUN apk add --no-cache curl

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 4000
# Generates a fresh dev RSA keypair on start, then launches the server.
CMD ["npm", "start"]
