FROM node:23-alpine3.20
WORKDIR /backend
COPY ./package.json .
COPY ./package-lock.json .
RUN npm install
COPY . .
