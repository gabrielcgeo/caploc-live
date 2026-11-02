FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.js viewer.html monitor.html ./
RUN mkdir -p /data && chown node:node /data
USER node
ENV PORT=8080 DATA_DIR=/data
EXPOSE 8080
CMD ["node","server.js"]
