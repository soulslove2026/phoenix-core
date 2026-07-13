FROM node:20-alpine
WORKDIR /app
COPY package.json VERSION.json ./
COPY src ./src
ENV PHOENIX_ENV=container PHOENIX_HOST=0.0.0.0 PHOENIX_PORT=3000
RUN addgroup -S phoenix && adduser -S phoenix -G phoenix
USER phoenix
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD node -e "fetch('http://127.0.0.1:3000/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node","src/server.mjs"]
