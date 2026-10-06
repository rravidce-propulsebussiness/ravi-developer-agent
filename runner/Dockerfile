FROM node:24-bookworm-slim
WORKDIR /app

ENV NODE_ENV=production
ENV RUNNER_HOST=0.0.0.0
ENV RUNNER_PORT=8788
ENV HEADLESS=true

COPY package.json ./
RUN npm install --omit=dev \
    && npx playwright install --with-deps chromium \
    && npm cache clean --force

COPY src ./src
RUN mkdir -p /data/browser-profiles

EXPOSE 8788
CMD ["npm","start"]
