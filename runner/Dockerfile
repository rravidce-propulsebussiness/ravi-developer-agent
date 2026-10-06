FROM node:24-bookworm-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev && npx playwright install --with-deps chromium
COPY src ./src
ENV RUNNER_HOST=0.0.0.0
ENV RUNNER_PORT=8788
ENV HEADLESS=true
EXPOSE 8788
CMD ["npm","start"]
