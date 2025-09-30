FROM node:20
WORKDIR /app
COPY package*.json pnpm-lock.yaml* ./
RUN corepack enable && corepack prepare pnpm@10.0.0 --activate
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm run build
CMD ["node", "dist/server.js"]
