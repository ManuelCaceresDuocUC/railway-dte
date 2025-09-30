FROM node:20-alpine
WORKDIR /app

# usa pnpm en imagen
RUN corepack enable && corepack prepare pnpm@10.0.0 --activate

# instala deps solo con los manifests
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# copia el resto del código (sin node_modules por .dockerignore)
COPY . .

RUN pnpm run build
CMD ["node", "dist/server.js"]
