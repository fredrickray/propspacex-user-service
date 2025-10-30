FROM node:22-alpine

WORKDIR /propspacex-user-service

COPY package.json package-lock.json* ./

COPY . .

RUN npm install

RUN npm run build

# Install only production dependencies
# RUN npm ci --only=production && npm cache clean --force
# RUN npm prune --production && npm cache clean --force

RUN ls -la .

ENV NODE_ENV=production


EXPOSE 9090

CMD ["npm", "start"]
# CMD ["node", "-r", "tsconfig-paths/register", "dist/index.js"]
# CMD ["node", "dist/index.js"]