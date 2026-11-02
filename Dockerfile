FROM node:20-alpine

# Create non-root user with uid=1000
RUN addgroup -g 1000 -S agent && \
    adduser -u 1000 -S agent -G agent

WORKDIR /app

# Copy application code
COPY package*.json ./
COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts
COPY tests ./tests
COPY prompts ./prompts
COPY skills ./skills
COPY locale ./locale
COPY examples ./examples

# Install dependencies and build
RUN npm ci --only=production && \
    npm run build

# Copy .github directory for credentials (will be mounted at runtime)
RUN mkdir -p /app/.github && chown -R agent:agent /app

# Switch to non-root user
USER agent

# Default command: run credential check
CMD ["node", "scripts/github-app-auth.mjs", "--help"]
