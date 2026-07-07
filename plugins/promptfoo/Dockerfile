FROM node:22-slim

RUN npm install -g promptfoo@latest

WORKDIR /work
COPY package.json ./
RUN npm install --omit=dev
COPY agentsec-promptfoo-bridge.js ./

# Fully local generation/grading: never call promptfoo's cloud service.
ENV PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true
ENV OLLAMA_BASE_URL=http://host.docker.internal:11434

ENTRYPOINT ["node", "/work/agentsec-promptfoo-bridge.js"]
