
FROM oven/bun:latest


WORKDIR /usr/src/app


# Install dependencies
COPY package.json bun.lockb ./
RUN bun install


COPY . .


EXPOSE 80


CMD [ "bun", "run", "start" ]
