FROM alpine:3

ENV USERMAP_UID 1000
ENV RUNNER_UID 1001
ENV DOCKER_UID 1002
ENV PYTHONPATH="$PYTHONPATH:/NATS"

# Setup folder structure and copy files
RUN mkdir -p \
             /tmp/NATS/scripts \
             /tmp/NATS/data/nats \
             /tmp/NATS/stage/nats \
             /tmp/NATS/quarantine/nats \
             /tmp/NATS/failed_to_parse/nats \
             /tmp/NATS/log \
             /tmp/NATS/bin \
             /NATS \
             /home/runner/.pm2 \
             /home/runner/.ssh


COPY packages.txt /tmp/NATS/scripts
COPY ecosystem.config.js /tmp/NATS/scripts
COPY docker-entrypoint.sh /
ADD bin /tmp/NATS/bin
ADD scripts /tmp/NATS/scripts

# Add user
RUN addgroup -g $RUNNER_UID runner && \
    adduser -u $USERMAP_UID -G runner -D runner && \
    addgroup -g $DOCKER_UID docker && \
    chown -R runner:runner /NATS && \
    chown -R runner:runner /home/runner/.pm2 && \
    chown -R runner:runner /home/runner/.ssh

# Install script dependencies
RUN apk add --update py-pip && \
    apk add --update py3-boto3 && \
    apk add --update py3-paramiko && \
    apk add --update py3-requests && \
    apk add --update py3-schedule && \
    apk add --update py3-cryptography

# Install PM2
RUN apk add --update nodejs npm
RUN npm install -g pm2 && \
    npm update -g pm2


RUN apk update --quiet \
    && apk upgrade --quiet

VOLUME ["/NATS"]
RUN chown -R runner:runner /NATS

RUN chown runner:runner /docker-entrypoint.sh && \
chmod +x /docker-entrypoint.sh

USER ${USERMAP_UID}

WORKDIR /NATS

ENTRYPOINT ["sh", "/docker-entrypoint.sh"]

# Start PM2
CMD pm2-docker /NATS/scripts/ecosystem.config.js  -- --config $SSH_REMOTE_HOST $SSH_REMOTE_USER $SSH_PRIVATE_KEY_PATH $SSH_LANDING_DIR $S3_BUCKET_NAME \
    $S3_KEY_PREFIX $S3_ACCESS_KEY_ID $S3_SECRET_ACCESS_KEY $GA_S3_BUCKET_NAME $GA_S3_KEY_PREFIX $GA_S3_ACCESS_KEY_ID $GA_S3_SECRET_ACCESS_KEY \
    $CLAMAV_URL $CLAMAV_PORT $SLACK_WEBHOOK

# Save PM2 configuration
RUN pm2 save

RUN node --version
RUN npm --version
