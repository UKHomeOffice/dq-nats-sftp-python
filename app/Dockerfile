FROM centos:8

ENV USERMAP_UID 1000
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
RUN groupadd -r runner && \
    useradd --no-log-init -u $USERMAP_UID -r -g runner runner && \
    groupadd docker && \
    usermod -aG docker runner && \
    chown -R runner:runner /NATS && \
    chown -R runner:runner /home/runner/.pm2 && \
    chown -R runner:runner /home/runner/.ssh

# Install script dependencies
RUN yum update -y
RUN yum install -y wget make gcc openssl-devel zlib-devel pcre-devel bzip2-devel libffi-devel epel-release python3

# Install modules with pip
RUN pip3 install --no-cache-dir -r /tmp/NATS/scripts/packages.txt

# Install PM2
RUN curl -sL https://raw.githubusercontent.com/nodesource/distributions/master/rpm/setup_12.x -o setup_12.x && bash setup_12.x && rm setup_12.x && \
    yum install -y nodejs && \
    npm install -g pm2

VOLUME ["/NATS"]
RUN chown -R runner:runner /NATS

RUN chown runner:runner /docker-entrypoint.sh && \
chmod +x /docker-entrypoint.sh

USER ${USERMAP_UID}

WORKDIR /NATS

ENTRYPOINT ["/docker-entrypoint.sh"]

# Start PM2
CMD pm2-docker /NATS/scripts/ecosystem.config.js  -- --config $SSH_REMOTE_HOST $SSH_REMOTE_USER $SSH_PRIVATE_KEY_PATH $SSH_LANDING_DIR $S3_BUCKET_NAME \
    $S3_KEY_PREFIX $S3_ACCESS_KEY_ID $S3_SECRET_ACCESS_KEY $GA_S3_BUCKET_NAME $GA_S3_KEY_PREFIX $GA_S3_ACCESS_KEY_ID $GA_S3_SECRET_ACCESS_KEY \
    $CLAMAV_URL $CLAMAV_PORT $SLACK_WEBHOOK

# Save PM2 configuration
RUN pm2 save
