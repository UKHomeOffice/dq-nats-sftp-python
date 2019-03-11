module.exports = {
  /**
   * Application configuration
   * Note: all environment variables are required.
   *
   */
  apps : [
    {
      name      : "DQ-NATS-file-ingest",
      script    : "/NATS/bin/DQ_NATS_file_ingest",
      interpreter: "python",
      env: {
        PROCESS_INTERVAL: 60,
        MAX_BATCH_SIZE: 5000,
        SSH_REMOTE_HOST : process.argv[5],
        SSH_REMOTE_USER : process.argv[6],
        SSH_PRIVATE_KEY : process.argv[7],
        SSH_LANDING_DIR : process.argv[8],
        S3_BUCKET_NAME : process.argv[9],
        S3_KEY_PREFIX : process.argv[10],
        S3_ACCESS_KEY_ID : process.argv[11],
        S3_SECRET_ACCESS_KEY : process.argv[12],
        S3_REGION_NAME : "eu-west-2",
        GA_S3_BUCKET_NAME: process.argv[13],
        GA_S3_KEY_PREFIX: process.argv[14],
        GA_S3_ACCESS_KEY_ID: process.argv[15],
        GA_S3_SECRET_ACCESS_KEY: process.argv[16],
        CLAMAV_URL : process.argv[17],
        CLAMAV_PORT : process.argv[18]
      }
    }
  ]
};
