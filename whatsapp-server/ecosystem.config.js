module.exports = {
  apps: [{
    name: 'whatsapp-server',
    script: 'src/index.js',
    // watch: true,
    env: {
      NODE_ENV: 'production',
    },
    instances: 1,
    // autorestart: true,
    max_memory_restart: '1G',
    error_file: 'logs/err.log',
    out_file: 'logs/out.log',
    merge_logs: true,
    log_date_format: 'YYYY-MM-DD HH:mm:ss',
  }]
}; 