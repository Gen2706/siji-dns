#!/usr/bin/env python3
"""
siji-DNS Backend API
Main Flask application entry point
"""

import os
import logging
from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO

from api.zones import zones_bp
from api.records import records_bp
from api.forwarding import forwarding_bp
from api.filtering import filtering_bp
from api.dnssec import dnssec_bp
from api.doh_dot import doh_dot_bp
from api.settings import settings_bp
from api.stats import stats_bp
from api.auth import auth_bp
from core.database import init_db
from core.scheduler import init_scheduler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler('/var/log/siji-dns/api.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def create_app(config=None):
    app = Flask(__name__, 
                static_folder='../frontend/static',
                template_folder='../frontend/templates')

    app.config.update(
        SECRET_KEY=os.environ.get('SIJI_SECRET_KEY', os.urandom(32).hex()),
        DATABASE_PATH=os.environ.get('SIJI_DB_PATH', '/etc/siji-dns/siji.db'),
        BIND_CONFIG_DIR=os.environ.get('BIND_CONFIG_DIR', '/etc/bind'),
        BIND_ZONES_DIR=os.environ.get('BIND_ZONES_DIR', '/etc/bind/zones'),
        BIND_LOG=os.environ.get('BIND_LOG', '/var/log/named/named.log'),
        BLOCKLIST_DIR=os.environ.get('BLOCKLIST_DIR', '/etc/siji-dns/blocklists'),
        UNBOUND_CONFIG=os.environ.get('UNBOUND_CONFIG', '/etc/unbound/unbound.conf'),
        DNSDIST_CONFIG=os.environ.get('DNSDIST_CONFIG', '/etc/dnsdist/dnsdist.conf'),
        JWT_EXPIRY=3600,
    )

    if config:
        app.config.update(config)

    CORS(app, origins=['http://localhost:8080', 'http://127.0.0.1:8080'])

    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
    app.socketio = socketio

    # Register blueprints
    app.register_blueprint(auth_bp,       url_prefix='/api/auth')
    app.register_blueprint(zones_bp,      url_prefix='/api/zones')
    app.register_blueprint(records_bp,    url_prefix='/api/records')
    app.register_blueprint(forwarding_bp, url_prefix='/api/forwarding')
    app.register_blueprint(filtering_bp,  url_prefix='/api/filtering')
    app.register_blueprint(dnssec_bp,     url_prefix='/api/dnssec')
    app.register_blueprint(doh_dot_bp,    url_prefix='/api/transport')
    app.register_blueprint(settings_bp,   url_prefix='/api/settings')
    app.register_blueprint(stats_bp,      url_prefix='/api/stats')

    # Serve frontend
    from flask import send_from_directory, render_template
    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def serve_frontend(path):
        if path and os.path.exists(os.path.join(app.static_folder, path)):
            return send_from_directory(app.static_folder, path)
        return render_template('index.html')

    with app.app_context():
        init_db(app)
        init_scheduler(app, socketio)

    logger.info("siji-DNS API started")
    return app, socketio


if __name__ == '__main__':
    app, socketio = create_app()
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
