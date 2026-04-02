from flask import Flask, render_template
from .extensions import db, socketio, cors
from .api import register_blueprints
from config import config_map


def create_app(config_name='development'):
    app = Flask(__name__)
    app.config.from_object(config_map[config_name])

    db.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')
    cors.init_app(app)

    with app.app_context():
        db.create_all()

    register_blueprints(app)

    @app.route('/')
    def index():
        return render_template('index.html')

    return app
