from .monitor import monitor_bp
from .alerts import alerts_bp
from .stats import stats_bp
from .threats import threats_bp


def register_blueprints(app):
    app.register_blueprint(monitor_bp, url_prefix='/api/v1')
    app.register_blueprint(alerts_bp, url_prefix='/api/v1')
    app.register_blueprint(stats_bp, url_prefix='/api/v1')
    app.register_blueprint(threats_bp, url_prefix='/api/v1')
