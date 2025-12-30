from flask import Flask
from pathlib import Path
from .routes import bp

def create_app():
    base_dir = Path(__file__).resolve().parent.parent  # project root
    app = Flask(
        __name__,
        template_folder=str(base_dir / "templates"),
        static_folder=str(base_dir / "static"),
    )
    app.register_blueprint(bp)
    return app
