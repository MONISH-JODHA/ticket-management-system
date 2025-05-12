# wsgi.py
from server import app, socketio # This imports the app and socketio instance from server.py
import os

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001))
    # For Docker, debug mode is often controlled by an environment variable too
    # For local testing directly with `python wsgi.py`, you might set debug=True here
    # But for Docker, the CMD/ENTRYPOINT should ideally control this or use FLASK_DEBUG
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1" # Match Docker ENV
    print(f"Starting SocketIO server via wsgi.py on port {port} with debug={debug_mode}")
    socketio.run(app, host='0.0.0.0', port=port, debug=debug_mode, use_reloader=debug_mode)
