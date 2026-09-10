import os
import uvicorn
from app.config import HOST, PORT

if __name__ == "__main__":
    dev_reload = os.getenv("DEV_RELOAD", "false").lower() == "true"
    print(f"[*] Starting AmneziaWG Panel at http://{HOST}:{PORT}")
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=dev_reload)
