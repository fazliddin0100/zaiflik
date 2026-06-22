import uvicorn

from app.browser import open_browser

if __name__ == "__main__":
    open_browser("http://localhost:8000")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
