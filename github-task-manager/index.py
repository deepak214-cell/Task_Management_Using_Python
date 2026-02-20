from app import app

# Vercel looks for a variable named `app` or a callable in index.py
if __name__ == '__main__':
    app.run()
