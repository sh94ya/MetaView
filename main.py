from workspace import app
import os

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.mkdir('uploads')
    if not os.path.exists('logs'):
        os.mkdir('logs')
    if not os.path.exists('Logs.txt'):
        open('logs\Logs.txt', 'a').close()
    port = int(os.environ.get('PORT', 5000))
    app.run(host = '0.0.0.0', port = 5000, debug=False)
