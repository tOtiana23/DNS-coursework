from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app)

messages = []
suspicious = []

@app.route("/")
def index():
    return render_template("index.html")

@socketio.on("connect")
def on_connect():
    print("👤 Клиент подключился")
    emit("init", {"messages": messages, "suspicious": suspicious})

@socketio.on("new_message")
def on_new_message(data):
    messages.append(data)
    emit("new_message", data, broadcast=True)

@socketio.on("suspicious_log")
def on_suspicious(data):
    suspicious.append(data)
    emit("suspicious_log", data, broadcast=True)

if __name__ == "__main__":
    socketio.run(app, port=5000)
