from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/classify", methods=["POST"])
def classify():
    data = request.get_json()
    # ... simple mock classification ...
    return jsonify({
        "classification": "Test Packet",
        "explanation": "Mock AI says it's a generic packet."
    })

app.run(port=5000)
