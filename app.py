# Simple Flask Calculator Application
from flask import Flask, render_template, request, jsonify

#h
app = Flask(__name__)

@app.route('/')
def index():
    """Render the calculator homepage"""
    return render_template('index.html')

@app.route('/calculate', methods=['POST'])
def calculate():
    """Perform calculation based on user input"""
    try:
        data = request.get_json()
        num1 = float(data['num1'])
        num2 = float(data['num2'])
        operation = data['operation']

        if operation == 'add':
            result = num1 + num2
        elif operation == 'subtract':
            result = num1 - num2
        elif operation == 'multiply':
            result = num1 * num2
        elif operation == 'divide':
            if num2 == 0:
                return jsonify({'error': 'Cannot divide by zero'}), 400
            result = num1 / num2
        else:
            return jsonify({'error': 'Invalid operation'}), 400

        return jsonify({'result': result})

    except (ValueError, KeyError) as e:
        return jsonify({'error': 'Invalid input'}), 400

if __name__ == '__main__':
    # Note: debug=False in production
    app.run(host='0.0.0.0', port=5000, debug=True)
