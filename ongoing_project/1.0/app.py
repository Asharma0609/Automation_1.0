import os
import subprocess
import time
from flask import Flask, render_template, request, jsonify, send_file, g
from werkzeug.utils import secure_filename
from os.path import basename
import logging

app = Flask(__name__)
# app.debug = False
# log_file = "download_debug.log"
# logging.basicConfig(filename=log_file, level=logging.DEBUG,
#                     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Set the upload folder to the directory where app.py is located
app.config['UPLOAD_FOLDER'] = os.path.dirname(os.path.abspath(__file__))

# Create the "uploads" folder if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"message": "No file part"})

    file = request.files['file']

    if file.filename == '':
        return jsonify({"message": "No selected file"})

    if file and allowed_file(file.filename):
        # Get the secure filename
        filename = secure_filename(file.filename)

        # Construct the full path to save the file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Remove the existing file if it already exists
        if os.path.exists(file_path):
            os.remove(file_path)

        # Save the new file with its original filename
        file.save(file_path)

        return jsonify({"message": "File successfully uploaded"})
    return jsonify({"message": "File upload failed"})


def allowed_file(filename):
    # Check if the file has a valid extension (e.g., .tgz)
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'tgz'


@app.route('/start-investigation', methods=['POST'])
def start_investigation():
    app.config['UPLOAD_FOLDER'] = os.path.dirname(os.path.abspath(__file__))
    # Get the list of files in the UPLOAD_FOLDER
    files = os.listdir(app.config['UPLOAD_FOLDER'])

    # Find the file with the appropriate file extension (e.g., .tgz)
    tgz_file_path = None
    for filename in files:
        if filename.lower().endswith('.tgz'):
            tgz_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            break

    if tgz_file_path is None:
        return jsonify({"message": "No valid .tgz file uploaded for investigation"})

    # Define the path to the Python script
    script_path = os.path.join(app.config['UPLOAD_FOLDER'], 'Health_check_with_argument.py')

    if not os.path.exists(script_path):
        return jsonify({"message": "Investigation script not found"})

    # Define a default result_filename
    result_filename = "result.txt"

    try:
        # Run the script with the .tgz file as an argument
        result = subprocess.run(['python3', script_path, tgz_file_path], capture_output=True, text=True, check=True)

        # Delete the uploaded file after processing
        os.remove(tgz_file_path)

        # Construct the filename for the result file (assuming it's in the same directory as the .tgz file)
        base_filename, _ = os.path.splitext(tgz_file_path)
        result_filename = basename(base_filename) + '.txt'

        return jsonify({"message": "Investigation completed", "fileUrl": result_filename})


    except subprocess.CalledProcessError as e:
        return jsonify({"message": f"Investigation failed: {e.stderr}"})


if __name__ == '__main__':
    app.run()
