from flask import Flask, request, render_template, jsonify, send_from_directory
import json
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_volatility_file(filepath):
    """Process the volatility file and return JSON data"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            all_lines = [line.rstrip() for line in f if line.strip()]
        header_line_idx = -1
        for i, line in enumerate(all_lines):
            if line.strip().startswith('PID') and 'PPID' in line:
                header_line_idx = i
                break

        if header_line_idx == -1:
            return {"error": "Could not find header line containing PID and PPID"}

        headers = all_lines[header_line_idx].replace('(V)', '').split('\t')
        data_lines = all_lines[header_line_idx + 1:]

        key_map = {
            'PID': 'pid', 'PPID': 'ppid', 'ImageFileName': 'ImageFileName', 
            'Offset': 'Offset', 'Threads': 'Threads', 'Handles': 'Handles', 
            'SessionId': 'SessionId', 'Wow64': 'Wow64', 'CreateTime': 'CreateTime',
            'ExitTime': 'ExitTime', 'Audit': 'Audit', 'Cmd': 'Cmd', 'Path': 'Path'
        }

        data = []
        for line_num, line in enumerate(data_lines, start=header_line_idx + 2):
            line = line.lstrip('* ').rstrip()
            if not line:
                continue
            
            parts = line.split('\t')
            if len(parts) < 3: 
                continue
            
            obj = {}
            for idx, header in enumerate(headers):
                key = key_map.get(header, header)
                value = parts[idx] if idx < len(parts) else ''
                value = '' if value == '-' or value == 'N/A' else value
                obj[key] = value

            if 'pid' not in obj or not str(obj['pid']).strip():
                continue

            try:
                obj['pid'] = int(obj['pid']) if str(obj['pid']).isdigit() else obj['pid']
                if 'ppid' in obj:
                    obj['ppid'] = int(obj['ppid']) if str(obj['ppid']).isdigit() else obj['ppid']
                if 'Threads' in obj:
                    obj['Threads'] = int(obj['Threads']) if str(obj['Threads']).isdigit() else obj['Threads']
            except ValueError:
                continue
                
            data.append(obj)

        return {"success": True, "data": data, "count": len(data)}
    
    except Exception as e:
        return {"error": f"Error processing file: {str(e)}"}

@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/visualizer')
def visualizer():
    return render_template('visualizer.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'})
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        result = process_volatility_file(filepath)
        
        if "error" in result:
            return jsonify(result), 400
        
        json_filename = filename.rsplit('.', 1)[0] + '.json'
        json_filepath = os.path.join(app.config['UPLOAD_FOLDER'], json_filename)
        
        with open(json_filepath, 'w', encoding='utf-8') as f:
            json.dump(result['data'], f, indent=2)
        
        return jsonify({
            'success': True, 
            'message': f'File processed successfully. Found {result["count"]} processes.',
            'json_file': json_filename
        })
    
    return jsonify({'error': 'Invalid file type. Only .txt files are allowed.'})

@app.route('/data/<filename>')
def get_data(filename):
    """Serve JSON data files"""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except:
        return jsonify({'error': 'File not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)