from flask import Flask, request, render_template, jsonify, send_from_directory
import json
import os
from werkzeug.utils import secure_filename
import google.generativeai as genai

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'txt'}

# 🔹 Configure Google AI Studio
genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")  # Fast model

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def analyze_batch(processes):
    """
    Send a batch of processes to Gemini for analysis.
    Returns a list of analyses in the same order as input.
    """
    prompt = f"""
    You are a digital forensics assistant.
    Analyze these Windows processes from Volatility psscan.

    Respond ONLY in valid JSON array. Do not include any markdown formatting or code blocks.
    Each element should match this schema:
    {{
      "pid": <pid>,
      "description": "Explain what this process usually does",
      "suspicious": true/false,
      "reason": "Why you marked it suspicious or not"
    }}

    Processes:
    {json.dumps(processes, indent=2)}
    """

    response = model.generate_content(prompt)
    print("Raw response:")
    print(response.text)
    
    response_text = response.text.strip()
    
    # Remove ```json and ``` markers if present
    if response_text.startswith('```json'):
        response_text = response_text[7:]
    elif response_text.startswith('```'):
        response_text = response_text[3:]
        
    if response_text.endswith('```'):
        response_text = response_text[:-3]
        
    response_text = response_text.strip()
    
    print("Cleaned response:")
    print(response_text)
    
    try:
        analyses = json.loads(response_text)
        if isinstance(analyses, list):
            return analyses
        else:
            return [analyses] if isinstance(analyses, dict) else []
    except Exception as e:
        print(f"Error parsing Gemini response: {e}")
        return [
            {
                "pid": p.get("pid"),
                "description": "Analysis unavailable due to parsing error",
                "suspicious": False,
                "reason": "Could not parse AI response"
            }
            for p in processes
        ]


def process_volatility_file(filepath, batch_size=10):
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

        processes = []
        for line in data_lines:
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
                value = '' if value in ['-', 'N/A'] else value
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

            processes.append(obj)

        results = []
        for i in range(0, len(processes), batch_size):
            batch = processes[i:i+batch_size]
            analyses = analyze_batch(batch)

            analysis_map = {a.get("pid"): a for a in analyses if isinstance(a, dict)}
            
            for p in batch:
                analysis = analysis_map.get(p["pid"])
                if analysis:
                    p["description"] = analysis.get("description", "No description available")
                    p["suspicious"] = analysis.get("suspicious", False)
                    p["reason"] = analysis.get("reason", "No analysis reason provided")
                else:
                    p["description"] = "Analysis not available"
                    p["suspicious"] = False
                    p["reason"] = "No analysis data received"
                
                results.append(p)

        return {"success": True, "data": results, "count": len(results)}

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