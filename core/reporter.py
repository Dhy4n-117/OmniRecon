import json
from core.console import Logger
import os
from jinja2 import Environment, FileSystemLoader

class set_encoder(json.JSONEncoder):
    """Used to serialize Python sets to JSON lists"""
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)

async def generate_json_report(context: dict, output_path: str):
    """Saves the context dictionary to a structured JSON file and generates an HTML dashboard."""
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        # 1. Output JSON
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(context, f, indent=4, cls=set_encoder)
        
        # 2. Output HTML
        html_path = output_path.replace(".json", ".html")
        template_dir = os.path.dirname(os.path.abspath(__file__))
        
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('report_template.html')
        
        html_content = template.render(context=context)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        Logger.success(f"HTML Dashboard saved to {html_path}")
            
    except Exception as e:
        Logger.error(f"Failed to generate reports: {e}")
