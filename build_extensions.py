import os
import zipfile
import shutil
from pathlib import Path

def create_extension_package(browser, source_dir, output_dir):
    """Create a ZIP package for a browser extension"""
    extension_files = {
        'chrome': ['manifest.json', 'content.js', 'background.js', 'popup.html', 'popup.js', 'styles.css', 'icons/'],
        'firefox': ['manifest.json', 'content.js', 'background.js', 'popup.html', 'popup.js', 'styles.css', 'icons/'],
        'edge': ['manifest.json', 'content.js', 'background.js', 'popup.html', 'popup.js', 'styles.css', 'icons/']
    }
    
    zip_path = os.path.join(output_dir, f'GENIUSGAURD-extension-{browser}.zip')
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for item in extension_files[browser]:
            item_path = os.path.join(source_dir, item)
            
            if item.endswith('/'):  # Directory
                for root, dirs, files in os.walk(item_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, source_dir)
                        zipf.write(file_path, arcname)
            else:  # File
                if os.path.exists(item_path):
                    zipf.write(item_path, os.path.basename(item_path))
    
    print(f"✅ Created {browser} extension: {zip_path}")
    return zip_path

def main():
    # Ensure static downloads directory exists
    static_dir = Path('static/downloads')
    static_dir.mkdir(parents=True, exist_ok=True)
    
    # Package each browser extension
    browsers = ['chrome', 'firefox', 'edge']
    
    for browser in browsers:
        source_dir = Path(f'browser_extensions/{browser}')
        if source_dir.exists():
            create_extension_package(browser, source_dir, static_dir)
        else:
            print(f"❌ Source directory not found: {source_dir}")
    
    print("\n🎉 Extension packages created successfully!")
    print("📁 Location: static/downloads/")
    print("\nTo install:")
    print("Chrome/Edge: Go to chrome://extensions → Enable Developer Mode → Load unpacked")
    print("Firefox: Go to about:debugging → This Firefox → Load Temporary Add-on")

if __name__ == '__main__':
    main()