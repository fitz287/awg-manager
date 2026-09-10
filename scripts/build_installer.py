#!/usr/bin/env python3
import io
import os
import tarfile
import base64
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

EXCLUDE_DIRS = {
    'venv', '.git', '__pycache__', 'data', 'scratch',
    '.user_uploaded', 'tests', '.system_generated'
}

EXCLUDE_FILES = {
    'scratch_check.js', 'install.sh'
}

def create_tar_archive() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for root, dirs, files in os.walk(BASE_DIR):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for f in files:
                if f in EXCLUDE_FILES or f.endswith('.pyc') or f.endswith('.db') or f.endswith('.log'):
                    continue
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, BASE_DIR)
                tar.add(full_path, arcname=rel_path)
    return buf.getvalue()

def build_installer():
    print('[*] Creating compressed project archive (tar.gz)...')
    archive_bytes = create_tar_archive()
    b64_payload = base64.b64encode(archive_bytes).decode('utf-8')
    print(f'[+] Archive size: {len(archive_bytes)} bytes | Base64: {len(b64_payload)} bytes (~{round(len(b64_payload)/1024)} KB)')

    template_file = BASE_DIR / 'scripts' / 'install_template.sh'
    with open(template_file, 'r', encoding='utf-8') as f:
        template = f.read()

    installer_content = template.replace('__AWG_PAYLOAD_PLACEHOLDER__', b64_payload)
    installer_content = installer_content.replace('\r\n', '\n')

    targets = [
        BASE_DIR / 'install.sh',
        BASE_DIR / 'scripts' / 'install.sh',
        BASE_DIR / 'app' / 'static' / 'install.sh'
    ]

    for target in targets:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, 'w', encoding='utf-8', newline='\n') as f:
            f.write(installer_content)
        print(f'[+] Written installer to: {target}')

    print('[+] Build completed successfully!')

if __name__ == '__main__':
    build_installer()
