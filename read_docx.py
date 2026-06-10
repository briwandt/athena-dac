import zipfile
import xml.etree.ElementTree as ET
import os

def get_docx_text(path):
    try:
        if not os.path.exists(path):
            return f"Error: File not found at {path}"
        doc = zipfile.ZipFile(path)
        xml_content = doc.read('word/document.xml')
        root = ET.fromstring(xml_content)
        
        ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
        
        paragraphs = []
        for p in root.findall('.//w:p', ns):
            texts = p.findall('.//w:t', ns)
            if texts:
                paragraphs.append(''.join([t.text for t in texts if t.text]))
            else:
                paragraphs.append('') # Preserve empty paragraphs as line breaks
                
        return '\n'.join(paragraphs)
    except Exception as e:
        return f"Error processing file: {e}"

docx_path = r"C:\Users\user\Downloads\detection engineering.docx"
text_content = get_docx_text(docx_path)

# Save the extracted text as a markdown file for easy viewing
output_path = r"c:\Users\user\Documents\AntiGravity\detection engineering\extracted_docx.md"
with open(output_path, "w", encoding="utf-8") as f:
    f.write(text_content)

print(f"Text extracted successfully and saved to {output_path}")
print("First 1000 characters:")
print(text_content[:1000])
