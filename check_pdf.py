import fitz

doc = fitz.open('test_report.pdf')
for i, page in enumerate(doc):
    if i > 5: break
    print(f'--- PAGE {i+1} ---')
    blocks = page.get_text('dict')['blocks']
    for b in blocks:
        if 'lines' in b:
            for l in b['lines']:
                for s in l['spans']:
                    color_hex = '#%06x' % s['color']
                    text = s['text'].strip()
                    if text:
                        print(f'Y: {s["bbox"][1]:.1f}, Color: {color_hex}, Size: {s["size"]:.1f} | {text}')
