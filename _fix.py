lines = open('src/selftest.rs', newline='').read().split('\n')
i = next(k for k,l in enumerate(lines) if 'for l in text.split' in l)
# rebuild the line; then drop orphan continuation lines until the next real code
lines[i] = "                for l in text.split(['\u{d}', '\u{a}']) {"
j = i + 1
while j < len(lines) and lines[j].strip() in (']) {', "']) {", '] ){', ''):
    del lines[j]
open('src/selftest.rs','w',newline='').write('\n'.join(lines))
