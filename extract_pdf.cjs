const fs = require('fs');
const pdf = require('pdf-parse');
const path = require('path');

const files = [
    { path: '/Users/ric/Desktop/SEC+ quiz tool/unit 6 malware.pdf', unit: 'unit-6' },
    { path: '/Users/ric/Desktop/SEC+ quiz tool/unit 7 data protection.pdf', unit: 'unit-7' }
];

async function extract() {
    for (const file of files) {
        if (fs.existsSync(file.path)) {
            const dataBuffer = fs.readFileSync(file.path);
            try {
                const data = await pdf(dataBuffer);
                console.log(`\n--- START ${file.unit} ---`);
                console.log(data.text);
                console.log(`--- END ${file.unit} ---\n`);
            } catch (e) {
                console.error(`Error parsing ${file.path}:`, e);
            }
        } else {
            console.error(`File not found: ${file.path}`);
        }
    }
}

extract();
