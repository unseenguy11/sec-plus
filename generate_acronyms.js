import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const inputFile = path.join(__dirname, 'Security+_701_Acronyms_with_Brief_Definitions.txt');
const outputFile = path.join(__dirname, 'src/data/acronyms_data.js');

const rawData = fs.readFileSync(inputFile, 'utf-8');
const lines = rawData.split('\n').filter(line => line.trim() !== '');

const acronyms = [];

lines.forEach(line => {
    // Format: ACRONYM = Expansion — Definition
    // Sometimes Expansion and Definition are the same.
    const parts = line.split('=').map(p => p.trim());
    if (parts.length >= 2) {
        const acronym = parts[0];
        const rest = parts[1];

        // Split by em dash '—' or hyphen '-' if em dash is missing (though file looks like em dash)
        // copy pasted em dash from file content just to be safe: —
        let expansion = rest;
        let definition = '';

        if (rest.includes('—')) {
            const defParts = rest.split('—').map(p => p.trim());
            expansion = defParts[0];
            definition = defParts[1];
        } else {
            // Fallback if no dash
            expansion = rest;
            definition = rest;
        }

        // Clean up
        if (acronym && expansion) {
            acronyms.push({ acronym, expansion, definition });
        }
    }
});

// Generate Questions
const questions = acronyms.map((item, index) => {
    const correctAnswer = item.expansion;

    // Select 3 random distractors
    const distractors = [];
    while (distractors.length < 3) {
        const randomIdx = Math.floor(Math.random() * acronyms.length);
        const randomItem = acronyms[randomIdx];
        if (randomItem.expansion !== correctAnswer && !distractors.includes(randomItem.expansion)) {
            distractors.push(randomItem.expansion);
        }
    }

    const options = [correctAnswer, ...distractors];
    // Shuffle options
    for (let i = options.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [options[i], options[j]] = [options[j], options[i]];
    }

    const answerIndex = options.indexOf(correctAnswer);

    return {
        q: `What does the acronym "${item.acronym}" stand for?`,
        options: options,
        answer: answerIndex,
        explanation: `${item.acronym} stands for ${item.expansion}. ${item.definition !== item.expansion ? item.definition : ''}`
    };
});

const fileContent = `export const acronymsData = ${JSON.stringify(questions, null, 4)};`;

fs.writeFileSync(outputFile, fileContent);

console.log(`Generated ${questions.length} questions in ${outputFile}`);
