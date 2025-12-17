
import { newUnits } from './src/data/new_units.js';
import fs from 'fs';

// Heuristic keywords to identify port/protocol questions
const keywords = [
    'port',
    'protocol',
    'stands for',
    'TCP',
    'UDP',
    'uses port',
    'listening on port',
    'implies which port',
    'service runs on'
];

// Regex for strictly port questions? 
// Maybe checking if options are all numbers is a good heuristic for "What port is X?"

// Let's iterate through all units and collect matching questions
const portQuestions = [];

Object.entries(newUnits).forEach(([unitKey, questions]) => {
    questions.forEach(q => {
        const explanation = q.explanation ? q.explanation.toLowerCase() : "";
        const text = q.q.toLowerCase() + " " + explanation;

        let isMatch = false;

        // Check for keywords
        if (keywords.some(k => text.includes(k.toLowerCase()))) {
            // Refine: "stands for" usually implies acronym memorization
            // "port" usually implies port memorization
            isMatch = true;
        }

        // Check if options are mostly numbers (port questions)
        const numericOptions = q.options.filter(o => !isNaN(parseInt(o)) && o.length < 6).length;
        if (numericOptions >= 3) {
            isMatch = true;
        }

        if (isMatch) {
            // Avoid duplicates in our collection list based on question text
            if (!portQuestions.find(existing => existing.q === q.q)) {
                portQuestions.push(q);
            }
        }
    });
});

console.log(`Found ${portQuestions.length} potential port/protocol questions.`);

// Output a sample for verification
console.log("--- Sample Questions ---");
portQuestions.slice(0, 5).forEach(q => console.log(`Q: ${q.q}`));
console.log("------------------------");

// Prepare the output string to append to new_units.js
// We want to construct a JS object string for "unit-ports"
const output = JSON.stringify(portQuestions, null, 4);

// Write to a temporary file for inspection
fs.writeFileSync('extracted_ports.json', output);
console.log("Full extraction written to extracted_ports.json");
