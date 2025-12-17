
import { newUnits } from './src/data/new_units.js';
import fs from 'fs';

// Refined keywords - strictly focusing on ports and protocols context
const strongKeywords = [
    'port number',
    'default port',
    'listen on port',
    'tcp port',
    'udp port',
    'uses port',
];

const portQuestions = [];

Object.entries(newUnits).forEach(([unitKey, questions]) => {
    questions.forEach(q => {
        const qLowerCase = q.q.toLowerCase();

        let isMatch = false;

        // Condition 1: Direct port question
        if (strongKeywords.some(k => qLowerCase.includes(k))) {
            isMatch = true;
        }

        // Condition 2: Question asks "What is port X?" or "Which port..."
        // Regex: /port\s*\d+/ match "port 80", "port 443"
        if (/port\s+\d+/.test(qLowerCase)) {
            isMatch = true;
        }

        // Condition 3: Options are mostly short numbers (likely asking for a port)
        // Filter options that are just numbers (or like "80", "8080", "TCP/80")
        const numericOptions = q.options.filter(o =>
            // Is a number OR is "TCP/X" or "UDP/X" format
            /^\d+$/.test(o) || /^(tcp|udp)\/\d+/i.test(o) || /^\d+\/\w+/.test(o)
        ).length;

        if (numericOptions >= 3) {
            isMatch = true;
        }

        // Condition 4: "What does X stand for?" (Acronyms)
        // HEURISTIC: "stand for" in question AND options are roughly same length text
        if (qLowerCase.includes("stand for") || qLowerCase.includes("stands for")) {
            // Keep specialized acronyms out unless requested? User said "ports/protocol names. the quick memorization stuff"
            // So yes, acronyms are "quick memorization stuff".
            isMatch = true;
        }

        // Condition 5: "Which protocol..." and options are acronyms
        if (qLowerCase.includes("which protocol") || qLowerCase.includes("what protocol")) {
            // Check if options are short (likely acronyms)
            const shortOptions = q.options.filter(o => o.length < 10).length;
            if (shortOptions >= 3) {
                isMatch = true;
            }
        }

        if (isMatch) {
            // Avoid duplicates in our collection list
            if (!portQuestions.find(existing => existing.q === q.q)) {
                // Add a "unit" property for debugging context
                const qWithUnit = { ...q, _originalUnit: unitKey };
                portQuestions.push(qWithUnit);
            }
        }
    });
});

console.log(`Found ${portQuestions.length} potential port/protocol/acronym questions.`);

// Output a sample
console.log("--- Sample Questions ---");
portQuestions.slice(0, 10).forEach(q => console.log(`[${q._originalUnit}] ${q.q}`));
console.log("------------------------");

const output = JSON.stringify(portQuestions.map(({ _originalUnit, ...rest }) => rest), null, 4);
fs.writeFileSync('extracted_ports_refined.json', output);
console.log("Written to extracted_ports_refined.json");
