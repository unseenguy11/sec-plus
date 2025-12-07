
import fs from 'fs';
import { newUnits } from './src/data/new_units.js';

const unitsToFix = ['unit-16', 'unit-17', 'unit-18'];

unitsToFix.forEach(unitKey => {
    if (newUnits[unitKey]) {
        console.log(`Fixing ${unitKey}...`);
        newUnits[unitKey] = newUnits[unitKey].map(item => {
            // Check if it's already in the correct format
            if (item.q && item.answer !== undefined) {
                return item;
            }

            // Transform from { question, correctAnswer } to { q, answer }
            if (item.question && item.correctAnswer) {
                const answerIndex = item.options.indexOf(item.correctAnswer);

                if (answerIndex === -1) {
                    console.error(`Error: Correct answer "${item.correctAnswer}" not found in options for question: "${item.question}"`);
                    // Fallback or keep as is to avoid data loss, but mark as error
                    return item;
                }

                return {
                    q: item.question,
                    options: item.options,
                    answer: answerIndex,
                    explanation: item.explanation
                };
            }

            return item;
        });
    } else {
        console.warn(`Unit ${unitKey} not found in newUnits.`);
    }
});

const content = `export const newUnits = ${JSON.stringify(newUnits, null, 4)};`;
fs.writeFileSync('./src/data/new_units.js', content);
console.log('Successfully fixed data format for Units 16, 17, and 18.');
