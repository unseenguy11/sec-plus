import { questionsData } from './src/data/questions.js';
import { newUnits } from './src/data/new_units.js';

// Merge all units
const allUnits = { ...questionsData, ...newUnits };

const flaggedQuestions = [];

for (const [unit, questions] of Object.entries(allUnits)) {
    // Filter for units 5-15
    const unitNum = parseInt(unit.replace('unit-', ''));
    if (isNaN(unitNum) || unitNum < 5 || unitNum > 15) continue;

    questions.forEach((q, index) => {
        const correctOpt = q.options[q.answer];
        const distractors = q.options.filter((_, i) => i !== q.answer);

        const correctLen = correctOpt.length;
        const maxDistractorLen = Math.max(...distractors.map(d => d.length));
        const avgDistractorLen = distractors.reduce((a, b) => a + b.length, 0) / distractors.length;

        // Criteria: Correct answer is the longest AND significantly longer
        // e.g., 40% longer than the longest distractor OR 
        // 50% longer than average distractor and at least 15 chars difference

        const ratio = correctLen / maxDistractorLen;
        const diff = correctLen - maxDistractorLen;

        if (correctLen > maxDistractorLen && (ratio > 1.4 || diff > 25)) {
            flaggedQuestions.push({
                unit,
                index,
                question: q.q,
                correct: correctOpt,
                longestDistractor: distractors.find(d => d.length === maxDistractorLen),
                ratio: ratio.toFixed(2),
                diff
            });
        }
    });
}

// Sort by ratio descending
flaggedQuestions.sort((a, b) => parseFloat(b.ratio) - parseFloat(a.ratio));

console.log(JSON.stringify(flaggedQuestions, null, 2));
console.log(`Total flagged: ${flaggedQuestions.length}`);
