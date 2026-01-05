import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const inputFile = path.join(__dirname, 'Security+_701_Acronyms_with_Brief_Definitions.txt');
const outputFile = path.join(__dirname, 'src/data/acronyms_data.js');

const rawData = fs.readFileSync(inputFile, 'utf-8');
const lines = rawData.split('\n').filter(line => line.trim() !== '');

const acronyms = [];
const wordCorpus = {}; // Map<Letter, Set<Word>>

// Words we don't want to use as swap targets or keep in the corpus usually
const stopWords = new Set(['of', 'and', 'the', 'for', 'in', 'to', 'a', 'or', 'with', 'by']);

lines.forEach(line => {
    // Format: ACRONYM = Expansion — Definition
    const parts = line.split('=').map(p => p.trim());
    if (parts.length >= 2) {
        const acronym = parts[0];
        const rest = parts[1];

        let expansion = rest;
        let definition = '';

        if (rest.includes('—')) {
            const defParts = rest.split('—').map(p => p.trim());
            expansion = defParts[0];
            definition = defParts[1];
        } else {
            expansion = rest;
            definition = rest;
        }

        if (acronym && expansion) {
            acronyms.push({ acronym, expansion, definition });

            // Build corpus
            const words = expansion.split(/[\s\-\/]+/).map(w => w.replace(/[^a-zA-Z]/g, ''));
            words.forEach(word => {
                if (word.length > 2 && !stopWords.has(word.toLowerCase())) {
                    const firstLetter = word[0].toUpperCase();
                    if (!wordCorpus[firstLetter]) {
                        wordCorpus[firstLetter] = new Set();
                    }
                    wordCorpus[firstLetter].add(word);
                }
            });
        }
    }
});

// Convert sets to arrays for random access
const corpusArrays = {};
for (const letter in wordCorpus) {
    corpusArrays[letter] = Array.from(wordCorpus[letter]);
}

function getRandomWord(letter) {
    const words = corpusArrays[letter];
    if (!words || words.length === 0) return null;
    return words[Math.floor(Math.random() * words.length)];
}

function generateDistractor(item) {
    const correctWords = item.expansion.split(' ');
    const strategy = Math.random();

    // Strategy 1: Swap words (60% chance)
    if (strategy < 0.60 && correctWords.length > 1) {
        const newWords = [...correctWords];
        let swapped = false;
        // Try to swap up to 2 words
        for (let i = 0; i < 2; i++) {
            const idx = Math.floor(Math.random() * newWords.length);
            const originalWord = newWords[idx];
            // Remove punctuation for corpus lookup
            const cleanWord = originalWord.replace(/[^a-zA-Z]/g, '');
            if (cleanWord.length > 2 && !stopWords.has(cleanWord.toLowerCase())) {
                const letter = cleanWord[0].toUpperCase();
                const swapCandidate = getRandomWord(letter);

                if (swapCandidate && swapCandidate !== cleanWord) {
                    // Try to preserve original casing/punctuation if simple
                    newWords[idx] = swapCandidate;
                    swapped = true;
                }
            }
        }

        const candidate = newWords.join(' ');
        if (swapped && candidate !== item.expansion) return candidate;
    }

    // Strategy 2: Scramble words (20% chance)
    if (strategy >= 0.60 && strategy < 0.80 && correctWords.length > 2) {
        const shuffled = [...correctWords];
        for (let i = shuffled.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }
        const candidate = shuffled.join(' ');
        if (candidate !== item.expansion) return candidate;
    }

    // Strategy 3: Random other acronym expansion (Fallback / 20% chance)
    // Try to find one starting with same letter
    const startChar = item.expansion[0].toUpperCase();
    const sameStart = acronyms.filter(a => a.expansion[0].toUpperCase() === startChar && a.expansion !== item.expansion);

    if (sameStart.length > 0) {
        return sameStart[Math.floor(Math.random() * sameStart.length)].expansion;
    }

    // Last resort: pure random
    let randomItem;
    do {
        randomItem = acronyms[Math.floor(Math.random() * acronyms.length)];
    } while (randomItem.expansion === item.expansion);
    return randomItem.expansion;
}

// Generate Questions
const questions = acronyms.map((item) => {
    const correctAnswer = item.expansion;
    const distractors = new Set();

    // Attempt to generate 3 unique distractors
    let attempts = 0;
    while (distractors.size < 3 && attempts < 20) {
        const d = generateDistractor(item);
        if (d && d !== correctAnswer) {
            distractors.add(d);
        }
        attempts++;
    }

    // Fill with randoms if we failed to generate enough smart ones
    while (distractors.size < 3) {
        let randomItem = acronyms[Math.floor(Math.random() * acronyms.length)];
        if (randomItem.expansion !== correctAnswer) {
            distractors.add(randomItem.expansion);
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
