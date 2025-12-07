import { questionsData } from './src/data/questions.js';
import { newUnits } from './src/data/new_units.js';

console.log('Testing imports...');
console.log(`newUnits has ${Object.keys(newUnits).length} units.`);
console.log(`questionsData has ${Object.keys(questionsData).length} units.`);

if (questionsData['unit-25']) {
    console.log('Unit 25 found in questionsData.');
} else {
    console.error('Unit 25 NOT found in questionsData.');
}
