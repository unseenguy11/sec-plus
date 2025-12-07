
import fs from 'fs';
import { newUnits } from './src/data/new_units.js';
import { unit16Questions, unit17Questions, unit18Questions } from './temp_units_16_18.js';

newUnits['unit-16'] = unit16Questions;
newUnits['unit-17'] = unit17Questions;
newUnits['unit-18'] = unit18Questions;

const content = `export const newUnits = ${JSON.stringify(newUnits, null, 4)};`;
fs.writeFileSync('./src/data/new_units.js', content);
console.log('Successfully merged Units 16, 17, and 18 into new_units.js');
