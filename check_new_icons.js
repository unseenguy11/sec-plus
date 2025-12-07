import * as Lucide from 'lucide-react';

const iconsToCheck = ['Search', 'Bot', 'GraduationCap'];

console.log('Checking icon exports...');
iconsToCheck.forEach(icon => {
    if (Lucide[icon]) {
        console.log(`✅ ${icon} is exported.`);
    } else {
        console.error(`❌ ${icon} is NOT exported.`);
    }
});
