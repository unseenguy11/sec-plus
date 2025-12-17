
const fs = require('fs');
const newUnitsPath = './src/data/new_units.js';
const portsPath = './extracted_ports_refined.json';

try {
    console.log("Reading new_units.js...");
    let newUnits = fs.readFileSync(newUnitsPath, 'utf8');
    console.log(`Original size: ${newUnits.length} bytes`);

    console.log("Reading extracted_ports_refined.json...");
    const ports = fs.readFileSync(portsPath, 'utf8');
    console.log(`Ports size: ${ports.length} bytes`);

    // Find the last closing brace which ends the 'units' object
    // We expect the file to end with "};" or just "}"
    const lastBraceIndex = newUnits.lastIndexOf('}');
    console.log(`Found last brace at index: ${lastBraceIndex}`);

    if (lastBraceIndex !== -1) {
        // Prepare indentation
        const insertion = ',\n    "unit-ports": ' + ports + '\n';

        // Insert before the last brace
        const updated = newUnits.slice(0, lastBraceIndex) + insertion + newUnits.slice(lastBraceIndex);

        fs.writeFileSync(newUnitsPath, updated);
        console.log(`Successfully appended unit-ports. New size: ${updated.length} bytes`);
    } else {
        console.error('Could not find closing brace in new_units.js');
        process.exit(1);
    }
} catch (err) {
    console.error('Error processing files:', err);
    process.exit(1);
}
