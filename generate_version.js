import fs from 'fs';
import { execSync } from 'child_process';

try {
    const commitHash = execSync('git rev-parse --short HEAD').toString().trim();
    const commitDate = execSync('git log -1 --format=%cd').toString().trim();
    const buildDate = new Date().toISOString();

    const versionInfo = {
        commitHash,
        commitDate,
        buildDate
    };

    fs.writeFileSync('src/version.json', JSON.stringify(versionInfo, null, 2));
    console.log('Version info generated:', versionInfo);
} catch (error) {
    console.error('Error generating version info:', error);
    // Fallback if git fails (e.g. in some CI environments without .git)
    const fallback = {
        commitHash: 'unknown',
        commitDate: 'unknown',
        buildDate: new Date().toISOString()
    };
    fs.writeFileSync('src/version.json', JSON.stringify(fallback, null, 2));
}
