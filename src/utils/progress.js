const STORAGE_KEY = 'security_plus_progress_v1';

export const getProgress = () => {
    try {
        const stored = localStorage.getItem(STORAGE_KEY);
        return stored ? JSON.parse(stored) : {};
    } catch (e) {
        console.error('Failed to load progress:', e);
        return {};
    }
};

export const saveProgress = (unitId, score, totalQuestions) => {
    try {
        const currentProgress = getProgress();
        const unitProgress = currentProgress[unitId] || {
            highScore: 0,
            attempts: 0,
            completed: false,
            bestPercentage: 0
        };

        const percentage = Math.round((score / totalQuestions) * 100);

        const newProgress = {
            ...currentProgress,
            [unitId]: {
                highScore: Math.max(unitProgress.highScore, score),
                bestPercentage: Math.max(unitProgress.bestPercentage || 0, percentage),
                attempts: unitProgress.attempts + 1,
                completed: unitProgress.completed || percentage >= 80, // Mark as completed if passed (80%+)
                lastPlayed: new Date().toISOString()
            }
        };

        localStorage.setItem(STORAGE_KEY, JSON.stringify(newProgress));
        return newProgress[unitId];
    } catch (e) {
        console.error('Failed to save progress:', e);
        return null;
    }
};

export const getUnitProgress = (unitId) => {
    const progress = getProgress();
    return progress[unitId] || null;
};
