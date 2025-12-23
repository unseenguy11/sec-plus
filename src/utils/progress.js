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

// Mastery System
const MASTERY_KEY = 'security_plus_mastery_v1';

export const getMasteryProgress = () => {
    try {
        const stored = localStorage.getItem(MASTERY_KEY);
        return stored ? JSON.parse(stored) : {};
    } catch (e) {
        console.error('Failed to load mastery progress:', e);
        return {};
    }
};

export const getQuestionStats = (unitId, questionIndex) => {
    const mastery = getMasteryProgress();
    const unitStats = mastery[unitId] || {};
    return unitStats[questionIndex] || { attempts: 0, correct: 0, incorrect: 0, streak: 0 };
};

export const updateQuestionStats = (unitId, questionIndex, isCorrect) => {
    try {
        const mastery = getMasteryProgress();
        const unitStats = mastery[unitId] || {};
        const currentStats = unitStats[questionIndex] || { attempts: 0, correct: 0, incorrect: 0, streak: 0 };

        let newStreak = currentStats.streak;
        if (isCorrect) {
            newStreak = newStreak >= 0 ? newStreak + 1 : 1;
        } else {
            newStreak = newStreak <= 0 ? newStreak - 1 : -1;
        }

        const newStats = {
            attempts: currentStats.attempts + 1,
            correct: currentStats.correct + (isCorrect ? 1 : 0),
            incorrect: currentStats.incorrect + (isCorrect ? 0 : 1),
            streak: newStreak
        };

        const newMastery = {
            ...mastery,
            [unitId]: {
                ...unitStats,
                [questionIndex]: newStats
            }
        };

        localStorage.setItem(MASTERY_KEY, JSON.stringify(newMastery));
        return newStats;
    } catch (e) {
        console.error('Failed to save mastery stats:', e);
        return null;
    }
};
