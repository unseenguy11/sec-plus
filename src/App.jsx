import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ArrowLeft, ShieldCheck, BookOpen, Gamepad2, Keyboard, Shuffle } from 'lucide-react'
import UnitSelector from './components/UnitSelector'
import QuizMode from './components/QuizMode'
import GameMode from './components/GameMode'
import ReviewSetup from './components/ReviewSetup'
import WrittenMode from './components/WrittenMode'
import MixMode from './components/MixMode'
import { Button } from './components/ui/button'

export default function App() {
    const [selectedUnit, setSelectedUnit] = useState(null)
    const [mode, setMode] = useState('quiz') // 'quiz', 'game', 'review-setup', 'review-game'
    const [reviewQuestions, setReviewQuestions] = useState([])

    return (
        <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500/30">
            {/* Header */}
            <header className="sticky top-0 z-50 border-b border-white/5 bg-slate-950/80 backdrop-blur-xl">
                <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        {selectedUnit ? (
                            <Button
                                variant="ghost"
                                size="icon"
                                onClick={() => setSelectedUnit(null)}
                                className="hover:bg-white/5"
                            >
                                <ArrowLeft className="w-5 h-5" />
                            </Button>
                        ) : (
                            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                                <ShieldCheck className="w-6 h-6 text-white" />
                            </div>
                        )}
                        <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-400">
                            {selectedUnit ? (mode === 'quiz' ? 'Quiz Session' : mode === 'written' ? 'Written Challenge' : mode === 'mix' ? 'Mix Challenge' : 'Speed Match') : 'Security+ Master'}
                        </h1>
                    </div>

                    {!selectedUnit && (
                        <div className="flex bg-slate-900/50 p-1 rounded-lg border border-white/5">
                            <button
                                onClick={() => setMode('quiz')}
                                className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${mode === 'quiz' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
                            >
                                <BookOpen size={16} />
                                Study
                            </button>
                            <button
                                onClick={() => setMode('game')}
                                className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${mode === 'game' ? 'bg-purple-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
                            >
                                <Gamepad2 size={16} />
                                Game
                            </button>
                            <button
                                onClick={() => setMode('review-setup')}
                                className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${mode.startsWith('review') ? 'bg-cyan-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
                            >
                                <ShieldCheck size={16} />
                                Review
                            </button>
                            <button
                                onClick={() => setMode('written')}
                                className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${mode === 'written' ? 'bg-emerald-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
                            >
                                <Keyboard size={16} />
                                Written
                            </button>
                            <button
                                onClick={() => setMode('mix')}
                                className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${mode === 'mix' ? 'bg-indigo-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
                            >
                                <Shuffle size={16} />
                                Mix
                            </button>
                        </div>
                    )}
                </div>
            </header>

            {/* Main Content */}
            <main className="p-6">
                <AnimatePresence mode="wait">
                    {mode === 'review-setup' ? (
                        <motion.div
                            key="review-setup"
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                        >
                            <ReviewSetup
                                onStart={(questions) => {
                                    setReviewQuestions(questions)
                                    setMode('review-game')
                                }}
                                onCancel={() => setMode('quiz')}
                            />
                        </motion.div>
                    ) : mode === 'review-game' ? (
                        <motion.div
                            key="review-game"
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                        >
                            <QuizMode
                                customQuestions={reviewQuestions}
                                onComplete={() => setMode('review-setup')}
                            />
                        </motion.div>
                    ) : selectedUnit ? (
                        <motion.div
                            key="mode"
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                        >
                            {mode === 'quiz' ? (
                                <QuizMode unitId={selectedUnit} />
                            ) : mode === 'written' ? (
                                <WrittenMode unitId={selectedUnit} />
                            ) : mode === 'mix' ? (
                                <MixMode unitId={selectedUnit} />
                            ) : (
                                <GameMode unitId={selectedUnit} />
                            )}
                        </motion.div>
                    ) : (
                        <motion.div
                            key="selector"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                        >
                            <div className="text-center mb-12 mt-8">
                                <h2 className="text-4xl md:text-5xl font-bold mb-4 bg-clip-text text-transparent bg-gradient-to-b from-white to-slate-500">
                                    {mode === 'quiz' ? 'Select a Unit to Study' : 'Choose Your Challenge'}
                                </h2>
                                <p className="text-slate-400 text-lg max-w-2xl mx-auto">
                                    {mode === 'quiz'
                                        ? 'Master the Security+ curriculum one unit at a time with our comprehensive question bank.'
                                        : 'Test your reflexes and knowledge in this fast-paced speed matching game.'}
                                </p>
                            </div>
                            <UnitSelector onSelect={setSelectedUnit} />
                        </motion.div>
                    )}
                </AnimatePresence>
            </main>
        </div>
    )
}
