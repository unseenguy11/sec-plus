import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Card } from './ui/card'
import { Button } from './ui/button'
import { CheckCircle, AlertCircle, Play, Check, X } from 'lucide-react'
import { units } from '../data/units'
import { getProgress } from '../utils/progress'
import { questionsData } from '../data/questions'

export default function ReviewSetup({ onStart, onCancel }) {
    const [completedUnits, setCompletedUnits] = useState([])
    const [selectedUnits, setSelectedUnits] = useState([])
    const [questionCount, setQuestionCount] = useState(20)
    const [error, setError] = useState(null)

    useEffect(() => {
        const progress = getProgress()
        const completed = units.filter(unit => {
            const unitProgress = progress[unit.id]
            return unitProgress?.completed
        }).map(u => u.id)

        setCompletedUnits(completed)
        // Auto-select all completed units by default
        setSelectedUnits(completed)
    }, [])

    const toggleUnit = (unitId) => {
        setSelectedUnits(prev =>
            prev.includes(unitId)
                ? prev.filter(id => id !== unitId)
                : [...prev, unitId]
        )
        setError(null)
    }

    const handleStart = () => {
        if (selectedUnits.length === 0) {
            setError("Please select at least one unit.")
            return
        }

        // Aggregate questions
        let pool = []
        selectedUnits.forEach(unitId => {
            if (questionsData[unitId]) {
                pool = [...pool, ...questionsData[unitId]]
            }
        })

        if (pool.length === 0) {
            setError("No questions found for selected units.")
            return
        }

        // Shuffle pool
        for (let i = pool.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [pool[i], pool[j]] = [pool[j], pool[i]];
        }

        // Slice to requested count
        const finalQuestions = pool.slice(0, Math.min(questionCount, pool.length))

        onStart(finalQuestions)
    }

    return (
        <div className="max-w-4xl mx-auto p-6">
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
            >
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h2 className="text-3xl font-bold text-white mb-2">Recurring Review</h2>
                        <p className="text-slate-400">Select completed units to practice random questions.</p>
                    </div>
                    <Button variant="ghost" onClick={onCancel}>
                        <X className="mr-2 h-4 w-4" /> Cancel
                    </Button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                    {/* Left Col: Settings */}
                    <div className="md:col-span-1 space-y-6">
                        <Card className="p-6 bg-slate-900/50 border-white/10">
                            <h3 className="text-lg font-bold text-white mb-4">Settings</h3>

                            <div className="space-y-4">
                                <div>
                                    <label className="block text-sm text-slate-400 mb-2">Number of Questions</label>
                                    <div className="flex items-center gap-2">
                                        {[10, 20, 30, 50].map(count => (
                                            <button
                                                key={count}
                                                onClick={() => setQuestionCount(count)}
                                                className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${questionCount === count
                                                        ? 'bg-cyan-500 text-white'
                                                        : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                                                    }`}
                                            >
                                                {count}
                                            </button>
                                        ))}
                                    </div>
                                </div>

                                <div className="pt-4 border-t border-white/5">
                                    <div className="flex justify-between text-sm mb-2">
                                        <span className="text-slate-400">Selected Units:</span>
                                        <span className="text-white font-bold">{selectedUnits.length}</span>
                                    </div>
                                    <div className="flex justify-between text-sm">
                                        <span className="text-slate-400">Pool Size:</span>
                                        <span className="text-white font-bold">
                                            {selectedUnits.reduce((acc, uid) => acc + (questionsData[uid]?.length || 0), 0)}
                                        </span>
                                    </div>
                                </div>

                                {error && (
                                    <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg flex items-start gap-2 text-red-400 text-sm">
                                        <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                                        {error}
                                    </div>
                                )}

                                <Button onClick={handleStart} className="w-full bg-cyan-600 hover:bg-cyan-500 text-white">
                                    <Play className="mr-2 h-4 w-4" /> Start Review
                                </Button>
                            </div>
                        </Card>
                    </div>

                    {/* Right Col: Unit Selection */}
                    <div className="md:col-span-2">
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            {units.map(unit => {
                                const isCompleted = completedUnits.includes(unit.id)
                                const isSelected = selectedUnits.includes(unit.id)

                                return (
                                    <div
                                        key={unit.id}
                                        onClick={() => isCompleted && toggleUnit(unit.id)}
                                        className={`
                                            relative p-4 rounded-xl border transition-all duration-200 flex items-start gap-3
                                            ${!isCompleted
                                                ? 'opacity-50 cursor-not-allowed border-white/5 bg-slate-900/20 grayscale'
                                                : 'cursor-pointer hover:bg-slate-800/50'
                                            }
                                            ${isSelected
                                                ? 'bg-cyan-500/10 border-cyan-500/50'
                                                : 'bg-slate-900/40 border-white/5'
                                            }
                                        `}
                                    >
                                        <div className={`p-2 rounded-lg ${unit.bg} ${unit.color}`}>
                                            <unit.icon size={18} />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <h4 className={`text-sm font-bold truncate ${isSelected ? 'text-cyan-400' : 'text-slate-300'}`}>
                                                {unit.title}
                                            </h4>
                                            <p className="text-xs text-slate-500 truncate">{unit.desc}</p>
                                        </div>
                                        {isSelected && (
                                            <div className="absolute top-2 right-2">
                                                <CheckCircle className="w-4 h-4 text-cyan-500" />
                                            </div>
                                        )}
                                        {!isCompleted && (
                                            <div className="absolute inset-0 flex items-center justify-center bg-slate-950/60 rounded-xl backdrop-blur-[1px]">
                                                <span className="text-xs font-bold text-slate-500 bg-slate-900 px-2 py-1 rounded border border-white/5">Locked</span>
                                            </div>
                                        )}
                                    </div>
                                )
                            })}
                        </div>
                    </div>
                </div>
            </motion.div>
        </div>
    )
}
