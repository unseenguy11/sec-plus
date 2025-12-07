import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { questionsData } from '../data/questions'
import { Card } from './ui/card'
import { Button } from './ui/button'
import { Timer, RefreshCw, AlertCircle, CheckCircle, XCircle, ArrowRight } from 'lucide-react'
import { cn } from '@/lib/utils'
import { saveProgress } from '../utils/progress'

function SimpleSwitch({ checked, onCheckedChange }) {
    return (
        <button
            className={cn(
                "w-10 h-6 rounded-full transition-colors relative focus:outline-none focus:ring-2 focus:ring-cyan-500/50",
                checked ? "bg-cyan-600" : "bg-slate-700"
            )}
            onClick={() => onCheckedChange(!checked)}
        >
            <span
                className={cn(
                    "block w-4 h-4 bg-white rounded-full absolute top-1 transition-transform shadow-sm",
                    checked ? "left-5" : "left-1"
                )}
            />
        </button>
    )
}

export default function QuizMode({ unitId }) {
    const [questions, setQuestions] = useState([])
    const [currentIndex, setCurrentIndex] = useState(0)
    const [selectedOption, setSelectedOption] = useState(null)
    const [score, setScore] = useState(0)
    const [showResult, setShowResult] = useState(false)
    const [isRandomized, setIsRandomized] = useState(false)
    const [isTimed, setIsTimed] = useState(false)
    const [timeLeft, setTimeLeft] = useState(0)
    const [missedQuestions, setMissedQuestions] = useState([])
    const [isReviewMode, setIsReviewMode] = useState(false)

    useEffect(() => {
        if (unitId && questionsData[unitId]) {
            resetQuiz(questionsData[unitId], false)
        }
    }, [unitId])

    useEffect(() => {
        if (showResult && !isReviewMode && questions.length > 0) {
            saveProgress(unitId, score, questions.length)
        }
    }, [showResult, isReviewMode, unitId, score, questions.length])

    useEffect(() => {
        if (isTimed && timeLeft > 0 && !showResult) {
            const timer = setInterval(() => {
                setTimeLeft((prev) => {
                    if (prev <= 1) {
                        clearInterval(timer)
                        setShowResult(true)
                        return 0
                    }
                    return prev - 1
                })
            }, 1000)
            return () => clearInterval(timer)
        }
    }, [isTimed, timeLeft, showResult])

    const shuffleArray = (array) => {
        const newArray = [...array]
        for (let i = newArray.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1))
                ;[newArray[i], newArray[j]] = [newArray[j], newArray[i]]
        }
        return newArray
    }

    const resetQuiz = (baseQuestions = questionsData[unitId], randomize = isRandomized) => {
        let qs = [...baseQuestions]
        if (randomize) {
            qs = shuffleArray(qs)
        }
        setQuestions(qs)
        setCurrentIndex(0)
        setSelectedOption(null)
        setScore(0)
        setShowResult(false)
        setMissedQuestions([])
        setIsReviewMode(false)

        if (isTimed) {
            setTimeLeft(qs.length * 60)
        }
    }

    const handleAnswer = (optionIndex) => {
        setSelectedOption(optionIndex)
        const currentQ = questions[currentIndex]

        if (optionIndex === currentQ.answer) {
            setScore(s => s + 1)
        } else {
            if (!isReviewMode) {
                setMissedQuestions(prev => [...prev, currentQ])
            }
        }
    }

    const nextQuestion = () => {
        if (currentIndex + 1 < questions.length) {
            setCurrentIndex(c => c + 1)
            setSelectedOption(null)
        } else {
            setShowResult(true)
        }
    }

    const startReview = () => {
        setQuestions(missedQuestions)
        setCurrentIndex(0)
        setSelectedOption(null)
        setScore(0)
        setShowResult(false)
        setIsReviewMode(true)
        setIsTimed(false)
    }

    if (!questions.length) return <div className="text-center p-10 text-slate-400">Loading questions...</div>

    if (showResult) {
        const percentage = Math.round((score / questions.length) * 100)
        return (
            <div className="max-w-2xl mx-auto px-6 py-10">
                <Card className="text-center p-10 border-white/10 bg-slate-900/80 backdrop-blur-xl">
                    <motion.div
                        initial={{ scale: 0.9, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                    >
                        <div className="mb-8">
                            {percentage >= 80 ? (
                                <div className="w-24 h-24 rounded-full bg-green-500/20 flex items-center justify-center mx-auto mb-6 ring-1 ring-green-500/50">
                                    <CheckCircle className="w-12 h-12 text-green-400" />
                                </div>
                            ) : (
                                <div className="w-24 h-24 rounded-full bg-yellow-500/20 flex items-center justify-center mx-auto mb-6 ring-1 ring-yellow-500/50">
                                    <AlertCircle className="w-12 h-12 text-yellow-400" />
                                </div>
                            )}
                            <h2 className="text-4xl font-bold mb-2 text-white">Quiz Complete!</h2>
                            <p className="text-slate-400 text-lg">
                                {isReviewMode ? 'Review Session' : `Unit: ${unitId}`}
                            </p>
                        </div>

                        <div className="grid grid-cols-2 gap-6 mb-10">
                            <div className="p-6 bg-slate-800/50 rounded-2xl border border-white/5">
                                <p className="text-sm text-slate-400 uppercase font-bold tracking-wider mb-1">Score</p>
                                <p className="text-4xl font-bold text-cyan-400">{score} <span className="text-lg text-slate-500">/ {questions.length}</span></p>
                            </div>
                            <div className="p-6 bg-slate-800/50 rounded-2xl border border-white/5">
                                <p className="text-sm text-slate-400 uppercase font-bold tracking-wider mb-1">Percentage</p>
                                <p className={cn("text-4xl font-bold", percentage >= 80 ? "text-green-400" : "text-yellow-400")}>
                                    {percentage}%
                                </p>
                            </div>
                        </div>

                        <div className="flex flex-col sm:flex-row justify-center gap-4">
                            <Button onClick={() => resetQuiz(questionsData[unitId], isRandomized)} size="lg" className="w-full sm:w-auto">
                                <RefreshCw className="mr-2 h-5 w-5" /> Restart Quiz
                            </Button>
                            {missedQuestions.length > 0 && !isReviewMode && (
                                <Button onClick={startReview} variant="outline" size="lg" className="w-full sm:w-auto">
                                    Review Missed ({missedQuestions.length})
                                </Button>
                            )}
                        </div>
                    </motion.div>
                </Card>
            </div>
        )
    }

    const currentQ = questions[currentIndex]

    return (
        <div className="lg:h-[calc(100vh-8rem)] h-auto max-w-7xl mx-auto flex flex-col">
            {/* Top Bar: Progress & Controls */}
            <div className="flex-none mb-4 px-2">
                <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-4">
                        <div className="flex items-center gap-2">
                            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Random</span>
                            <SimpleSwitch checked={isRandomized} onCheckedChange={(c) => { setIsRandomized(c); resetQuiz(questionsData[unitId], c); }} />
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Timer</span>
                            <SimpleSwitch checked={isTimed} onCheckedChange={(c) => { setIsTimed(c); if (c) setTimeLeft(questions.length * 60); }} />
                        </div>
                    </div>

                    <div className="flex items-center gap-4">
                        {isTimed && (
                            <div className={cn("font-mono font-bold", timeLeft < 60 ? "text-red-400" : "text-cyan-400")}>
                                {Math.floor(timeLeft / 60)}:{(timeLeft % 60).toString().padStart(2, '0')}
                            </div>
                        )}
                        <div className="text-sm font-medium text-slate-400">
                            {currentIndex + 1} <span className="text-slate-600">/ {questions.length}</span>
                        </div>
                    </div>
                </div>

                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <motion.div
                        className="h-full bg-gradient-to-r from-cyan-500 to-blue-600"
                        animate={{ width: `${((currentIndex) / questions.length) * 100}%` }}
                        transition={{ type: "spring", stiffness: 50 }}
                    />
                </div>
            </div>

            {/* Main Content Area - Split View */}
            <div className="flex-1 lg:min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-6 pb-2">
                {/* Left Column: Question */}
                <div className="lg:col-span-7 flex flex-col lg:min-h-0">
                    <AnimatePresence mode="wait">
                        <motion.div
                            key={currentIndex}
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -10 }}
                            transition={{ duration: 0.2 }}
                            className="lg:h-full"
                        >
                            <Card className="lg:h-full h-auto p-6 md:p-8 border-white/10 bg-slate-900/80 backdrop-blur-md flex flex-col justify-center lg:overflow-y-auto custom-scrollbar">
                                <h3 className="text-xl md:text-3xl font-medium leading-relaxed text-slate-100">
                                    {currentQ.q}
                                </h3>
                            </Card>
                        </motion.div>
                    </AnimatePresence>
                </div>

                {/* Right Column: Options & Feedback */}
                <div className="lg:col-span-5 flex flex-col lg:min-h-0 gap-4">
                    <div className="lg:flex-1 lg:overflow-y-auto custom-scrollbar pr-2 space-y-3">
                        {currentQ.options.map((option, idx) => {
                            let variant = "outline"
                            let extraClasses = "hover:border-cyan-500/50 hover:bg-slate-800"

                            if (selectedOption !== null) {
                                extraClasses = "opacity-50"
                                if (idx === currentQ.answer) {
                                    variant = "success"
                                    extraClasses = "opacity-100 ring-1 ring-emerald-500/50 bg-emerald-500/10"
                                }
                                else if (idx === selectedOption) {
                                    variant = "destructive"
                                    extraClasses = "opacity-100 ring-1 ring-red-500/50 bg-red-500/10"
                                }
                            }

                            return (
                                <Button
                                    key={idx}
                                    variant={variant}
                                    className={cn(
                                        "w-full justify-start text-left h-auto py-4 px-5 text-base whitespace-normal transition-all duration-200 border-white/10 bg-slate-800/40",
                                        extraClasses
                                    )}
                                    onClick={() => handleAnswer(idx)}
                                    disabled={selectedOption !== null}
                                >
                                    <div className="flex items-start gap-3">
                                        <span className={cn(
                                            "flex-shrink-0 w-6 h-6 rounded flex items-center justify-center text-xs font-bold border mt-0.5",
                                            selectedOption === null ? "bg-slate-800 border-white/10 text-slate-400" :
                                                idx === currentQ.answer ? "bg-emerald-500 border-emerald-400 text-white" :
                                                    idx === selectedOption ? "bg-red-500 border-red-400 text-white" : "bg-slate-800 border-white/10 text-slate-500"
                                        )}>
                                            {String.fromCharCode(65 + idx)}
                                        </span>
                                        <span className="leading-snug">{option}</span>
                                    </div>
                                </Button>
                            )
                        })}
                    </div>

                    {/* Feedback Area (Fixed at bottom of right col) */}
                    <div className={cn("flex-none transition-all duration-300 ease-in-out", selectedOption !== null ? "min-h-[140px]" : "min-h-0")}>
                        <AnimatePresence mode="wait">
                            {selectedOption !== null && (
                                <motion.div
                                    initial={{ opacity: 0, y: 20 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    exit={{ opacity: 0, y: 20 }}
                                    className={cn(
                                        "h-full p-5 rounded-xl border backdrop-blur-md flex flex-col",
                                        selectedOption === currentQ.answer ? "bg-emerald-500/10 border-emerald-500/20" : "bg-red-500/10 border-red-500/20"
                                    )}
                                >
                                    <div className="flex items-center gap-3 mb-2">
                                        {selectedOption === currentQ.answer ? (
                                            <CheckCircle className="w-5 h-5 text-emerald-400" />
                                        ) : (
                                            <XCircle className="w-5 h-5 text-red-400" />
                                        )}
                                        <span className={cn("font-bold", selectedOption === currentQ.answer ? "text-emerald-400" : "text-red-400")}>
                                            {selectedOption === currentQ.answer ? "Correct" : "Incorrect"}
                                        </span>
                                    </div>

                                    <div className="flex-1 overflow-y-auto custom-scrollbar mb-3">
                                        <p className="text-sm text-slate-300 leading-relaxed">{currentQ.explanation}</p>
                                    </div>

                                    <Button onClick={nextQuestion} className="w-full group">
                                        {currentIndex + 1 === questions.length ? "Finish Quiz" : "Next Question"}
                                        <ArrowRight className="ml-2 h-4 w-4 group-hover:translate-x-1 transition-transform" />
                                    </Button>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>
                </div>
            </div>
        </div>
    )
}
