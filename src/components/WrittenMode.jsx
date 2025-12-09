import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { questionsData } from '../data/questions'
import { Card } from './ui/card'
import { Button } from './ui/button'
import { Timer, RefreshCw, AlertCircle, CheckCircle, XCircle, ArrowRight, HelpCircle, Send } from 'lucide-react'
import { cn } from '@/lib/utils'

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

export default function WrittenMode({ unitId }) {
    const [questions, setQuestions] = useState([])
    const [currentIndex, setCurrentIndex] = useState(0)
    const [inputValue, setInputValue] = useState("")
    const [score, setScore] = useState(0)
    const [showResult, setShowResult] = useState(false)
    const [isRandomized, setIsRandomized] = useState(false)
    const [isTimed, setIsTimed] = useState(false)
    const [timeLeft, setTimeLeft] = useState(0)
    const [verificationState, setVerificationState] = useState('input') // 'input', 'verifying', 'feedback'
    const [isCorrect, setIsCorrect] = useState(false)
    const inputRef = useRef(null)

    useEffect(() => {
        if (unitId && questionsData[unitId]) {
            resetQuiz(questionsData[unitId], false)
        }
    }, [unitId])

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

    useEffect(() => {
        if (verificationState === 'input' && inputRef.current) {
            inputRef.current.focus()
        }
    }, [verificationState, currentIndex])

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
        setInputValue("")
        setScore(0)
        setShowResult(false)
        setVerificationState('input')
        setIsCorrect(false)

        if (isTimed) {
            setTimeLeft(qs.length * 60)
        }
    }

    const handleSubmit = (e) => {
        e?.preventDefault()
        if (!inputValue.trim()) return

        const currentQ = questions[currentIndex]
        const correctOption = currentQ.options[currentQ.answer]

        // Check for exact match (case insensitive)
        if (inputValue.trim().toLowerCase() === correctOption.toLowerCase()) {
            setIsCorrect(true)
            setScore(s => s + 1)
            setVerificationState('feedback')
        } else {
            setVerificationState('verifying')
        }
    }

    const handleVerification = (userSaysCorrect) => {
        if (userSaysCorrect) {
            setIsCorrect(true)
            setScore(s => s + 1)
        } else {
            setIsCorrect(false)
        }
        setVerificationState('feedback')
    }

    const nextQuestion = () => {
        if (currentIndex + 1 < questions.length) {
            setCurrentIndex(c => c + 1)
            setInputValue("")
            setVerificationState('input')
            setIsCorrect(false)
        } else {
            setShowResult(true)
        }
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
                            <h2 className="text-4xl font-bold mb-2 text-white">Session Complete!</h2>
                            <p className="text-slate-400 text-lg">Written Mode - Unit: {unitId}</p>
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

                        <Button onClick={() => resetQuiz(questionsData[unitId], isRandomized)} size="lg">
                            <RefreshCw className="mr-2 h-5 w-5" /> Restart Session
                        </Button>
                    </motion.div>
                </Card>
            </div>
        )
    }

    const currentQ = questions[currentIndex]
    const correctOption = currentQ.options[currentQ.answer]

    return (
        <div className="lg:h-[calc(100vh-8rem)] h-auto max-w-4xl mx-auto flex flex-col">
            {/* Top Bar */}
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

            {/* Main Content */}
            <div className="flex-1 flex flex-col gap-6 pb-2">
                {/* Question Card */}
                <Card className="p-8 border-white/10 bg-slate-900/80 backdrop-blur-md min-h-[200px] flex flex-col justify-center">
                    <h3 className="text-2xl md:text-3xl font-medium leading-relaxed text-slate-100 text-center">
                        {currentQ.q}
                    </h3>
                </Card>

                {/* Input Area */}
                <div className="relative">
                    <AnimatePresence mode="wait">
                        {verificationState === 'input' && (
                            <motion.form
                                key="input"
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -20 }}
                                onSubmit={handleSubmit}
                                className="w-full"
                            >
                                <div className="relative">
                                    <input
                                        ref={inputRef}
                                        type="text"
                                        value={inputValue}
                                        onChange={(e) => setInputValue(e.target.value)}
                                        placeholder="Type your answer here..."
                                        className="w-full bg-slate-800/50 border border-white/10 rounded-xl p-6 text-xl text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 transition-all"
                                        autoComplete="off"
                                    />
                                    <Button
                                        type="submit"
                                        size="icon"
                                        className="absolute right-3 top-3 h-12 w-12 bg-cyan-600 hover:bg-cyan-500"
                                        disabled={!inputValue.trim()}
                                    >
                                        <Send className="w-5 h-5" />
                                    </Button>
                                </div>
                            </motion.form>
                        )}

                        {verificationState === 'verifying' && (
                            <motion.div
                                key="verifying"
                                initial={{ opacity: 0, scale: 0.95 }}
                                animate={{ opacity: 1, scale: 1 }}
                                exit={{ opacity: 0, scale: 0.95 }}
                                className="bg-slate-800/90 border border-white/10 rounded-xl p-6 text-center"
                            >
                                <div className="mb-6">
                                    <p className="text-slate-400 text-sm uppercase tracking-wider font-bold mb-2">The Correct Answer Is</p>
                                    <p className="text-2xl font-bold text-white mb-4">{correctOption}</p>
                                    <div className="bg-slate-900/50 rounded-lg p-4 mb-4">
                                        <p className="text-slate-500 text-sm mb-1">You typed:</p>
                                        <p className="text-slate-300 font-mono">{inputValue}</p>
                                    </div>
                                    <p className="text-lg text-cyan-400 font-medium">Did you get it right?</p>
                                </div>
                                <div className="flex justify-center gap-4">
                                    <Button onClick={() => handleVerification(false)} variant="outline" className="w-32 border-red-500/20 hover:bg-red-500/10 hover:text-red-400">
                                        <XCircle className="mr-2 h-4 w-4" /> No
                                    </Button>
                                    <Button onClick={() => handleVerification(true)} className="w-32 bg-green-600 hover:bg-green-500">
                                        <CheckCircle className="mr-2 h-4 w-4" /> Yes
                                    </Button>
                                </div>
                            </motion.div>
                        )}

                        {verificationState === 'feedback' && (
                            <motion.div
                                key="feedback"
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: 20 }}
                                className={cn(
                                    "p-6 rounded-xl border backdrop-blur-md",
                                    isCorrect ? "bg-emerald-500/10 border-emerald-500/20" : "bg-red-500/10 border-red-500/20"
                                )}
                            >
                                <div className="flex items-center gap-3 mb-4">
                                    {isCorrect ? (
                                        <CheckCircle className="w-6 h-6 text-emerald-400" />
                                    ) : (
                                        <XCircle className="w-6 h-6 text-red-400" />
                                    )}
                                    <span className={cn("text-xl font-bold", isCorrect ? "text-emerald-400" : "text-red-400")}>
                                        {isCorrect ? "Correct!" : "Incorrect"}
                                    </span>
                                </div>

                                <div className="mb-6">
                                    <p className="text-sm text-slate-400 mb-1">Correct Answer:</p>
                                    <p className="text-lg font-medium text-white mb-4">{correctOption}</p>
                                    <p className="text-slate-300 leading-relaxed bg-slate-900/40 p-4 rounded-lg border border-white/5">
                                        {currentQ.explanation}
                                    </p>
                                </div>

                                <Button onClick={nextQuestion} className="w-full h-12 text-lg group">
                                    {currentIndex + 1 === questions.length ? "Finish Session" : "Next Question"}
                                    <ArrowRight className="ml-2 h-5 w-5 group-hover:translate-x-1 transition-transform" />
                                </Button>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>
            </div>
        </div>
    )
}
