import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { questionsData } from '../data/questions'
import { Card } from './ui/card'
import { Button } from './ui/button'
import { Timer, RefreshCw, AlertCircle, CheckCircle, XCircle, ArrowRight, Send, Shuffle } from 'lucide-react'
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

export default function MixMode({ unitId }) {
    const [questions, setQuestions] = useState([])
    const [currentIndex, setCurrentIndex] = useState(0)
    const [stage, setStage] = useState('mc') // 'mc' or 'written'

    // MC State
    const [mcSelectedOption, setMcSelectedOption] = useState(null)

    // Written State
    const [writtenInputValue, setWrittenInputValue] = useState("")
    const [verificationState, setVerificationState] = useState('input') // 'input', 'verifying', 'feedback'
    const [isWrittenCorrect, setIsWrittenCorrect] = useState(false)
    const inputRef = useRef(null)

    // Shared State
    const [score, setScore] = useState(0)
    const [showResult, setShowResult] = useState(false)
    const [isRandomized, setIsRandomized] = useState(false)
    const [isTimed, setIsTimed] = useState(false)
    const [timeLeft, setTimeLeft] = useState(0)

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
        if (stage === 'written' && verificationState === 'input' && inputRef.current) {
            inputRef.current.focus()
        }
    }, [stage, verificationState, currentIndex])

    const shuffleArray = (array) => {
        const newArray = [...array]
        for (let i = newArray.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1))
                ;[newArray[i], newArray[j]] = [newArray[j], newArray[i]]
        }
        return newArray
    }

    const resetQuiz = (baseQuestions = questionsData[unitId], randomize = isRandomized) => {
        // Deep copy and shuffle options for each question (for MC part)
        let qs = baseQuestions.map(q => {
            const optionsWithIndex = q.options.map((opt, i) => ({ opt, originalIndex: i }))
            const shuffledOptionsWithIndex = shuffleArray(optionsWithIndex)
            return {
                ...q,
                options: shuffledOptionsWithIndex.map(o => o.opt),
                answer: shuffledOptionsWithIndex.findIndex(o => o.originalIndex === q.answer)
            }
        })

        if (randomize) {
            qs = shuffleArray(qs)
        }
        setQuestions(qs)
        setCurrentIndex(0)
        setStage('mc')
        setMcSelectedOption(null)
        setWrittenInputValue("")
        setVerificationState('input')
        setScore(0)
        setShowResult(false)

        if (isTimed) {
            setTimeLeft(qs.length * 60)
        }
    }

    // MC Handlers
    const handleMCAnswer = (optionIndex) => {
        setMcSelectedOption(optionIndex)
        const currentQ = questions[currentIndex]
        if (optionIndex === currentQ.answer) {
            setScore(s => s + 1)
        }
    }

    const continueToWritten = () => {
        setStage('written')
        setWrittenInputValue("")
        setVerificationState('input')
        setIsWrittenCorrect(false)
    }

    // Written Handlers
    const handleWrittenSubmit = (e) => {
        e?.preventDefault()
        if (!writtenInputValue.trim()) return

        const currentQ = questions[currentIndex]
        const correctOption = currentQ.options[currentQ.answer]

        if (writtenInputValue.trim().toLowerCase() === correctOption.toLowerCase()) {
            setIsWrittenCorrect(true)
            setScore(s => s + 1)
            setVerificationState('feedback')
        } else {
            setVerificationState('verifying')
        }
    }

    const handleVerification = (userSaysCorrect) => {
        if (userSaysCorrect) {
            setIsWrittenCorrect(true)
            setScore(s => s + 1)
        } else {
            setIsWrittenCorrect(false)
        }
        setVerificationState('feedback')
    }

    const nextQuestion = () => {
        if (currentIndex + 1 < questions.length) {
            setCurrentIndex(c => c + 1)
            setStage('mc')
            setMcSelectedOption(null)
        } else {
            setShowResult(true)
        }
    }

    if (!questions.length) return <div className="text-center p-10 text-slate-400">Loading questions...</div>

    if (showResult) {
        const totalPoints = questions.length * 2
        const percentage = Math.round((score / totalPoints) * 100)
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
                            <p className="text-slate-400 text-lg">Mix Mode - Unit: {unitId}</p>
                        </div>

                        <div className="grid grid-cols-2 gap-6 mb-10">
                            <div className="p-6 bg-slate-800/50 rounded-2xl border border-white/5">
                                <p className="text-sm text-slate-400 uppercase font-bold tracking-wider mb-1">Score</p>
                                <p className="text-4xl font-bold text-cyan-400">{score} <span className="text-lg text-slate-500">/ {totalPoints}</span></p>
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
        <div className="lg:h-[calc(100vh-8rem)] h-auto max-w-7xl mx-auto flex flex-col">
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
                        <div className="px-3 py-1 rounded-full bg-slate-800 border border-white/10 text-xs font-bold uppercase tracking-wider text-cyan-400">
                            {stage === 'mc' ? 'Stage 1: Recognition' : 'Stage 2: Recall'}
                        </div>
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
            <div className="flex-1 lg:min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-6 pb-2">
                {/* Left Column: Question */}
                <div className="lg:col-span-7 flex flex-col lg:min-h-0">
                    <AnimatePresence mode="wait">
                        <motion.div
                            key={`${currentIndex}-${stage}`}
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

                {/* Right Column: Interaction */}
                <div className="lg:col-span-5 flex flex-col lg:min-h-0 gap-4">
                    <AnimatePresence mode="wait">
                        {stage === 'mc' ? (
                            <motion.div
                                key="mc-options"
                                initial={{ opacity: 0, x: 20 }}
                                animate={{ opacity: 1, x: 0 }}
                                exit={{ opacity: 0, x: -20 }}
                                className="flex flex-col h-full gap-4"
                            >
                                <div className="lg:flex-1 lg:overflow-y-auto custom-scrollbar pr-2 space-y-3">
                                    {currentQ.options.map((option, idx) => {
                                        let variant = "outline"
                                        let extraClasses = "hover:border-cyan-500/50 hover:bg-slate-800"

                                        if (mcSelectedOption !== null) {
                                            extraClasses = "opacity-50"
                                            if (idx === currentQ.answer) {
                                                variant = "success"
                                                extraClasses = "opacity-100 ring-1 ring-emerald-500/50 bg-emerald-500/10"
                                            }
                                            else if (idx === mcSelectedOption) {
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
                                                onClick={() => handleMCAnswer(idx)}
                                                disabled={mcSelectedOption !== null}
                                            >
                                                <div className="flex items-start gap-3">
                                                    <span className={cn(
                                                        "flex-shrink-0 w-6 h-6 rounded flex items-center justify-center text-xs font-bold border mt-0.5",
                                                        mcSelectedOption === null ? "bg-slate-800 border-white/10 text-slate-400" :
                                                            idx === currentQ.answer ? "bg-emerald-500 border-emerald-400 text-white" :
                                                                idx === mcSelectedOption ? "bg-red-500 border-red-400 text-white" : "bg-slate-800 border-white/10 text-slate-500"
                                                    )}>
                                                        {String.fromCharCode(65 + idx)}
                                                    </span>
                                                    <span className="leading-snug">{option}</span>
                                                </div>
                                            </Button>
                                        )
                                    })}
                                </div>

                                {mcSelectedOption !== null && (
                                    <motion.div
                                        initial={{ opacity: 0, y: 20 }}
                                        animate={{ opacity: 1, y: 0 }}
                                        className="flex-none"
                                    >
                                        <Button onClick={continueToWritten} className="w-full h-12 text-lg group bg-cyan-600 hover:bg-cyan-500">
                                            Continue to Stage 2
                                            <ArrowRight className="ml-2 h-5 w-5 group-hover:translate-x-1 transition-transform" />
                                        </Button>
                                    </motion.div>
                                )}
                            </motion.div>
                        ) : (
                            <motion.div
                                key="written-input"
                                initial={{ opacity: 0, x: 20 }}
                                animate={{ opacity: 1, x: 0 }}
                                exit={{ opacity: 0, x: -20 }}
                                className="flex flex-col h-full gap-4"
                            >
                                <div className="flex-1 flex flex-col justify-center">
                                    {verificationState === 'input' && (
                                        <form onSubmit={handleWrittenSubmit} className="w-full">
                                            <div className="relative">
                                                <input
                                                    ref={inputRef}
                                                    type="text"
                                                    value={writtenInputValue}
                                                    onChange={(e) => setWrittenInputValue(e.target.value)}
                                                    placeholder="Type the answer from memory..."
                                                    className="w-full bg-slate-800/50 border border-white/10 rounded-xl p-6 text-xl text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 transition-all"
                                                    autoComplete="off"
                                                />
                                                <Button
                                                    type="submit"
                                                    size="icon"
                                                    className="absolute right-3 top-3 h-12 w-12 bg-cyan-600 hover:bg-cyan-500"
                                                    disabled={!writtenInputValue.trim()}
                                                >
                                                    <Send className="w-5 h-5" />
                                                </Button>
                                            </div>
                                        </form>
                                    )}

                                    {verificationState === 'verifying' && (
                                        <div className="bg-slate-800/90 border border-white/10 rounded-xl p-6 text-center">
                                            <div className="mb-6">
                                                <p className="text-slate-400 text-sm uppercase tracking-wider font-bold mb-2">The Correct Answer Is</p>
                                                <p className="text-2xl font-bold text-white mb-4">{correctOption}</p>
                                                <div className="bg-slate-900/50 rounded-lg p-4 mb-4">
                                                    <p className="text-slate-500 text-sm mb-1">You typed:</p>
                                                    <p className="text-slate-300 font-mono">{writtenInputValue}</p>
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
                                        </div>
                                    )}

                                    {verificationState === 'feedback' && (
                                        <div className={cn(
                                            "p-6 rounded-xl border backdrop-blur-md",
                                            isWrittenCorrect ? "bg-emerald-500/10 border-emerald-500/20" : "bg-red-500/10 border-red-500/20"
                                        )}>
                                            <div className="flex items-center gap-3 mb-4">
                                                {isWrittenCorrect ? (
                                                    <CheckCircle className="w-6 h-6 text-emerald-400" />
                                                ) : (
                                                    <XCircle className="w-6 h-6 text-red-400" />
                                                )}
                                                <span className={cn("text-xl font-bold", isWrittenCorrect ? "text-emerald-400" : "text-red-400")}>
                                                    {isWrittenCorrect ? "Correct!" : "Incorrect"}
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
                                        </div>
                                    )}
                                </div>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>
            </div>
        </div>
    )
}
