import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { questionsData } from '../data/questions'
import { Card } from './ui/card'
import { Button } from './ui/button'
import { Timer, Zap, Trophy, Flame } from 'lucide-react'
import { cn } from '@/lib/utils'

export default function GameMode({ unitId }) {
    const [gameState, setGameState] = useState('intro') // intro, playing, gameover
    const [score, setScore] = useState(0)
    const [timeLeft, setTimeLeft] = useState(60)
    const [streak, setStreak] = useState(0)
    const [currentQuestion, setCurrentQuestion] = useState(null)
    const [shuffledOptions, setShuffledOptions] = useState([])

    const timerRef = useRef(null)

    useEffect(() => {
        if (gameState === 'playing') {
            timerRef.current = setInterval(() => {
                setTimeLeft(prev => {
                    if (prev <= 0.1) {
                        endGame()
                        return 0
                    }
                    return prev - 0.1
                })
            }, 100)
        }
        return () => clearInterval(timerRef.current)
    }, [gameState])

    const startGame = () => {
        setScore(0)
        setStreak(0)
        setTimeLeft(60)
        setGameState('playing')
        nextQuestion()
    }

    const endGame = () => {
        clearInterval(timerRef.current)
        setGameState('gameover')
    }

    const nextQuestion = () => {
        const unitQuestions = questionsData[unitId]
        const randomQ = unitQuestions[Math.floor(Math.random() * unitQuestions.length)]

        const options = randomQ.options.map((opt, i) => ({ text: opt, originalIndex: i }))
        for (let i = options.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1))
                ;[options[i], options[j]] = [options[j], options[i]]
        }

        setCurrentQuestion(randomQ)
        setShuffledOptions(options)
    }

    const handleAnswer = (originalIndex) => {
        if (originalIndex === currentQuestion.answer) {
            const timeBonus = Math.min(5, 2 + Math.floor(streak / 5))
            setTimeLeft(prev => Math.min(prev + timeBonus, 60))
            setScore(prev => prev + 10 + (streak * 2))
            setStreak(prev => prev + 1)
            nextQuestion()
        } else {
            setTimeLeft(prev => Math.max(prev - 5, 0))
            setStreak(0)
        }
    }

    if (gameState === 'intro') {
        return (
            <div className="max-w-md mx-auto px-6 text-center pt-10">
                <motion.div
                    initial={{ scale: 0.8, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                >
                    <div className="bg-purple-500/20 w-24 h-24 rounded-full flex items-center justify-center mx-auto mb-8 ring-1 ring-purple-500/50 shadow-[0_0_30px_rgba(168,85,247,0.3)]">
                        <Zap size={48} className="text-purple-400" />
                    </div>
                    <h2 className="text-4xl font-bold mb-4 text-white">Speed Match</h2>
                    <p className="text-slate-400 mb-10 text-lg leading-relaxed">
                        Race against the clock! Correct answers add time, wrong answers subtract it. Build your streak for massive points.
                    </p>
                    <Button size="lg" className="w-full text-lg h-16 bg-purple-600 hover:bg-purple-500 shadow-lg shadow-purple-900/40" onClick={startGame}>
                        Start Game
                    </Button>
                </motion.div>
            </div>
        )
    }

    if (gameState === 'gameover') {
        return (
            <div className="max-w-md mx-auto px-6 text-center pt-10">
                <Card className="p-10 border-white/10 bg-slate-900/80">
                    <Trophy className="w-24 h-24 text-yellow-400 mx-auto mb-6 drop-shadow-[0_0_15px_rgba(250,204,21,0.5)]" />
                    <h2 className="text-4xl font-bold mb-2 text-white">Time's Up!</h2>
                    <p className="text-slate-400 mb-8 text-lg">Great effort!</p>

                    <div className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400 mb-10">
                        {score}
                    </div>

                    <Button size="lg" className="w-full mb-4 h-14 text-lg bg-purple-600 hover:bg-purple-500" onClick={startGame}>
                        Play Again
                    </Button>
                    <Button variant="outline" className="w-full h-12" onClick={() => setGameState('intro')}>
                        Back to Menu
                    </Button>
                </Card>
            </div>
        )
    }

    return (
        <div className="max-w-4xl mx-auto px-6">
            {/* HUD */}
            <div className="flex justify-between items-center mb-8 bg-slate-900/60 p-5 rounded-2xl border border-white/10 backdrop-blur-md shadow-lg">
                <div className="flex items-center gap-8">
                    <div className="text-center">
                        <p className="text-xs text-slate-500 font-bold uppercase tracking-wider mb-1">Score</p>
                        <p className="text-3xl font-bold text-purple-400">{score}</p>
                    </div>
                    <div className="text-center px-8 border-l border-white/10">
                        <p className="text-xs text-slate-500 font-bold uppercase flex items-center gap-1 mb-1 justify-center">
                            <Flame size={14} className={streak > 2 ? "text-orange-500 fill-orange-500" : "text-slate-600"} /> Streak
                        </p>
                        <p className={cn("text-3xl font-bold transition-all", streak > 2 ? "text-orange-500 scale-110" : "text-slate-500")}>
                            {streak}
                        </p>
                    </div>
                </div>

                <div className="flex items-center gap-4">
                    <Timer className={cn("w-6 h-6", timeLeft < 10 ? "text-red-500 animate-pulse" : "text-slate-400")} />
                    <div className="w-48 h-4 bg-slate-800 rounded-full overflow-hidden border border-white/5">
                        <motion.div
                            className={cn("h-full shadow-[0_0_10px_currentColor]", timeLeft < 10 ? "bg-red-500 text-red-500" : "bg-purple-500 text-purple-500")}
                            animate={{ width: `${(timeLeft / 60) * 100}%` }}
                            transition={{ ease: "linear", duration: 0.1 }}
                        />
                    </div>
                </div>
            </div>

            {/* Game Area */}
            <AnimatePresence mode="popLayout">
                <motion.div
                    key={currentQuestion.q}
                    initial={{ scale: 0.9, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    exit={{ scale: 1.1, opacity: 0 }}
                    transition={{ duration: 0.15 }}
                >
                    <Card className="p-10 mb-8 text-center min-h-[240px] flex items-center justify-center border-white/10 bg-slate-900/80 shadow-2xl">
                        <h3 className="text-3xl font-medium leading-relaxed text-slate-100">
                            {currentQuestion.q}
                        </h3>
                    </Card>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                        {shuffledOptions.map((opt, i) => (
                            <motion.button
                                key={i}
                                whileHover={{ scale: 1.02 }}
                                whileTap={{ scale: 0.98 }}
                                className="p-6 bg-slate-800/50 border border-white/10 rounded-xl hover:border-purple-500/50 hover:bg-purple-500/10 transition-all text-left font-medium text-lg shadow-lg text-slate-200 hover:text-white hover:shadow-purple-900/20"
                                onClick={() => handleAnswer(opt.originalIndex)}
                            >
                                {opt.text}
                            </motion.button>
                        ))}
                    </div>
                </motion.div>
            </AnimatePresence>
        </div>
    )
}
