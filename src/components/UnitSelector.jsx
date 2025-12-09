import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Card } from './ui/card'
import { getProgress } from '../utils/progress'
import versionInfo from '../version.json'
import { units } from '../data/units'
import { Bot, CheckCircle, Trophy } from 'lucide-react'

export default function UnitSelector({ onSelect }) {
    const [progress, setProgress] = useState({})

    useEffect(() => {
        setProgress(getProgress())
    }, [])

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-5xl mx-auto">
            {units.map((unit, index) => {
                const unitProgress = progress[unit.id]
                const isCompleted = unitProgress?.completed
                const highScore = unitProgress?.bestPercentage || 0

                return (
                    <motion.div
                        key={unit.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.1 }}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                    >
                        <Card
                            className={`group cursor-pointer h-full border border-white/5 hover:bg-slate-800/80 transition-all duration-300 ${unit.border} relative overflow-hidden`}
                            onClick={() => onSelect(unit.id)}
                        >
                            {/* Progress Background Indicator */}
                            {highScore > 0 && (
                                <div
                                    className="absolute bottom-0 left-0 h-1 bg-gradient-to-r from-cyan-500 to-blue-600 transition-all duration-1000"
                                    style={{ width: `${highScore}%` }}
                                />
                            )}

                            <div className="p-6 flex items-start gap-6">
                                <div className={`p-4 rounded-xl ${unit.bg} ${unit.color} ring-1 ring-white/5 relative`}>
                                    <unit.icon size={32} />
                                    {isCompleted && (
                                        <div className="absolute -top-2 -right-2 bg-slate-950 rounded-full p-0.5 ring-1 ring-slate-800">
                                            <CheckCircle className="w-5 h-5 text-green-400 fill-green-400/20" />
                                        </div>
                                    )}
                                </div>
                                <div className="flex-1">
                                    <div className="flex items-start justify-between mb-2">
                                        <h3 className="text-xl font-bold text-slate-100 group-hover:text-white transition-colors">{unit.title}</h3>
                                        {highScore > 0 && (
                                            <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-slate-900/50 border border-white/5">
                                                <Trophy className="w-3 h-3 text-yellow-500" />
                                                <span className={`text-xs font-bold ${highScore >= 80 ? 'text-green-400' : 'text-slate-400'}`}>
                                                    {highScore}%
                                                </span>
                                            </div>
                                        )}
                                    </div>
                                    <p className="text-slate-400 group-hover:text-slate-300 transition-colors leading-relaxed">{unit.desc}</p>
                                </div>
                            </div>
                        </Card>
                    </motion.div>
                )
            })}
            {/* Version Card */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: units.length * 0.1 }}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
            >
                <Card className="group h-full border border-white/5 bg-slate-900/50 hover:bg-slate-800/80 transition-all duration-300 relative overflow-hidden">
                    <div className="p-6 flex items-start gap-6">
                        <div className="p-4 rounded-xl bg-slate-800 text-slate-400 ring-1 ring-white/5 relative">
                            <Bot size={32} />
                        </div>
                        <div className="flex-1">
                            <div className="flex items-start justify-between mb-2">
                                <h3 className="text-xl font-bold text-slate-100 group-hover:text-white transition-colors">System Version</h3>
                            </div>
                            <div className="space-y-1 text-sm text-slate-400 font-mono">
                                <p>Commit: <span className="text-cyan-400">{versionInfo.commitHash}</span></p>
                                <p>Built: {new Date(versionInfo.buildDate).toLocaleDateString()}</p>
                            </div>
                        </div>
                    </div>
                </Card>
            </motion.div>
        </div>
    )
}
