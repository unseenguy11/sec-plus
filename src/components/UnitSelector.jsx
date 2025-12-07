import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { BookOpen, Shield, Lock, Server, Database, Key, AlertTriangle, Scale, RefreshCw, ClipboardCheck, Network, Activity, ShieldCheck, Wifi, Scan, Bell, Siren, Users, Bug, Truck, BrickWall, UserCheck, Zap, Search, Bot, GraduationCap, CheckCircle, Trophy } from 'lucide-react';
import { Card } from './ui/card'
import { getProgress } from '../utils/progress'

const units = [
    { id: 'unit-2', title: 'Unit 2: Security Fundamentals', icon: Shield, color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'group-hover:border-blue-500/50', desc: 'CIA Triad, Risk Management, AAA' },
    { id: 'unit-3', title: 'Unit 3: Threats & Vulnerabilities', icon: Users, color: 'text-red-400', bg: 'bg-red-500/10', border: 'group-hover:border-red-500/50', desc: 'Threat Actors, Vectors, Social Engineering' },
    { id: 'unit-4', title: 'Unit 4: Physical Security', icon: Lock, color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'group-hover:border-emerald-500/50', desc: 'Controls, Surveillance, Biometrics' },
    { id: 'unit-5', title: 'Unit 5: Cryptography & PKI', icon: Network, color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'group-hover:border-purple-500/50', desc: 'Encryption, Hashing, Digital Signatures' },
    { id: 'unit-6', title: 'Unit 6: Malware', icon: Bug, color: 'text-red-400', bg: 'bg-red-500/10', border: 'group-hover:border-red-500/50', desc: 'Viruses, Worms, Trojans, Ransomware' },
    { id: 'unit-7', title: 'Unit 7: Data Protection', icon: Database, color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'group-hover:border-blue-500/50', desc: 'DLP, Data States, Sovereignty' },
    { id: 'unit-8', title: 'Unit 8: Cryptography & PKI', icon: Key, color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'group-hover:border-purple-500/50', desc: 'Hashing, Encryption, PKI, Certificates' },
    { id: 'unit-9', title: 'Unit 9: Risk Management', icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'group-hover:border-yellow-500/50', desc: 'Risk Assessment, BIA, Risk Treatment' },
    { id: 'unit-10', title: 'Unit 10: Vendor Risk', icon: Truck, color: 'text-cyan-400', bg: 'bg-cyan-500/10', border: 'group-hover:border-cyan-500/50', desc: 'Supply Chain, Vendor Assessment, SLAs' },
    { id: 'unit-11', title: 'Unit 11: Governance & Compliance', icon: Scale, color: 'text-indigo-400', bg: 'bg-indigo-500/10', border: 'group-hover:border-indigo-500/50', desc: 'Policies, Standards, Regulations, GDPR' },
    { id: 'unit-12', title: 'Unit 12: Asset & Change Management', icon: RefreshCw, color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'group-hover:border-orange-500/50', desc: 'Lifecycle, Disposal, Change Control, CAB' },
    { id: 'unit-13', title: 'Unit 13: Audits & Assessments', icon: ClipboardCheck, color: 'text-teal-400', bg: 'bg-teal-500/10', border: 'group-hover:border-teal-500/50', desc: 'Internal/External Audits, Vulnerability Scans' },
    { id: 'unit-14', title: 'Unit 14: Cyber Resilience & Redundancy', icon: Server, color: 'text-indigo-400', bg: 'bg-indigo-500/10', border: 'group-hover:border-indigo-500/50', desc: 'DRP, BCP, High Availability, Fault Tolerance' },
    { id: 'unit-15', title: 'Unit 15: Security Architecture', icon: Network, color: 'text-violet-400', bg: 'bg-violet-500/10', border: 'group-hover:border-violet-500/50', desc: 'Zero Trust, Cloud Security, Network Segmentation' },
    { id: 'unit-16', title: 'Unit 16: Security Infrastructure', icon: BrickWall, color: 'text-rose-400', bg: 'bg-rose-500/10', border: 'group-hover:border-rose-500/50', desc: 'Firewalls, Ports & Protocols, Load Balancers' },
    { id: 'unit-17', title: 'Unit 17: Identity & Access Management', icon: UserCheck, color: 'text-sky-400', bg: 'bg-sky-500/10', border: 'group-hover:border-sky-500/50', desc: 'MFA, Biometrics, SSO, Federation' },
    { id: 'unit-18', title: 'Unit 18: Vulnerabilities & Attacks', icon: Zap, color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'group-hover:border-amber-500/50', desc: 'Zero-Day, SQL Injection, XSS, Buffer Overflow' },
    { id: 'unit-19', title: 'Unit 19: Malicious Activity', icon: Activity, color: 'text-red-500', bg: 'bg-red-500/10', border: 'group-hover:border-red-500/50', desc: 'Rootkits, Replay Attacks, Session Hijacking, IoCs' },
    { id: 'unit-20', title: 'Unit 20: Hardening', icon: ShieldCheck, color: 'text-emerald-500', bg: 'bg-emerald-500/10', border: 'group-hover:border-emerald-500/50', desc: 'Secure Baselines, Patch Management, FDE, Group Policies' },
    { id: 'unit-21', title: 'Unit 21: Security Techniques', icon: Wifi, color: 'text-cyan-500', bg: 'bg-cyan-500/10', border: 'group-hover:border-cyan-500/50', desc: 'Wireless, Input Validation, Code Signing' },
    { id: 'unit-22', title: 'Unit 22: Vulnerability Management', icon: Scan, color: 'text-purple-500', bg: 'bg-purple-500/10', border: 'group-hover:border-purple-500/50', desc: 'Scanning, CVSS, CVE, Risk Tolerance' },
    { id: 'unit-23', title: 'Unit 23: Alerting and Monitoring', icon: Bell, color: 'text-yellow-500', bg: 'bg-yellow-500/10', border: 'group-hover:border-yellow-500/50', desc: 'SNMP, SIEM, NetFlow, Data Sources' },
    { id: 'unit-24', title: 'Unit 24: Incident Response', icon: Siren, color: 'text-red-500', bg: 'bg-red-500/10', border: 'group-hover:border-red-500/50', desc: 'Forensics, Chain of Custody, E-Discovery' },
    { id: 'unit-25', title: 'Unit 25: Investigating an Incident', icon: Search, color: 'text-blue-500', bg: 'bg-blue-500/10', border: 'group-hover:border-blue-500/50', desc: 'Investigation Process, Evidence Collection, Interviews' },
    { id: 'unit-26', title: 'Unit 26: Automation & Orchestration', icon: Bot, color: 'text-purple-500', bg: 'bg-purple-500/10', border: 'group-hover:border-purple-500/50', desc: 'SOAR, Playbooks, Runbooks, Scripting' },
    { id: 'unit-27', title: 'Unit 27: Security Awareness', icon: GraduationCap, color: 'text-green-500', bg: 'bg-green-500/10', border: 'group-hover:border-green-500/50', desc: 'Phishing, Social Engineering, Training, Culture' }
]

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
        </div>
    )
}
