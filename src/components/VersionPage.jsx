import { useState, useEffect } from 'react';
import versionInfo from '../version.json';

export default function VersionPage() {
    return (
        <div className="min-h-screen bg-slate-950 text-slate-100 p-8 font-mono">
            <div className="max-w-2xl mx-auto bg-slate-900 border border-white/10 rounded-xl p-8 shadow-2xl">
                <h1 className="text-3xl font-bold mb-6 text-cyan-400">System Version</h1>

                <div className="space-y-4">
                    <div className="flex flex-col gap-1">
                        <span className="text-slate-500 text-sm uppercase tracking-wider">Commit Hash</span>
                        <span className="text-xl text-white font-bold">{versionInfo.commitHash}</span>
                    </div>

                    <div className="flex flex-col gap-1">
                        <span className="text-slate-500 text-sm uppercase tracking-wider">Commit Date</span>
                        <span className="text-lg text-slate-300">{versionInfo.commitDate}</span>
                    </div>

                    <div className="flex flex-col gap-1">
                        <span className="text-slate-500 text-sm uppercase tracking-wider">Build Date</span>
                        <span className="text-lg text-slate-300">{new Date(versionInfo.buildDate).toLocaleString()}</span>
                    </div>
                </div>

                <div className="mt-8 pt-6 border-t border-white/5 text-xs text-slate-600">
                    <p>Security+ Master Quiz Tool</p>
                </div>
            </div>
        </div>
    );
}
