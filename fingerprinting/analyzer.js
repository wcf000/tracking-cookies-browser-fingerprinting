/**
 * Fingerprinting Analyzer
 * Analyzes fingerprinting techniques and their prevalence
 */

class FingerprintAnalyzer {
    constructor(fingerprintingAttempts = []) {
        this.attempts = fingerprintingAttempts;
        this.analysisResults = {};
    }

    /**
     * Load fingerprinting attempts from JSON file or object
     * @param {Object|string} data - Fingerprinting attempts data or JSON string
     */
    loadData(data) {
        try {
            if (typeof data === 'string') {
                this.attempts = JSON.parse(data);
            } else {
                this.attempts = data;
            }
            return true;
        } catch (e) {
            console.error("Error loading data:", e);
            return false;
        }
    }

    /**
     * Analyze the fingerprinting attempts
     * @returns {Object} Analysis results
     */
    analyze() {
        if (!this.attempts || this.attempts.length === 0) {
            console.warn("No fingerprinting attempts to analyze");
            return {};
        }

        // Initialize analysis results
        this.analysisResults = {
            totalAttempts: this.attempts.length,
            techniquesBreakdown: {},
            domainBreakdown: {},
            timeDistribution: {},
            browserImpact: this.analyzeImpact()
        };
        this.analyzeTechniques();
        this.analyzeDomains();
        this.analyzeTimePatterns();

        return this.analysisResults;
    }

    /**
     * Analyze fingerprinting techniques
     */
    analyzeTechniques() {
        const techniques = {};
        
        this.attempts.forEach(attempt => {
            const technique = attempt.technique || 'unknown';
            techniques[technique] = (techniques[technique] || 0) + 1;
        });
        
        // Sort by frequency
        const sortedTechniques = Object.entries(techniques)
            .map(([name, count]) => ({ 
                name, 
                count, 
                percentage: (count / this.attempts.length * 100).toFixed(1) 
            }))
            .sort((a, b) => b.count - a.count);
        
        this.analysisResults.techniquesBreakdown = {
            byCount: sortedTechniques,
            mostCommon: sortedTechniques[0]
        };
    }

    /**
     * Analyze domains using fingerprinting
     */
    analyzeDomains() {
        const domains = {};
        
        this.attempts.forEach(attempt => {
            const domain = attempt.domain || 'unknown';
            if (!domains[domain]) {
                domains[domain] = {
                    count: 0,
                    techniques: {},
                    blocked: 0
                };
            }
            
            domains[domain].count++;
            
            const technique = attempt.technique || 'unknown';
            domains[domain].techniques[technique] = (domains[domain].techniques[technique] || 0) + 1;
            
            if (attempt.blocked) {
                domains[domain].blocked++;
            }
        });
        
        // Sort by frequency
        const sortedDomains = Object.entries(domains)
            .map(([name, stats]) => ({
                name,
                count: stats.count,
                techniques: Object.keys(stats.techniques).length,
                mostUsedTechnique: Object.entries(stats.techniques)
                    .sort((a, b) => b[1] - a[1])[0][0],
                blockedPercentage: (stats.blocked / stats.count * 100).toFixed(1)
            }))
            .sort((a, b) => b.count - a.count);
        
        this.analysisResults.domainBreakdown = {
            totalDomains: sortedDomains.length,
            topDomains: sortedDomains.slice(0, 10)
        };
    }

    /**
     * Analyze time patterns of fingerprinting
     */
    analyzeTimePatterns() {
        // Group by hour of day
        const hourDistribution = Array(24).fill(0);
        
        this.attempts.forEach(attempt => {
            if (attempt.timestamp) {
                const date = new Date(attempt.timestamp);
                const hour = date.getHours();
                hourDistribution[hour]++;
            }
        });
        
        // Find peak hours
        let peakHour = 0;
        let peakCount = 0;
        
        hourDistribution.forEach((count, hour) => {
            if (count > peakCount) {
                peakCount = count;
                peakHour = hour;
            }
        });
        
        this.analysisResults.timeDistribution = {
            byHour: hourDistribution,
            peakHour: peakHour,
            peakCount: peakCount
        };
    }

    /**
     * Analyze potential impact of fingerprinting on browser
     */
    analyzeImpact() {
        // Count by impact level
        const impactLevels = {
            high: 0,
            medium: 0,
            low: 0
        };
        
        // Define high impact techniques
        const highImpactTechniques = [
            'Canvas Fingerprinting', 
            'WebGL Fingerprinting',
            'Audio Fingerprinting'
        ];
        
        // Define medium impact techniques
        const mediumImpactTechniques = [
            'Font Enumeration',
            'Navigator Enumeration',
            'Hardware Enumeration'
        ];
        
        this.attempts.forEach(attempt => {
            const technique = attempt.technique || '';
            
            if (highImpactTechniques.some(t => technique.includes(t))) {
                impactLevels.high++;
            } else if (mediumImpactTechniques.some(t => technique.includes(t))) {
                impactLevels.medium++;
            } else {
                impactLevels.low++;
            }
        });
        
        return {
            levels: impactLevels,
            highImpactPercentage: (impactLevels.high / this.attempts.length * 100).toFixed(1)
        };
    }

    /**
     * Export analysis results to JSON
     * @returns {string} JSON string of analysis results
     */
    exportToJson() {
        return JSON.stringify(this.analysisResults, null, 2);
    }
}

// Export for use in non-module environments
if (typeof window !== 'undefined') {
    window.FingerprintAnalyzer = FingerprintAnalyzer;
}
if (typeof module !== 'undefined' && module.exports) {
    module.exports = FingerprintAnalyzer;
}