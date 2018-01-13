var Cvss;

Cvss = (function () {
    var version = "3.0",
        vectorHead = "CVSS:3.0",
        metricSeparator = "/",
        valueSeparator = ":",
        exploitabilityCoefficient = 8.22,
        scopeCoefficient = 1.08;

    var metrics = {
        base: {
            AV: {
                N: 0.85,
                A: 0.62,
                L: 0.55,
                P: 0.2
            },
            AC: {
                L: 0.77,
                H: 0.44
            },
            PR: {
                N: 0.85,
                L: {
                    unchanged: 0.62,
                    changed: 0.68
                },
                H: {
                    unchanged: 0.27,
                    changed: 0.50
                }
            },
            UI: {
                N: 0.85,
                R: 0.62
            },
            S: {
                U: 6.42,
                C: 7.52
            },
            C: {
                N: 0,
                L: 0.22,
                H: 0.56
            },
            I: {
                N: 0,
                L: 0.22,
                H: 0.56
            },
            A: {
                N: 0,
                L: 0.22,
                H: 0.56
            }
        },
        temporal: {
            E: {
                X: 1,
                U: 0.91,
                P: 0.94,
                F: 0.97,
                H: 1
            },
            RL: {
                X: 1,
                O: 0.95,
                T: 0.96,
                W: 0.9,
                U: 1
            },
            RC: {
                X: 1,
                U: 0.92,
                R: 0.96,
                C: 1
            }
        },
        environmental: {
            CR: {
                X: 1,
                L: 0.5,
                M: 1,
                H: 1.5
            },
            IR: {
                X: 1,
                L: 0.5,
                M: 1,
                H: 1.5
            },
            AR: {
                X: 1,
                L: 0.5,
                M: 1,
                H: 1.5
            },
            MAV: {
                X: 0,
                N: 0.85,
                A: 0.62,
                L: 0.55,
                P: 0.2
            },
            MAC: {
                X: 0,
                L: 0.77,
                H: 0.44
            },
            MPR: {
                X: 0,
                N: 0.85,
                L: {
                    unchanged: 0.62,
                    changed: 0.68
                },
                H: {
                    unchanged: 0.27,
                    changed: 0.5
                }
            },
            MUI: {
                X: 0,
                N: 0.85,
                R: 0.62
            },
            MS: {
                X: 0,
                U: 6.42,
                C: 7.52
            },
            MC: {
                X: 0,
                N: 0,
                L: 0.22,
                H: 0.56
            },
            MI: {
                X: 0,
                N: 0,
                L: 0.22,
                H: 0.56
            },
            MA: {
                X: 0,
                N: 0,
                L: 0.22,
                H: 0.56
            }
        }
    };

    var severityRatings = [
        {name: "N", bottom: 0.0, top: 0.0},
        {name: "L", bottom: 0.1, top: 3.9},
        {name: "M", bottom: 4.0, top: 6.9},
        {name: "H", bottom: 7.0, top: 8.9},
        {name: "C", bottom: 9.0, top: 10.0}
    ];

    function Cvss() {
        this.scores = {
            base: 0,
            temporal: 0,
            environmental: 0
        };
        this.errors = [];
        this.vectorInputs = [];
        this.vectorLevels = [];
    }

    Cvss.prototype.parseVector = function (vector) {
        if (!this.isVectorValid(vector)) {
            return false;
        }

        var re = new RegExp('^' + vectorHead + '[\\' + metricSeparator + ']?');
        vector = vector.replace(re, '');

        var metrics = vector.split('/');
        for (var i = 0, j = metrics.length; i < j; i++) {
            var data = metrics[i].split(valueSeparator);
            this.vectorInputs[data[0]] = data[1];
        }

        this.checkBaseMetrics();
        this.checkTemporalMetrics();
        this.checkEnvironmentalMetrics();

        if (this.errors.length > 0) {
            return false;
        }

        this.setInputLevel();
        this.calculate();

        return true;
    };

    Cvss.prototype.setInputLevel = function () {
        for (metric in metrics.base) {
            var value = this.vectorInputs[metric];
            switch (metric) {
                case 'PR':
                    switch (value) {
                        case 'L':
                        case 'H':
                            var scope = this.vectorInputs['S'];
                            if (scope == 'U') {
                                this.vectorLevels[metric] = metrics.base[metric][value]['unchanged'];
                            }
                            else if (scope == 'C') {
                                this.vectorLevels[metric] = metrics.base[metric][value]['changed'];
                            }
                            break;
                        default:
                            this.vectorLevels[metric] = metrics.base[metric][value]
                            break;
                    }
                    break;
                default:
                    this.vectorLevels[metric] = metrics.base[metric][value];
                    break;
            }
        }

        for (metric in metrics.temporal) {
            this.vectorLevels[metric] = metrics.temporal[metric][this.vectorInputs[metric]];
        }

        for (metric in metrics.environmental) {
            var value = this.vectorInputs[metric];
            switch (metric) {
                case 'MPR':
                    var scope = this.vectorInputs['MS'] != 'X' ? this.vectorInputs['MS'] : this.vectorInputs['S'];
                    switch (value) {
                        case 'X':
                            if (scope == 'U') {
                                this.vectorLevels[metric] = metrics.base[metric.substr(1)][this.vectorInputs[metric.substr(1)]]['unchanged'] || metrics.base[metric.substr(1)][this.vectorInputs[metric.substr(1)]];
                            }
                            else if (scope == 'C') {
                                this.vectorLevels[metric] = metrics.base[metric.substr(1)][this.vectorInputs[metric.substr(1)]]['changed'] || metrics.base[metric.substr(1)][this.vectorInputs[metric.substr(1)]];
                            }
                            else {
                                this.vectorLevels[metric] = metrics.base[metric.substr(1)][this.vectorInputs[metric.substr(1)]];
                            }
                            break;
                        case 'L':
                        case 'H':
                            if (scope == 'U') {
                                this.vectorLevels[metric] = metrics.environmental[metric][value]['unchanged'];
                            }
                            else if (scope == 'C') {
                                this.vectorLevels[metric] = metrics.environmental[metric][value]['changed'];
                            }
                            break;
                        default:
                            this.vectorLevels[metric] = metrics.environmental[metric][value];
                            break;
                    }
                    break;
                case 'CR':
                case 'IR':
                case 'AR':
                    this.vectorLevels[metric] = metrics.environmental[metric][value];
                    break;
                default:
                    if (value == 'X') {
                        this.vectorLevels[metric] = this.vectorLevels[metric.substr(1)];
                    }
                    else {
                        this.vectorLevels[metric] = metrics.environmental[metric][value];
                    }
                    break;
            }
        }
    };

    Cvss.prototype.calculate = function () {
        var impactSubScore = 0;
        var impactSubScoreBase = 1 - ((1 - this.vectorLevels['C']) * (1 - this.vectorLevels['I']) * (1 - this.vectorLevels['A']));

        if (this.vectorInputs['S'] === 'U') {
            impactSubScore = this.vectorLevels['S'] * impactSubScoreBase;
        }
        else {
            impactSubScore = this.vectorLevels['S'] * (impactSubScoreBase - 0.029) - 3.25 * Math.pow(impactSubScoreBase - 0.02, 15);
        }

        var exploitabilitySubScore = exploitabilityCoefficient * this.vectorLevels['AV'] * this.vectorLevels['AC'] * this.vectorLevels['PR'] * this.vectorLevels['UI'];

        if (impactSubScore <= 0) {
            this.scores.base = 0;
        }
        else {
            if (this.vectorInputs['S'] === 'U') {
                this.scores.base = this.roundUp1(Math.min((exploitabilitySubScore + impactSubScore), 10));
            } else {
                this.scores.base = this.roundUp1(Math.min((exploitabilitySubScore + impactSubScore) * scopeCoefficient, 10));
            }
        }

        this.scores.temporal = this.roundUp1(this.scores.base * this.vectorLevels['E'] * this.vectorLevels['RL'] * this.vectorLevels['RC']);

        var modifiedImpactSubScore = 0;
        var modifiedImpactSubScoreBase = Math.min(1 - ((1 - this.vectorLevels['MC'] * this.vectorLevels['CR']) * (1 - this.vectorLevels['MI'] * this.vectorLevels['IR']) * (1 - this.vectorLevels['MA'] * this.vectorLevels['AR'])), 0.915);
        var modifiedScope = this.vectorInputs['MS'] != 'X' ? this.vectorInputs['MS'] : this.vectorInputs['S'];
        switch (modifiedScope) {
            case 'U':
                modifiedImpactSubScore = this.vectorLevels['MS'] * modifiedImpactSubScoreBase;
                break;
            case 'C':
                modifiedImpactSubScore = this.vectorLevels['MS'] * (modifiedImpactSubScoreBase - 0.029) - 3.25 * Math.pow((modifiedImpactSubScoreBase - 0.02), 15);
                break;
        }

        var modifiedExploitabilitySubScore = exploitabilityCoefficient * this.vectorLevels['MAV'] * this.vectorLevels['MAC'] * this.vectorLevels['MPR'] * this.vectorLevels['MUI'];

        if (modifiedImpactSubScore <= 0) {
            this.scores.environmental = this.scores.base;
        }
        else {
            switch (modifiedScope) {
                case 'U':
                    this.scores.environmental = this.roundUp1(this.roundUp1(Math.min(modifiedImpactSubScore + modifiedExploitabilitySubScore, 10)) * this.vectorLevels['E'] * this.vectorLevels['RL'] * this.vectorLevels['RC']);
                    break;
                case 'C':
                    this.scores.environmental = this.roundUp1(this.roundUp1(Math.min(1.08 * (modifiedImpactSubScore + modifiedExploitabilitySubScore), 10)) * this.vectorLevels['E'] * this.vectorLevels['RL'] * this.vectorLevels['RC']);
                    break;
            }
        }
    };

    Cvss.prototype.isVectorValid = function (vector) {
        var re = new RegExp('^' + vectorHead + '.*', 'mi');
        return re.test(vector);
    };

    Cvss.prototype.checkBaseMetrics = function () {
        for (metric in metrics.base) {
            var metricValue = this.vectorInputs[metric];
            if (metricValue == undefined) {
                this.errors.push("Missing base metric: " + metric);
            }
            else if (metrics.base[metric][metricValue] == undefined) {
                this.errors.push("Unknown value " + metricValue + " for base metric " + metric);
            }
        }
    };

    Cvss.prototype.checkTemporalMetrics = function () {
        for (metric in metrics.temporal) {
            var metricValue = this.vectorInputs[metric];
            if (metricValue == undefined) {
                this.vectorInputs[metric] = 'X';
                metricValue = 'X';
            }
            if (metrics.temporal[metric][metricValue] == undefined) {
                this.errors.push("Unknown value " + metricValue + " for temporal metric " + metric);
            }
        }
    };

    Cvss.prototype.checkEnvironmentalMetrics = function () {
        for (metric in metrics.environmental) {
            var metricValue = this.vectorInputs[metric];
            if (metricValue == undefined) {
                this.vectorInputs[metric] = 'X';
                metricValue = 'X';
            }
            if (metrics.environmental[metric][metricValue] == undefined) {
                this.errors.push("Unknown value " + metricValue + " for environmental metric " + metric);
            }
        }
    };

    Cvss.prototype.getScores = function () {
        return this.scores;
    };

    Cvss.prototype.getBaseScore = function () {
        return this.scores.base || 0;
    };

    Cvss.prototype.getTemporalScore = function () {
        return this.scores.temporal || 0;
    };

    Cvss.prototype.getEnvironmentalScore = function () {
        return this.scores.environmental || 0;
    };

    Cvss.prototype.getSeverity = function (score) {
        for (var i = 0, j = severityRatings.length; i <= j; i++) {
            if (score >= severityRatings[i].bottom && score <= severityRatings[i].top) {
                return severityRatings[i].name;
            }
        }
        return "N/A";
    };

    Cvss.prototype.getBaseSeverity = function () {
        return this.getSeverity(this.scores.base);
    };

    Cvss.prototype.getTemporalSeverity = function () {
        return this.getSeverity(this.scores.temporal);
    };

    Cvss.prototype.getEnvironmentalSeverity = function () {
        return this.getSeverity(this.scores.environmental);
    };

    Cvss.prototype.buildVector = function(inputs) {
        var parts = ['CVSS' + valueSeparator + version];
        for (metric in inputs) {
            parts.push(metric + valueSeparator + inputs[metric]);
        }
        return parts.join(metricSeparator);
    };

    Cvss.prototype.getErrors = function () {
        return this.errors;
    };

    Cvss.prototype.roundUp1 = function (num) {
        return Math.ceil(num * 10) / 10;
    };

    return Cvss;

})();