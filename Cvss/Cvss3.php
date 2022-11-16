<?php

namespace YWH\CvssBundle\Cvss;

use YWH\Cvss\Cvss3 as BaseCvss3;

/**
 * Class Cvss3
 *
 * @author Romain Honel <r.honel@yeswehack.com>
 * @author Maxime Bouchard <m.bouchard@yeswehack.com>
 */
class Cvss3 extends BaseCvss3
{
    public function getMetricTransId(string $metric): string
    {
        return strtolower(sprintf('cvss.metric.%s', $metric));
    }

    public function getMetricValueTransId(string $metric, string $value): string
    {
        return strtolower(sprintf('cvss.metric.%s.%s', $metric, $value));
    }

    public function getBaseSeverityTransId(): string
    {
        return strtolower(sprintf('cvss.severity.%s', $this->getBaseScoreSeverity()));
    }

    public function getTemporalSeverityTransId(): string
    {
        return strtolower(sprintf('cvss.severity.%s', $this->getTemporalScoreSeverity()));
    }

    public function getEnvironmentalSeverityTransId(): string
    {
        return strtolower(sprintf('cvss.severity.%s', $this->getEnvironmentalScoreSeverity()));
    }

    public function getOverallSeverityTransId(): string
    {
        return strtolower(sprintf('cvss.severity.%s', $this->getOverallScoreSeverity()));
    }

}
