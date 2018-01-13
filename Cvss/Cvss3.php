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
    /**
     * Cvss3 constructor.
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Get metric translation id
     *
     * @param string $metric
     *
     * @return string
     */
    public function getMetricTransId($metric)
    {
        return strtolower(sprintf('cvss.metric.%s', $metric));
    }

    /**
     * Get metric value translation id
     *
     * @param string $metric
     * @param string $value
     *
     * @return string
     */
    public function getMetricValueTransId($metric, $value)
    {
        return strtolower(sprintf('cvss.metric.%s.%s', $metric, $value));
    }

    /**
     * Get base severity translation id
     * @return string
     */
    public function getBaseSeverityTransId()
    {
        return strtolower(sprintf('cvss.severity.%s', $this->getBaseScoreSeverity()));
    }

    /**
     * Get temporal severity translation id
     * @return string
     */
    public function getTemporalSeverityTransId()
    {
        return strtolower(sprintf('cvss.severity.%s', $this->getTemporalScoreSeverity()));
    }

    /**
     * Get environmental severity translation id
     * @return string
     */
    public function getEnvironmentalSeverityTransId()
    {
        return strtolower(sprintf('cvss.severity.%s', $this->getEnvironmentalScoreSeverity()));
    }

    /**
     * Get overall severity translation id
     *
     * @return string
     */
    public function getOverallSeverityTransId()
    {
        return strtolower(sprintf('cvss.severity.%s', $this->getOvegetOverallSeverityTransIdrallScoreSeverity()));
    }

}