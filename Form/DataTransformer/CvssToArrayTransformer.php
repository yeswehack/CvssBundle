<?php

namespace YWH\CvssBundle\Form\DataTransformer;

use YWH\CvssBundle\Cvss\Cvss3;
use Symfony\Component\Form\DataTransformerInterface;
use Symfony\Component\Form\Exception\TransformationFailedException;

/**
 * Class CvssToArrayTransformer
 *
 * @author Romain Honel <r.honel@yeswehack.com>
 * @author Maxime Bouchard <m.bouchard@yeswehack.com>
 */
class CvssToArrayTransformer implements DataTransformerInterface
{
    /**
     * {@inheritdoc}
     */
    public function transform($vector)
    {
        if (null === $vector) {
            return array();
        }

        if (!is_string($vector)) {
            throw new TransformationFailedException('Expected a string.');
        }

        return Cvss3::parseVector($vector);
    }

    /**
     * {@inheritdoc}
     */
    public function reverseTransform($value)
    {
        if (null === $value) {
            return;
        }

        if (!is_array($value)) {
            throw new TransformationFailedException('Expected an array.');
        }

        if ('' === implode('', $value)) {
            return;
        }

        return Cvss3::buildVector(array_filter($value));
    }
}