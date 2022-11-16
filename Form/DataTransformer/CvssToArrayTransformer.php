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
    public function transform($value): array
    {
        if (null === $value) {
            return array();
        }

        if (!is_string($value)) {
            throw new TransformationFailedException('Expected a string.');
        }

        return Cvss3::parseVector($value);
    }

    public function reverseTransform($value): ?string
    {
        if (null === $value) {
            return null;
        }

        if (!is_array($value)) {
            throw new TransformationFailedException('Expected an array.');
        }

        if ('' === implode('', $value)) {
            return null;
        }

        return Cvss3::buildVector(array_filter($value));
    }
}
