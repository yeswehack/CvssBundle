<?php

namespace YWH\CvssBundle\Validator\Constraints;

use Symfony\Component\Validator\Constraint;

/**
 * @Annotation
 * @Target({"PROPERTY"})
 *
 * @author Romain Honel <r.honel@yeswehack.com>
 * @author Maxime Bouchard <m.bouchard@yeswehack.com>
 */
#[\Attribute(\Attribute::TARGET_PROPERTY)]
class Cvss3 extends Constraint
{
    public string $message = 'Cvss3 vector "%vector%" is invalid.';
}
