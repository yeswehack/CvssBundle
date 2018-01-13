<?php

namespace YWH\CvssBundle\Validator\Constraints;

use Symfony\Component\Validator\Constraint;

/**
 * @Annotation
 *
 * @author Romain Honel <r.honel@yeswehack.com>
 * @author Maxime Bouchard <m.bouchard@yeswehack.com>
 */
class Cvss3 extends Constraint
{
    public $message = 'Cvss3 vector "%vector%" is invalid.';
}