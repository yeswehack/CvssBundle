<?php

namespace YWH\CvssBundle\Validator\Constraints;

use Symfony\Component\OptionsResolver\Exception\InvalidArgumentException;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;
use YWH\CvssBundle\Cvss\Cvss3 as Parser;

/**
 * Class Cvss3Validator
 *
 * @author Romain Honel <r.honel@yeswehack.com>
 * @author Maxime Bouchard <m.bouchard@yeswehack.com>
 */
class Cvss3Validator extends ConstraintValidator
{
    private string $pattern = '/^CVSS:3\.0\/((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])\/)*(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$/';

    public function validate($value, Constraint $constraint)
    {
        if (!$constraint instanceof Cvss3) {
            throw new UnexpectedTypeException($constraint, Cvss3::class);
        }

        if (null === $value || '' === $value) {
            return;
        }

        if (!preg_match($this->pattern, $value)) {
            $this->context->buildViolation($constraint->message)
                ->setParameter('%vector%', $value)
                ->addViolation();
        } else {
            $cvss3Parser = new Parser();
            try {
                $cvss3Parser->setVector($value);
            } catch (InvalidArgumentException $e) {
                $this->context->buildViolation($constraint->message)
                    ->setParameter('%vector%', $value)
                    ->addViolation();
            }
        }
    }
}
