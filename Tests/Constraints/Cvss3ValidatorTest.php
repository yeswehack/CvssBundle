<?php

namespace YWH\CvssBundle\Tests\Constraints;

use YWH\CvssBundle\Validator\Constraints\Cvss3;
use YWH\CvssBundle\Validator\Constraints\Cvss3Validator;
use Symfony\Component\Validator\Test\ConstraintValidatorTestCase;

/**
 * Class Cvss3ValidatorTest
 *
 * @author Romain Honel <r.honel@yeswehack.com>
 * @author Maxime Bouchard <m.bouchard@yeswehack.com>
 */
class Cvss3ValidatorTest extends ConstraintValidatorTestCase
{
    protected function createValidator()
    {
        return new Cvss3Validator();
    }

    public function testNullIsValid()
    {
        $this->validator->validate(null, new Cvss3());

        $this->assertNoViolation();
    }

    public function testEmptyStringIsValid()
    {
        $this->validator->validate('', new Cvss3());

        $this->assertNoViolation();
    }

    /**
     * @dataProvider getValidBics
     */
    public function testValidBics($vector)
    {
        $this->validator->validate($vector, new Cvss3());

        $this->assertNoViolation();
    }

    public function getValidBics()
    {
        return array(
            array('CVSS:3.0/AV:N'),
            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
        );
    }

    /**
     * @dataProvider getInvalidVectors
     */
    public function testInvalidVectors($vector)
    {
        $constraint = new Cvss3(array(
            'message' => 'myMessage',
        ));

        $this->validator->validate($vector, $constraint);

        $this->buildViolation('myMessage')
            ->setParameter('%vector%', $vector)
            ->assertRaised();
    }

    public function getInvalidVectors()
    {
        return array(
            array('aaaa'),
            array('CVSS:A'),
            array('AAA:3.0'),
            array('CVSS:3.0/AV:_/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
        );
    }
}