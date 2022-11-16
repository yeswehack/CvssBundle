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
    protected function createValidator(): Cvss3Validator
    {
        return new Cvss3Validator();
    }

    public function testNullIsValid(): void
    {
        $this->validator->validate(null, new Cvss3());

        $this->assertNoViolation();
    }

    public function testEmptyStringIsValid(): void
    {
        $this->validator->validate('', new Cvss3());

        $this->assertNoViolation();
    }

    /**
     * @dataProvider getValidBics
     */
    public function testValidBics($vector): void
    {
        $this->validator->validate($vector, new Cvss3());

        $this->assertNoViolation();
    }

    public function getValidBics(): array
    {
        $baseVector = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N';
        return array(
            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
            array('CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
            array('CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
            array('CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),

            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
            array('CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N'),

            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
            array('CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N'),
            array('CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N'),

            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N'),

            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N'),

            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),

            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'),
            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N'),

            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'),
            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'),

            array($baseVector.'/E:X'),
            array($baseVector.'/E:H'),
            array($baseVector.'/E:F'),
            array($baseVector.'/E:P'),
            array($baseVector.'/E:U'),

            array($baseVector.'/RL:X'),
            array($baseVector.'/RL:U'),
            array($baseVector.'/RL:W'),
            array($baseVector.'/RL:T'),
            array($baseVector.'/RL:O'),

            array($baseVector.'/RC:X'),
            array($baseVector.'/RC:C'),
            array($baseVector.'/RC:R'),
            array($baseVector.'/RC:U'),

            array($baseVector.'/CR:X'),
            array($baseVector.'/CR:H'),
            array($baseVector.'/CR:L'),
            array($baseVector.'/CR:M'),

            array($baseVector.'/IR:X'),
            array($baseVector.'/IR:H'),
            array($baseVector.'/IR:L'),
            array($baseVector.'/IR:M'),

            array($baseVector.'/AR:X'),
            array($baseVector.'/AR:H'),
            array($baseVector.'/AR:L'),
            array($baseVector.'/AR:M'),

            array($baseVector.'/MAV:X'),
            array($baseVector.'/MAV:N'),
            array($baseVector.'/MAV:A'),
            array($baseVector.'/MAV:L'),
            array($baseVector.'/MAV:P'),

            array($baseVector.'/MAC:X'),
            array($baseVector.'/MAC:L'),
            array($baseVector.'/MAC:H'),

            array($baseVector.'/MPR:X'),
            array($baseVector.'/MPR:N'),
            array($baseVector.'/MPR:L'),
            array($baseVector.'/MPR:H'),

            array($baseVector.'/MUI:X'),
            array($baseVector.'/MUI:N'),
            array($baseVector.'/MUI:R'),

            array($baseVector.'/MS:X'),
            array($baseVector.'/MS:U'),
            array($baseVector.'/MS:C'),

            array($baseVector.'/MC:X'),
            array($baseVector.'/MC:N'),
            array($baseVector.'/MC:L'),
            array($baseVector.'/MC:H'),

            array($baseVector.'/MI:X'),
            array($baseVector.'/MI:N'),
            array($baseVector.'/MI:L'),
            array($baseVector.'/MI:H'),

            array($baseVector.'/MA:X'),
            array($baseVector.'/MA:N'),
            array($baseVector.'/MA:L'),
            array($baseVector.'/MA:H'),
        );
    }

    /**
     * @dataProvider getInvalidVectors
     */
    public function testInvalidVectors($vector): void
    {
        $constraint = new Cvss3(array(
            'message' => 'myMessage',
        ));

        $this->validator->validate($vector, $constraint);

        $this->buildViolation('myMessage')
            ->setParameter('%vector%', $vector)
            ->assertRaised();
    }

    public function getInvalidVectors(): array
    {
        return array(
            array('aaaa'),
            array('CVSS:A'),
            array('AAA:3.0'),
            array('CVSS:3.0/AV:_/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
            array('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/A/N'),
        );
    }
}
