<?php

namespace YWH\CvssBundle\Tests\Form\Type;

use YWH\CvssBundle\Cvss\Cvss3;
use YWH\CvssBundle\Form\Type\Cvss3Type;
use Symfony\Component\Form\PreloadedExtension;

/**
 * Class Cvss3TypeTest
 *
 * @author Romain Honel <r.honel@yeswehack.com>
 * @author Maxime Bouchard <m.bouchard@yeswehack.com>
 */
class Cvss3TypeTest extends \Symfony\Component\Form\Test\TypeTestCase
{
    /**
     * @var Cvss3
     */
    protected $cvss;

    private $baseVector = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N';

    private $temporalVector = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:X/RL:X/RC:X';

    private $fullVector = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X';

    private $parsedBaseVector = array(
        'AV' => 'N',
        'AC' => 'L',
        'PR' => 'N',
        'UI' => 'N',
        'S' => 'U',
        'C' => 'N',
        'I' => 'N',
        'A' => 'N',
    );

    private $parsedTemporalVector = array(
        'AV' => 'N',
        'AC' => 'L',
        'PR' => 'N',
        'UI' => 'N',
        'S' => 'U',
        'C' => 'N',
        'I' => 'N',
        'A' => 'N',
        'E' => 'X',
        'RL' => 'X',
        'RC' => 'X',
    );

    private $parsedFullVector = array(
        'AV' => 'N',
        'AC' => 'L',
        'PR' => 'N',
        'UI' => 'N',
        'S' => 'U',
        'C' => 'N',
        'I' => 'N',
        'A' => 'N',
        'E' => 'X',
        'RL' => 'X',
        'RC' => 'X',
        'CR' => 'X',
        'IR' => 'X',
        'AR' => 'X',
        'MAV' => 'X',
        'MAC' => 'X',
        'MPR' => 'X',
        'MUI' => 'X',
        'MS' => 'X',
        'MC' => 'X',
        'MI' => 'X',
        'MA' => 'X',
    );

    protected function setUp()
    {
        $this->cvss = $this->getMockBuilder(Cvss3::class);
        $this->cvss = new Cvss3();

        parent::setUp();
    }

    protected function getExtensions()
    {
        $type = new Cvss3Type($this->cvss);
        return array(
            new PreloadedExtension(array($type), array()),
        );
    }

    public function testSetData()
    {
        $form = $this->factory->create(Cvss3Type::class);
        $form->setData($this->baseVector);

        $this->assertEquals($this->baseVector, $form->getData());

        foreach ($this->parsedBaseVector as $metric => $value) {
            $this->assertArrayHasKey($metric, $form);
            $this->assertEquals($value, $form[$metric]->getData());
        }
    }

    public function testSetTemporalData()
    {
        $form = $this->factory->create(Cvss3Type::class, null, array(
            'temporal' => true,
        ));
        $form->setData($this->temporalVector);

        $this->assertEquals($this->temporalVector, $form->getData());

        foreach ($this->parsedTemporalVector as $metric => $value) {
            $this->assertArrayHasKey($metric, $form);
            $this->assertEquals($value, $form[$metric]->getData());
        }
    }

    public function testSetFullData()
    {
        $form = $this->factory->create(Cvss3Type::class, null, array(
            'temporal' => true,
            'environmental' => true,
        ));
        $form->setData($this->fullVector);

        $this->assertEquals($this->fullVector, $form->getData());

        foreach ($this->parsedFullVector as $metric => $value) {
            $this->assertArrayHasKey($metric, $form);
            $this->assertEquals($value, $form[$metric]->getData());
        }
    }

    /**
     * @expectedException \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     */
    public function testSetInvalidOptions()
    {
        $this->factory->create(Cvss3Type::class, null, array(
            'options' => '123',
        ));
    }

    /**
     * @expectedException \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     */
    public function testSetInvalidTemporal()
    {
        $this->factory->create(Cvss3Type::class, null, array(
            'temporal' => '123',
        ));
    }

    /**
     * @expectedException \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     */
    public function testSetInvalidEnvironmental()
    {
        $this->factory->create(Cvss3Type::class, null, array(
            'environmental' => '123',
        ));
    }


}
