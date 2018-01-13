<?php

namespace YWH\CvssBundle\Tests\Form\DataTransformer;

use YWH\CvssBundle\Form\DataTransformer\CvssToArrayTransformer;

/**
 * Class CvssToArrayTransformerTest
 *
 * @author Romain Honel <r.honel@yeswehack.com>
 * @author Maxime Bouchard <m.bouchard@yeswehack.com>
 */
class CvssToArrayTransformerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var CvssToArrayTransformer
     */
    protected $transformer;

    private $vector = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N';

    private $parsedVector = array(
        'AV' => 'N',
        'AC' => 'L',
        'PR' => 'N',
        'UI' => 'N',
        'S' => 'U',
        'C' => 'N',
        'I' => 'N',
        'A' => 'N',
    );

    public function setUp()
    {
        $this->transformer = new CvssToArrayTransformer();
    }

    protected function tearDown()
    {
        $this->transformer = null;
    }

    public function testTransform()
    {
        $this->assertSame($this->parsedVector, $this->transformer->transform($this->vector));
    }

    public function testTransformEmpty()
    {
        $this->assertEquals(array(), $this->transformer->transform(null));
    }

    /**
     * @expectedException \Symfony\Component\Form\Exception\TransformationFailedException
     */
    public function testTransformRequiresString()
    {
        $this->transformer->transform(array());
    }

    public function testReverseTransform()
    {
        $this->assertSame($this->vector, $this->transformer->reverseTransform($this->parsedVector));
    }

    public function testReverseTransformCompletelyEmpty()
    {
        $this->assertNull($this->transformer->reverseTransform(array()));
    }

    /**
     * @expectedException \Symfony\Component\Form\Exception\TransformationFailedException
     */
    public function testReverseTransformRequiresArray()
    {
        $this->transformer->reverseTransform('123');
    }
}