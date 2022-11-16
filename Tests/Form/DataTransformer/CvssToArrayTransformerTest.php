<?php

namespace YWH\CvssBundle\Tests\Form\DataTransformer;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Form\Exception\TransformationFailedException;
use YWH\CvssBundle\Form\DataTransformer\CvssToArrayTransformer;

/**
 * Class CvssToArrayTransformerTest
 *
 * @author Romain Honel <r.honel@yeswehack.com>
 * @author Maxime Bouchard <m.bouchard@yeswehack.com>
 */
class CvssToArrayTransformerTest extends TestCase
{
    protected CvssToArrayTransformer $transformer;

    private string $vector = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N';

    private array $parsedVector = [
        'AV' => 'N',
        'AC' => 'L',
        'PR' => 'N',
        'UI' => 'N',
        'S' => 'U',
        'C' => 'N',
        'I' => 'N',
        'A' => 'N',
    ];

    public function setUp(): void
    {
        $this->transformer = new CvssToArrayTransformer();
    }

    public function testTransform(): void
    {
        $this->assertSame($this->parsedVector, $this->transformer->transform($this->vector));
    }

    public function testTransformEmpty(): void
    {
        $this->assertEquals(array(), $this->transformer->transform(null));
    }

    public function testTransformRequiresString(): void
    {
        $this->expectException(TransformationFailedException::class);
        $this->transformer->transform(array());
    }

    public function testReverseTransform(): void
    {
        $this->assertSame($this->vector, $this->transformer->reverseTransform($this->parsedVector));
    }

    public function testReverseTransformCompletelyEmpty(): void
    {
        $this->assertNull($this->transformer->reverseTransform(array()));
    }

    public function testReverseTransformRequiresArray(): void
    {
        $this->expectException(TransformationFailedException::class);
        $this->transformer->reverseTransform('123');
    }
}
