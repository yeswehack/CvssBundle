<?php

namespace YWH\CvssBundle\Form\Type;

use YWH\CvssBundle\Cvss\Cvss3;
use YWH\CvssBundle\Form\DataTransformer\CvssToArrayTransformer;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Class Cvss3Type
 *
 * @author Romain Honel <r.honel@yeswehack.com>
 * @author Maxime Bouchard <m.bouchard@yeswehack.com>
 */
class Cvss3Type extends AbstractType
{
    private Cvss3 $cvss;

    private ?string $translationDomain;

    public function __construct(Cvss3 $cvss, ?string $translationDomain = null)
    {
        $this->cvss = $cvss;
        $this->translationDomain = $translationDomain;
    }

    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        foreach ($this->cvss->getBaseMetricDefinitions() as $metric => $values) {
            $builder->add($metric, $options['type'], array_merge($this->getDefaultFieldOptions($metric, $values), $options['options'], $options['base_options']));
        }

        if ($options['temporal']) {
            foreach ($this->cvss->getTemporalMetricDefinitions() as $metric => $values) {
                $builder->add($metric, $options['type'], array_merge($this->getDefaultFieldOptions($metric, $values), $options['options'], $options['temporal_options']));
            }
        }

        if ($options['environmental']) {
            foreach ($this->cvss->getEnvironmentalMetricDefinitions() as $metric => $values) {
                $builder->add($metric, $options['type'], array_merge($this->getDefaultFieldOptions($metric, $values), $options['options'], $options['environmental_options']));
            }
        }

        $builder
            ->addViewTransformer(new CvssToArrayTransformer())
        ;
    }

    protected function getDefaultFieldOptions(string $metric, array $values): array
    {
        return array(
            'placeholder' => false,
            'choices' => array_combine(array_keys($values), array_keys($values)),
            'choice_label' => function ($value, $key, $index) use ($metric) {
                return $this->cvss->getMetricValueTransId($metric, $value);
            },
            'label' => $this->cvss->getMetricTransId($metric),
            'expanded' => true,
            'multiple' => false,
            'translation_domain' => $this->translationDomain ?: 'cvss',
        );
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults(array(
            'type' => ChoiceType::class,
            'options' => array(),
            'base_options' => array(),
            'temporal' => false,
            'temporal_options' => array(),
            'environmental' => false,
            'environmental_options' => array(),
        ));

        $resolver->setAllowedTypes('options', 'array');
        $resolver->setAllowedTypes('base_options', 'array');
        $resolver->setAllowedTypes('temporal', 'boolean');
        $resolver->setAllowedTypes('temporal_options', 'array');
        $resolver->setAllowedTypes('environmental', 'boolean');
        $resolver->setAllowedTypes('environmental_options', 'array');
    }

    public function getBlockPrefix(): string
    {
        return 'ywh_cvss3';
    }
}
