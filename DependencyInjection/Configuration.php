<?php

namespace YWH\CvssBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Configuration
 *
 * This is the class that validates and merges configuration from your app/config files.
 *
 * @author Romain Honel <r.honel@yeswehack.com>
 * @author Maxime Bouchard <m.bouchard@yeswehack.com>
 */
class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('ywh_cvss');

        $rootNode
            ->children()
                ->scalarNode('translation_domain')->defaultValue('cvss')->cannotBeEmpty()->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
