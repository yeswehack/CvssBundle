<?php

namespace YWH\CvssBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Configuration
 *
 * @author Romain Honel <r.honel@yeswehack.com>
 * @author Maxime Bouchard <m.bouchard@yeswehack.com>
 */
class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('ywh_cvss');
        $rootNode = $treeBuilder->getRootNode();

        $rootNode
            ->children()
                ->scalarNode('translation_domain')->defaultValue('cvss')->cannotBeEmpty()->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
