CVSS Bundle for Symfony2
========================

[![Latest Stable Version](https://poser.pugx.org/ywh/cvss-bundle/version)](https://packagist.org/packages/ywh/cvss-bundle)
[![Total Downloads](https://poser.pugx.org/ywh/cvss-bundle/downloads)](https://packagist.org/packages/ywh/cvss-bundle)
[![Latest Unstable Version](https://poser.pugx.org/ywh/cvss-bundle/v/unstable)](//packagist.org/packages/ywh/cvss-bundle)
[![License](https://poser.pugx.org/ywh/cvss-bundle/license)](https://packagist.org/packages/ywh/cvss-bundle)

This bundle provides integration for [CVSS](https://github.com/yeswehack/cvss) in your Symfony2 Project.

License: [MIT](LICENSE)

# Installation

## Step 1: Download the Bundle

Open a command console, enter your project directory and execute the
following command to download the latest stable version of this bundle:

```bash
    $ composer require ywh/cvss-bundle
```

This command requires you to have Composer installed globally, as explained
in the [installation chapter](https://getcomposer.org/doc/00-intro.md) of the Composer documentation.

## 2: Enable the Bundle

> When using Flex, this step is handled automatically.

Then, enable the bundle by adding the following line in the `app/AppKernel.php`
file of your project:

```php

    // app/AppKernel.php

    class AppKernel extends Kernel
    {
        public function registerBundles()
        {
            $bundles = array(
                // ...

                new YWH\CvssBundle\YWHCvssBundle(),
            );

            // ...
        }

        // ...
    }
```

## 3: Configure the bundle

```yaml
# app/config/config.yml
ywh_cvss:
    translation_domain: 'cvss'
```

# Cvss form type

Basic exemple
```php
use YWH\CvssBundle\Form\Type\Cvss3Type;
//...
$builder->add('cvss', Cvss3Type::class);
```

Advanced exemple
```php
use YWH\CvssBundle\Form\Type\Cvss3Type;
//...
$builder->add('cvss', Cvss3Type::class, array(
    'options' => array(),
    'base_options' => array(
        'required' => true,
    ),
    'temporal' => true,
    'temporal_options' => array(
        'required' => false,
    ),
    'environmental' => true,
    'environmental_options' => array(
        'required' => false,
    ),
));
```

# Cvss3 validator

```php
use YWH\CvssBundle\Validator\Constraints as CvssAssert;

class MyEntity 
{
    //...
    
    /**
     * ...
     * @CvssAssert\Cvss3
     */
    private $cvss;
    
    //...
}
```