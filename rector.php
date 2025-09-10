<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\CodingStyle\Rector\ArrowFunction\StaticArrowFunctionRector;
use Rector\CodingStyle\Rector\Closure\StaticClosureRector;

return RectorConfig::configure()
    ->withPaths([
        __DIR__ . '/examples',
        __DIR__ . '/src',
        __DIR__ . '/tests',
    ])
    ->withPhpSets()
    ->withRules([
        StaticArrowFunctionRector::class,
        StaticClosureRector::class,
    ])
    ->withSkip([
        StaticArrowFunctionRector::class => [
            __DIR__ . '/tests'
        ],
        StaticClosureRector::class => [
            __DIR__ . '/tests'
        ]
    ])
    ->withTypeCoverageLevel(0)
    ->withDeadCodeLevel(0)
    ->withCodeQualityLevel(0);
