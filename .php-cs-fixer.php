<?php
return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@PSR12' => true,
        '@PhpCsFixer' => true,
        'array_indentation' => true,
        'array_syntax' => ['syntax' => 'short'],
        'align_multiline_comment' => true,
        'binary_operator_spaces' => [
            'default' => 'single_space'
        ],
        'concat_space' => ['spacing' => 'one'],
        'constant_case' => ['case' => 'lower'],
        'declare_strict_types' => true,
        'line_ending' => true,
        'modernize_types_casting' => true,
        'not_operator_with_successor_space' => true,
        'ordered_imports' => true,
        'ordered_traits' => true,
        'header_comment' => [
            'header' => "Copyright (c) 2025, William Eggers, Ashley Hindle

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.",
            'comment_type' => 'PHPDoc',
            'location' => 'after_declare_strict',
            'separate' => 'bottom',
    ],
        'unary_operator_spaces' => true,
        'trim_array_spaces' => true,
        'declare_strict_types' => true,
        'linebreak_after_opening_tag' => false,
        'blank_line_after_opening_tag' => false,
    ])
    ->setLineEnding("\n")
;