<?php declare(strict_types=1);
/**
 * Copyright (c) 2025, William Eggers, Ashley Hindle
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

namespace WilliamEggers\React\SSH\Values;

final class KeyboardInteractiveConfig
{
    /**
     * @param null|string                              $title       Optional title text displayed to the user
     * @param null|string                              $instruction Optional instruction text below the title
     * @param array<array{prompt: string, echo: bool}> $prompts     Array of prompts to present to the user
     */
    public function __construct(
        public readonly ?string $title = null,
        public readonly ?string $instruction = null,
        public readonly array $prompts = [],
    ) {
        foreach ($this->prompts as $index => $prompt) {
            if (
                ! is_array($prompt)
                || ! isset($prompt['prompt'], $prompt['echo'])
                || ! is_string($prompt['prompt'])
                || ! is_bool($prompt['echo'])
            ) {
                throw new \InvalidArgumentException("Invalid prompt at index {$index}: must be ['prompt' => string, 'echo' => bool]");
            }
        }
    }

    /**
     * Generates a packet config structure with the following fields:
     *
     * - name (string):          Optional display name shown by the client
     * - instruction (string):   Optional instructions for the user
     * - language_tag (string):  Usually empty (""); generally ignored
     * - num_prompts (uint32):   Number of prompts being sent
     * - prompt[n] (string):     The prompt text (e.g., "Password:")
     * - echo[n] (boolean):      Whether the input should be echoed (false = hidden)
     */
    public function generatePacketConfig(): array
    {
        $packet = [
            $this->title ?? '',
            $this->instruction ?? '',
            '',
            count($this->prompts),
        ];

        foreach ($this->prompts as $prompt) {
            $packet[] = $prompt['prompt'];
            $packet[] = (bool) ($prompt['echo'] ?? false);
        }

        return $packet;
    }
}
