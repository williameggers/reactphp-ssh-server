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

namespace WilliamEggers\React\SSH\Enums;

enum DisconnectReason: int
{
    case HOST_NOT_ALLOWED_TO_CONNECT = 1;
    case PROTOCOL_ERROR = 2;
    case KEY_EXCHANGE_FAILED = 3;
    case RESERVED = 4;
    case MAC_ERROR = 5;
    case COMPRESSION_ERROR = 6;
    case SERVICE_NOT_AVAILABLE = 7;
    case PROTOCOL_VERSION_NOT_SUPPORTED = 8;
    case HOST_KEY_NOT_VERIFIABLE = 9;
    case CONNECTION_LOST = 10;
    case DISCONNECT_BY_APPLICATION = 11;
    case TOO_MANY_CONNECTIONS = 12;
    case AUTH_CANCELLED_BY_USER = 13;
    case NO_MORE_AUTH_METHODS_AVAILABLE = 14;
    case ILLEGAL_USER_NAME = 15;
}
