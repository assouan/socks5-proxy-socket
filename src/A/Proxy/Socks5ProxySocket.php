<?php

declare(strict_types=1);

namespace A\Proxy;

use A\Network\TcpSocket;

class Socks5ProxySocket extends TcpSocket
{
    protected(set) string $proxy_host;

    protected(set) int $proxy_port;

    protected(set) ?string $username;

    protected(set) ?string $password;

    protected array $options;

    public function __construct(
        string $proxy_host,
        int $proxy_port = 1080,
        ?string $username = null,
        ?string $password = null,
        array $options = [],
        ?\Socket $socket = null,
    ) {
        $this->proxy_host = $proxy_host;
        $this->proxy_port = $proxy_port;
        $this->username = $username;
        $this->password = $password;
        $this->options = $options;

        parent::__construct($socket);
    }

    public static function create(
        string $host,
        int $port = 0,
        mixed $third = null,
        mixed $fourth = null,
        array $options = [],
    ) : static {
        return new static($host, $port ?: 1080, is_string($third) ? $third : null, is_string($fourth) ? $fourth : null, $options);
    }

    protected function connect_transport(string $host, int $port) : void
    {
        try
        {
            $this->connect_to_proxy();
            $this->connect_to_target($host, $port);
            $this->remote_host = $host;
            $this->remote_port = $port;
        }
        catch (\Throwable $error)
        {
            $this->close();

            throw $error;
        }
    }

    protected function connect_to_proxy() : void
    {
        $this->connect_tcp_transport($this->proxy_host, $this->proxy_port);
        $this->stop_selecting();
    }

    protected function connect_to_target(string $host, int $port) : void
    {
        $methods = $this->username === null ? "\x00" : "\x00\x02";

        $this->raw_write("\x05" . chr(strlen($methods)) . $methods);

        $response = $this->read_exact(2);

        if ($response[0] !== "\x05")
        {
            throw new \RuntimeException('Invalid SOCKS5 greeting response.');
        }

        $method = ord($response[1]);

        if ($method === 0xff)
        {
            throw new \RuntimeException('SOCKS5 proxy rejected all authentication methods.');
        }

        if ($method === 0x02)
        {
            $this->authenticate();
        }
        else if ($method !== 0x00)
        {
            throw new \RuntimeException('SOCKS5 proxy selected an unsupported authentication method.');
        }

        $this->raw_write("\x05\x01\x00" . $this->address($host) . pack('n', $port));

        $head = $this->read_exact(4);

        if ($head[0] !== "\x05")
        {
            throw new \RuntimeException('Invalid SOCKS5 connect response.');
        }

        $status = ord($head[1]);

        if ($status !== 0)
        {
            throw new \RuntimeException('SOCKS5 connect failed with status ' . $status . '.');
        }

        match (ord($head[3]))
        {
            1 => $this->read_exact(4),
            3 => $this->read_exact(ord($this->read_exact(1))),
            4 => $this->read_exact(16),
            default => throw new \RuntimeException('Invalid SOCKS5 bind address type.'),
        };

        $this->read_exact(2);
    }

    protected function authenticate() : void
    {
        $username = $this->username ?? '';
        $password = $this->password ?? '';

        if (strlen($username) > 255 or strlen($password) > 255)
        {
            throw new \InvalidArgumentException('SOCKS5 username and password must be 255 bytes or shorter.');
        }

        $this->raw_write("\x01" . chr(strlen($username)) . $username . chr(strlen($password)) . $password);

        $response = $this->read_exact(2);

        if ($response[0] !== "\x01" or $response[1] !== "\x00")
        {
            throw new \RuntimeException('SOCKS5 authentication failed.');
        }
    }

    protected function address(string $host) : string
    {
        $packed = @inet_pton($host);

        if ($packed !== false and strlen($packed) === 4)
        {
            return "\x01" . $packed;
        }

        if ($packed !== false and strlen($packed) === 16)
        {
            return "\x04" . $packed;
        }

        if (strlen($host) > 255)
        {
            throw new \InvalidArgumentException('SOCKS5 host name must be 255 bytes or shorter.');
        }

        return "\x03" . chr(strlen($host)) . $host;
    }

    protected function read_exact(int $length) : string
    {
        $data = '';

        while (strlen($data) < $length)
        {
            $chunk = $this->raw_read($length - strlen($data));

            if ($chunk !== '')
            {
                $data .= $chunk;
                continue;
            }

            if (!$this->is_open)
            {
                throw new \RuntimeException('Proxy connection closed during handshake.');
            }

            $this->wait_read();
        }

        return $data;
    }
}
